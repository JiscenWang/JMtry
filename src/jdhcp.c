/*
 * jdhcp.c
 *
 *  Created on: 2018年7月22日
 *      Author: jerome
 */

#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "jmodule.h"
#include "jdhcp.h"
#include "jnet.h"
#include "jconfig.h"
#include "client_list.h"
#include "debug.h"

//Jerome: Try this one first
#define HAVE_SFHASH

#ifdef HAVE_SFHASH
uint32_t SuperFastHash(const char * data, int len, uint32_t hash);
#elif HAVE_LOOKUP3
#if LITTLE_ENDIAN
uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
#elif BIG_ENDIAN
uint32_t hashbig(const void *key, size_t length, uint32_t initval);
#endif
#else
#error No hashing function found.
#endif

const unsigned int IPPOOL_STATSIZE = 0x10000;

static uint8_t bmac[PKT_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t nmac[PKT_ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int connections = 0;

/*Jerome TBD combined with clients*/
struct app_conn_t *firstfreeconn=0; /* First free in linked list */
struct app_conn_t *lastfreeconn=0;  /* Last free in linked list */
struct app_conn_t *firstusedconn=0; /* First used in linked list */
struct app_conn_t *lastusedconn=0;  /* Last used in linked list */

extern struct ippool_t *ippool;
extern struct tun_t *tun;
extern struct timespec mainclock;

struct dhcp_ctx {
  struct dhcp_t *parent;
  int idx;
};


#undef get16bits
#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)    \
                      +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

int dhcp_relay(struct dhcp_t *this, uint8_t *pack, size_t len);
int dhcp_timeout(struct dhcp_t *this);

uint32_t SuperFastHash (const char * data, int len, uint32_t hash) {
  uint32_t tmp;
  int rem;

  if (len <= 0 || data == NULL) return 0;

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for (;len > 0; len--) {
    hash  += get16bits (data);
    tmp    = (get16bits (data+2) << 11) ^ hash;
    hash   = (hash << 16) ^ tmp;
    data  += 2*sizeof (uint16_t);
    hash  += hash >> 11;
  }

  /* Handle end cases */
  switch (rem) {
    case 3: hash += get16bits (data);
      hash ^= hash << 16;
      hash ^= data[sizeof (uint16_t)] << 18;
      hash += hash >> 11;
      break;
    case 2: hash += get16bits (data);
      hash ^= hash << 11;
      hash += hash >> 17;
      break;
    case 1: hash += *data;
      hash ^= hash << 10;
      hash += hash >> 1;
  }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;
}

uint32_t lookup(uint8_t *k,  uint32_t length,  uint32_t initval)
{
#ifdef HAVE_SFHASH
  return SuperFastHash((const char*)k, length, initval);
#elif HAVE_LOOKUP3
#if LITTLE_ENDIAN
  return hashlittle(k, length, initval);
#elif BIG_ENDIAN
  return hashbig(k, length, initval);
#endif
#endif
}

uint32_t ippool_hash4(struct in_addr *addr) {
  return lookup((unsigned char *)&addr->s_addr, sizeof(addr->s_addr), 0);
}


int ippool_hashadd(struct ippool_t *this, struct ippoolm_t *member) {
  uint32_t hash;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Insert into hash table */
  hash = ippool_hash4(&member->addr) & this->hashmask;

  for (p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;

  if (!p_prev)
    this->hash[hash] = member;
  else
    p_prev->nexthash = member;

  return 0; /* Always OK to insert */
}

int ippool_hashdel(struct ippool_t *this, struct ippoolm_t *member) {
  uint32_t hash;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Find in hash table */
  hash = ippool_hash4(&member->addr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if (p == member) {
      break;
    }
    p_prev = p;
  }

  if (p!= member) {
    debug(LOG_ERR, "ippool_hashdel: Tried to delete member not in hash table");
    return -1;
  }

  if (!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

/* Find an IP address in the pool */
int ippool_getip(struct ippool_t *this,
		 struct ippoolm_t **member,
		 struct in_addr *addr) {
  struct ippoolm_t *p;
  uint32_t hash;

  /* Find in hash table */
  hash = ippool_hash4(addr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if ((p->addr.s_addr == addr->s_addr) && (p->in_use)) {
      if (member) *member = p;
      return 0;
    }
  }

  if (member) *member = NULL;
  return -1;
}

/* Create new address pool */
int ippool_new(struct ippool_t **this, char *dyn, int start, int end) {
    s_config *config = config_get_config();

  /* Parse only first instance of pool for now */
  int i;
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr stataddr;
  struct in_addr statmask;
  struct in_addr naddr;
  uint32_t m;
  uint32_t listsize;
  uint32_t dynsize;
  uint32_t statsize;

  char *stat = NULL;
  int allowdyn = 1;
  int allowstat = 0;

  if (!allowdyn) {
    dynsize = 0;
  }
  else {
    if (parse_ip_aton(&addr, &mask, dyn)) {
      debug(LOG_ERR, "Failed to parse dynamic pool");
      return -1;
    }

    /* auto-dhcpstart if not already set */
    if (!start)
      start = ntohl(addr.s_addr & ~(mask.s_addr));

    /* ensure we have the true network space */
    addr.s_addr = addr.s_addr & mask.s_addr;

    m = ntohl(mask.s_addr);
    dynsize = ((~m)+1);

    if ( ((ntohl(addr.s_addr) + start) & m) != (ntohl(addr.s_addr) & m) ) {
      addr.s_addr = htonl(ntohl(addr.s_addr) + start);
      debug(LOG_ERR, "Invalid dhcpstart=%d (%s) (outside of subnet)!",
             start, inet_ntoa(addr));
      return -1;
    }

    if ( ((ntohl(addr.s_addr) + end) & m) != (ntohl(addr.s_addr) & m) ) {
      debug(LOG_ERR, "Invalid dhcpend (outside of subnet)!");
      return -1;
    }

    if (start > 0 && end > 0) {

      if (end < start) {
	debug(LOG_ERR, "Bad arguments dhcpstart=%d and dhcpend=%d", start, end);
	return -1;
      }

      if ((end - start) > dynsize) {
	debug(LOG_ERR, "Too many IPs between dhcpstart=%d and dhcpend=%d",
               start, end);
	return -1;
      }

      dynsize = end - start;

    } else {

      if (start > 0) {

	/*
	 * if only dhcpstart is set, subtract that from count
	 */
	dynsize -= start;

	dynsize--;/* no broadcast */

      } else if (end > 0) {

	/*
	 * if only dhcpend is set, ensure only that many
	 */
	if (dynsize > end)
	  dynsize = end;

	dynsize--;/* no network */

      } else {
	dynsize-=2;/* no network, no broadcast */
      }

      dynsize--;/* no uamlisten */
    }
  }

  if (!allowstat) {
    statsize = 0;
    stataddr.s_addr = 0;
    statmask.s_addr = 0;
  }
  else {
    if (parse_ip_aton(&stataddr, &statmask, stat)) {
      debug(LOG_ERR, "Failed to parse static range");
      return -1;
    }

    /* ensure we have the true network space */
    stataddr.s_addr = stataddr.s_addr & statmask.s_addr;

    m = ntohl(statmask.s_addr);
    statsize = ((~m)+1);

    if (statsize > IPPOOL_STATSIZE)
      statsize = IPPOOL_STATSIZE;
  }

  listsize = dynsize + statsize; /* Allocate space for static IP addresses */

  if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
    debug(LOG_ERR, "Failed to allocate memory for ippool");
    return -1;
  }

  (*this)->allowdyn  = allowdyn;
  (*this)->allowstat = allowstat;
  (*this)->stataddr  = stataddr;
  (*this)->statmask  = statmask;

  (*this)->dynsize   = dynsize;
  (*this)->statsize  = statsize;
  (*this)->listsize  = listsize;

  if (!((*this)->member = calloc(sizeof(struct ippoolm_t), listsize))){
    debug(LOG_ERR, "Failed to allocate memory for members in ippool");
    return -1;
  }

  for ((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  debug(LOG_DEBUG, "Hashlog %d %d %d", (*this)->hashlog, listsize,
         (1 << (*this)->hashlog));

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet*/
  (*this)->hashmask = (*this)->hashsize -1;

  /* Allocate hash table */
  if (!((*this)->hash =
	calloc(sizeof(struct ippoolm_t *), (*this)->hashsize))){
    debug(LOG_ERR, "Failed to allocate memory for hash members in ippool");
    return -1;
  }

  if (start <= 0) /* adjust for skipping network */
    start = 1;

  (*this)->firstdyn = NULL;
  (*this)->lastdyn = NULL;

  for (i = 0; i < dynsize; i++) {

    naddr.s_addr = htonl(ntohl(addr.s_addr) + i + start);
    if (naddr.s_addr == config->dhcplisten.s_addr ||
	naddr.s_addr == config->tundevip.s_addr) {
      start++; /* skip the uamlisten address! */
      naddr.s_addr = htonl(ntohl(addr.s_addr) + i + start);
    }

    (*this)->member[i].addr.s_addr = naddr.s_addr;
    (*this)->member[i].in_use = 0;
    (*this)->member[i].is_static = 0;

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->lastdyn;
    if ((*this)->lastdyn) {
      (*this)->lastdyn->next = &((*this)->member[i]);
    }
    else {
      (*this)->firstdyn = &((*this)->member[i]);
    }
    (*this)->lastdyn = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */

    ippool_hashadd(*this, &(*this)->member[i]);
  }

  (*this)->firststat = NULL;
  (*this)->laststat = NULL;
  for (i = dynsize; i < listsize; i++) {
    (*this)->member[i].addr.s_addr = 0;
    (*this)->member[i].in_use = 0;
    (*this)->member[i].is_static = 1;

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->laststat;
    if ((*this)->laststat) {
      (*this)->laststat->next = &((*this)->member[i]);
    }
    else {
      (*this)->firststat = &((*this)->member[i]);
    }
    (*this)->laststat = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */
  }

  /*Jerome TBD for print if necessary*/
//    ippool_print(0, *this);

  return 0;
}


/**
 * ippool_newip
 * Get an IP address. If addr = 0.0.0.0 get a dynamic IP address. Otherwise
 * check to see if the given address is available. If available within
 * dynamic address space allocate it there, otherwise allocate within static
 * address space.
 **/
int ippool_newip(struct ippool_t *this,
		 struct ippoolm_t **member,
		 struct in_addr *addr,
		 int statip) {
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p2 = NULL;
  uint32_t hash;

  debug(LOG_DEBUG, "Requesting new %s ip: %s",
         statip ? "static" : "dynamic", inet_ntoa(*addr));

  /* If static:
   *   Look in dynaddr.
   *     If found remove from firstdyn/lastdyn linked list.
   *   Else allocate from stataddr.
   *    Remove from firststat/laststat linked list.
   *    Insert into hash table.
   *
   * If dynamic
   *   Remove from firstdyn/lastdyn linked list.
   *
   */


  /*Jerome TBD for print if necessary*/
//    ippool_print(0, this);

  /* First, check to see if this type of address is allowed */
  if ((addr) && (addr->s_addr) && statip) { /* IP address given */
      if (!this->allowstat) {
	debug(LOG_DEBUG, "Static IP address not allowed");
	return -1;
      }
      if ((addr->s_addr & this->statmask.s_addr) != this->stataddr.s_addr) {
	debug(LOG_ERR, "Static out of range (%s)", inet_ntoa(*addr));
	return -1;
      }
  }
  else {
    if (!this->allowdyn) {
      debug(LOG_ERR, "Dynamic IP address not allowed");
      return -1;
    }
  }

  /* If IP address given try to find it in address pool */
  if ((addr) && (addr->s_addr)) { /* IP address given */
    /* Find in hash table */
    hash = ippool_hash4(addr) & this->hashmask;
    for (p = this->hash[hash]; p; p = p->nexthash) {
      if (p->addr.s_addr == addr->s_addr) {
	p2 = p;
	break;
      }
    }
  }

  /* If IP was already allocated we can not use it */
  if ((!statip) && (p2) && (p2->in_use)) {
    p2 = NULL;
  }

  /* If not found yet and dynamic IP then allocate dynamic IP */
  if ((!p2) && (!statip) /*XXX: && (!addr || !addr->s_addr)*/) {
    if (!this->firstdyn) {
      debug(LOG_ERR, "No more dynamic addresses available");
      return -1;
    }
    else {
      p2 = this->firstdyn;
    }
  }

  if (p2) { /* Was allocated from dynamic address pool */

    if (p2->in_use) {
      debug(LOG_ERR, "IP address already in use");
      return -1; /* Already in use / Should not happen */
    }

    /* Remove from linked list of free dynamic addresses */

    if (p2->is_static) {
      debug(LOG_ERR, "Should not happen!");
      return -1;
    }

    if (p2->prev)
      p2->prev->next = p2->next;
    else
      this->firstdyn = p2->next;

    if (p2->next)
      p2->next->prev = p2->prev;
    else
      this->lastdyn = p2->prev;

    p2->next = NULL;
    p2->prev = NULL;
    p2->in_use = 1;

    *member = p2;
/*Jerome TBD for print if necessery*/
//    ippool_print(0, this);
    return 0; /* Success */
  }

  /* It was not possible to allocate from dynamic address pool */
  /* Try to allocate from static address space */

  if ((addr) && (addr->s_addr) && (statip)) { /* IP address given */

    if (!this->firststat) {
      debug(LOG_ERR, "No more static addresses available");
      return -1; /* No more available */
    }
    else {
      p2 = this->firststat;
    }

    /* Remove from linked list of free static addresses */

    if (p2->in_use) {
      debug(LOG_ERR, "IP address already in use");
      return -1; /* Already in use / Should not happen */
    }

    if (!p2->is_static) {
      debug(LOG_ERR, "Should not happen!");
      return -1;
    }

    if (p2->prev)
      p2->prev->next = p2->next;
    else
      this->firststat = p2->next;

    if (p2->next)
      p2->next->prev = p2->prev;
    else
      this->laststat = p2->prev;

    p2->next = NULL;
    p2->prev = NULL;
    p2->in_use = 1;

    p2->addr.s_addr = addr->s_addr;

    *member = p2;

    debug(LOG_DEBUG, "Assigned a static ip to: %s", inet_ntoa(*addr));

    ippool_hashadd(this, *member);

    /*Jerome TBD for print if necessary*/
  //      ippool_print(0, this);

    return 0; /* Success */
  }

  return -1;
}


/* Delete existing address pool */
int ippool_free(struct ippool_t *this) {
  free(this->hash);
  free(this->member);
  free(this);
  return 0; /* Always OK */
}

int ippool_freeip(struct ippool_t *this, struct ippoolm_t *member) {

/*Jerome TBD for print if necessary*/
	//ippool_print(0, this);


  if (!member->in_use) {
    debug(LOG_ERR, "Address not in use");
    return -1; /* Not in use: Should not happen */
  }

  if (member->is_static) {

    if (ippool_hashdel(this, member))
      return -1;

    member->prev = this->laststat;

    if (this->laststat) {
      this->laststat->next = member;
    }
    else {
      this->firststat = member;
    }

    this->laststat = member;

    member->in_use = 0;
    member->addr.s_addr = 0;
    member->peer = NULL;
    member->nexthash = NULL;

  } else {

    member->prev = this->lastdyn;

    if (this->lastdyn) {
      this->lastdyn->next = member;
    }
    else {
      this->firstdyn = member;
    }

    this->lastdyn = member;

    member->in_use = 0;
    member->peer = NULL;
  }

  /*Jerome TBD for print if necessary*/
//   ippool_print(0, this);

  return 0;
}

/***********************************************************
 *
 * Functions handling uplink protocol authentication.
 * Called in response to radius access request response.
 *
 ***********************************************************/

static int newip(struct ippoolm_t **ipm, struct in_addr *hisip, uint8_t *hismac) {
  debug(LOG_DEBUG, "newip %s",    inet_ntoa(*hisip));

  if (ippool_newip(ippool, ipm, hisip, 1)) {
    if (ippool_newip(ippool, ipm, hisip, 0)) {
      debug(LOG_ERR, "Failed to allocate either static or dynamic IP address");
      return -1;
    }
  }

  return 0;
}

time_t mainclock_now() {
  return mainclock.tv_sec;
}

size_t icmpfrag(struct dhcp_conn_t *conn,
		uint8_t *pack, size_t plen, uint8_t *orig_pack) {
  /*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           unused = 0          |         Next-Hop MTU          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Used when we recived a truncated (from recvfrom() where our buffer
    is smaller than IP packet length) IP packet.
  */

  size_t icmp_req_len = PKT_IP_HLEN + 8;

  size_t icmp_ip_len = PKT_IP_HLEN + sizeof(struct pkt_icmphdr_t) +
      4 + icmp_req_len;

  size_t icmp_full_len = icmp_ip_len + sizeofeth(orig_pack);

  struct pkt_iphdr_t  *orig_pack_iph  = pkt_iphdr(orig_pack);
  struct pkt_ethhdr_t *orig_pack_ethh = pkt_ethhdr(orig_pack);

  if (icmp_full_len > plen) return 0;

  memset(pack, 0, icmp_full_len);
  copy_ethproto(orig_pack, pack);

  {
    struct pkt_ethhdr_t *pack_ethh  = pkt_ethhdr(pack);
    struct pkt_iphdr_t *pack_iph = pkt_iphdr(pack);
    struct pkt_icmphdr_t *pack_icmph;

    /* eth */
    memcpy(pack_ethh->dst, orig_pack_ethh->src, PKT_ETH_ALEN);
    memcpy(pack_ethh->src, orig_pack_ethh->dst, PKT_ETH_ALEN);

    /* ip */
    pack_iph->version_ihl = PKT_IP_VER_HLEN;
    pack_iph->saddr = conn->ourip.s_addr;
    pack_iph->daddr = orig_pack_iph->saddr;
    pack_iph->protocol = PKT_IP_PROTO_ICMP;
    pack_iph->ttl = 0x10;
    pack_iph->tot_len = htons(icmp_ip_len);

    pack_icmph = pkt_icmphdr(pack);
    pack_icmph->type = 3;
    pack_icmph->code = 4;

    /* go beyond icmp header and fill in next hop MTU */
    pack_icmph++;
    pack_icmph->check = htons(conn->mtu);

    memcpy(pack + (icmp_full_len - icmp_req_len),
	   orig_pack + sizeofeth(orig_pack), icmp_req_len);

    chksum(pack_iph);
  }

  return icmp_full_len;
}

/* Get IP address and mask */
int parse_ip_aton(struct in_addr *addr, struct in_addr *mask, char *pool) {

  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  unsigned int m;
  int masklog;
  int c;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
	     &a1, &a2, &a3, &a4,
	     &m1, &m2, &m3, &m4);

  switch (c) {
    case 4:
      mask->s_addr = htonl(0xffffff00);
      break;
    case 5:
      if (m1 > 32) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Invalid mask */
      }
      mask->s_addr = m1 > 0 ? htonl(0xffffffff << (32 - m1)) : 0;
      break;
    case 8:
      if (m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Wrong mask format */
      }
      m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
      for (masklog = 0; ((1 << masklog) < ((~m)+1)); masklog++);
      if (((~m)+1) != (1 << masklog)) {
        debug(LOG_ERR, "Invalid mask");
        return -1; /* Wrong mask format (not all ones followed by all zeros)*/
      }
      mask->s_addr = htonl(m);
      break;
    default:
      debug(LOG_ERR, "Invalid mask");
      return -1; /* Invalid mask */
  }

  if (a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256) {
    debug(LOG_ERR, "Wrong IP address format");
    return -1;
  }
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}

/* Compare a MAC address to the addresses given in the macallowed option */
int static maccmp(unsigned char *mac, s_config *config) {
  int i;

  for (i=0; i < config->macoklen; i++)
    if (!memcmp(mac, config->macok[i], PKT_ETH_ALEN))
      return 0;

  return -1;
}


/**
 * dhcp_set_cb_data_ind()
 * Set callback function which is called when packet has arrived
 **/
int dhcp_set_cb_data_ind(struct dhcp_t *this,
                         int (*cb_data_ind) (struct dhcp_conn_t *conn,
                                             uint8_t *pack, size_t len)) {
  this->cb_data_ind = cb_data_ind;
  return 0;
}

/**
 * dhcp_set_cb_data_ind()
 * Set callback function which is called when a dhcp request is received
 **/
int dhcp_set_cb_request(struct dhcp_t *this,
                        int (*cb_request) (struct dhcp_conn_t *conn,
                                           struct in_addr *addr,
                                           uint8_t *pack, size_t len)) {
  this->cb_request = cb_request;
  return 0;
}


/**
 * dhcp_set_cb_connect()
 * Set callback function which is called when a connection is created
 **/
int dhcp_set_cb_connect(struct dhcp_t *this,
                        int (*cb_connect) (struct dhcp_conn_t *conn)) {
  this->cb_connect = cb_connect;
  return 0;
}

/**
 * dhcp_set_cb_disconnect()
 * Set callback function which is called when a connection is deleted
 **/
int dhcp_set_cb_disconnect(struct dhcp_t *this,
                           int (*cb_disconnect) (struct dhcp_conn_t *conn,
                                                 int term_cause)) {
  this->cb_disconnect = cb_disconnect;
  return 0;
}

/**
 * dhcp_create_pkt()
 * Create a new typed DHCP packet
 */
int
dhcp_create_pkt(uint8_t type, uint8_t *pack, uint8_t *req,
		struct dhcp_conn_t *conn) {

  struct dhcp_t *this = conn->parent;

  struct pkt_ethhdr_t *req_ethh = pkt_ethhdr(req);
  struct dhcp_packet_t *req_dhcp = pkt_dhcppkt(req);

  struct pkt_ethhdr_t *pack_ethh;
  struct pkt_iphdr_t *pack_iph;
  struct pkt_udphdr_t *pack_udph;
  struct dhcp_packet_t *pack_dhcp;

  int pos = 0;

  int is_req_dhcp = (req_dhcp->options[0] == 0x63 &&
		     req_dhcp->options[1] == 0x82 &&
		     req_dhcp->options[2] == 0x53 &&
		     req_dhcp->options[3] == 0x63);

  copy_ethproto(req, pack);

  pack_ethh = pkt_ethhdr(pack);
  pack_iph  = pkt_iphdr(pack);

  /* IP header */
  pack_iph->version_ihl = PKT_IP_VER_HLEN;
  pack_iph->tos = 0;
  pack_iph->tot_len = 0; /* Calculate at end of packet */
  pack_iph->id = 0;
  pack_iph->opt_off_high = 0;
  pack_iph->off_low = 0;
  pack_iph->ttl = 0x10;
  pack_iph->protocol = 0x11;
  pack_iph->check = 0; /* Calculate at end of packet */

  pack_udph = pkt_udphdr(pack);
  pack_dhcp = pkt_dhcppkt(pack);

  pack_dhcp->op     = DHCP_BOOTREPLY;
  pack_dhcp->htype  = DHCP_HTYPE_ETH;
  pack_dhcp->hlen   = PKT_ETH_ALEN;

  if (is_req_dhcp) {
    pack_dhcp->xid      = req_dhcp->xid;
    pack_dhcp->flags[0] = req_dhcp->flags[0];
    pack_dhcp->flags[1] = req_dhcp->flags[1];
    pack_dhcp->giaddr   = req_dhcp->giaddr;

    memcpy(&pack_dhcp->chaddr, &req_dhcp->chaddr, DHCP_CHADDR_LEN);
    debug(LOG_DEBUG, "dhcp server: %s", pack_dhcp->sname);
  }

  switch(type) {
    case DHCPOFFER:
    case DHCPFORCERENEW:
      pack_dhcp->yiaddr = conn->hisip.s_addr;
      break;
    case DHCPACK:
      pack_dhcp->xid    = req_dhcp->xid;
      pack_dhcp->yiaddr = conn->hisip.s_addr;
      break;
    case DHCPNAK:
      break;
  }

  /* Ethernet Header */
  memcpy(pack_ethh->dst, req_ethh->src, PKT_ETH_ALEN);
  memcpy(pack_ethh->src, dhcp_nexthop(this), PKT_ETH_ALEN);

  /* UDP and IP Headers */
  pack_udph->src = htons(DHCP_BOOTPS);
  pack_iph->saddr = conn->ourip.s_addr;

  /** http://www.faqs.org/rfcs/rfc1542.html
      Now see: http://www.faqs.org/rfcs/rfc2131.html

      BOOTREQUEST fields     BOOTREPLY values for UDP, IP, link-layer
      +-----------------------+-----------------------------------------+
      | 'ciaddr'  'giaddr'  B | UDP dest     IP destination   link dest |
      +-----------------------+-----------------------------------------+
      | non-zero     X      X | BOOTPC (68)  'ciaddr'         normal    |
      | 0.0.0.0   non-zero  X | BOOTPS (67)  'giaddr'         normal    |
      | 0.0.0.0   0.0.0.0   0 | BOOTPC (68)  'yiaddr'         'chaddr'  |
      | 0.0.0.0   0.0.0.0   1 | BOOTPC (68)  255.255.255.255  broadcast |
      +-----------------------+-----------------------------------------+

      B = BROADCAST flag

      X = Don't care

      normal = determine from the given IP destination using normal
      IP routing mechanisms and/or ARP as for any other
      normal datagram

      If the 'giaddr' field in a DHCP message from a client is non-zero,
      the server sends any return messages to the 'DHCP server' port on the
      BOOTP relay agent whose address appears in 'giaddr'.

      If the 'giaddr' field is zero and the 'ciaddr' field is nonzero, then the
      server unicasts DHCPOFFER and DHCPACK messages to the address in
      'ciaddr'.

      If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is set,
      then the server broadcasts DHCPOFFER and DHCPACK messages to
      0xffffffff.

      If the broadcast bit is not set and 'giaddr' is zero and 'ciaddr' is
      zero, then the server unicasts DHCPOFFER and DHCPACK messages to the
      client's hardware address and 'yiaddr' address.

      In all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
      messages to 0xffffffff.

  **/

  if (is_req_dhcp) {
    if (req_dhcp->ciaddr) {
      pack_iph->daddr = req_dhcp->ciaddr;
      pack_udph->dst = htons(DHCP_BOOTPC);
    } else if (req_dhcp->giaddr) {
      pack_iph->daddr = req_dhcp->giaddr;
      pack_udph->dst = htons(DHCP_BOOTPS);
    } else if (type == DHCPNAK ||           /* Nak always to broadcast */
	       (req_dhcp->flags[0] & 0x80) ){  /* Broadcast bit set */
      pack_iph->daddr = ~0;
      pack_udph->dst = htons(DHCP_BOOTPC);
      pack_dhcp->flags[0] = 0x80;
      if (req_dhcp->flags[0] & 0x80)
	memcpy(pack_ethh->dst, bmac, PKT_ETH_ALEN);
    } else {
      pack_iph->daddr = pack_dhcp->yiaddr;
      pack_udph->dst = htons(DHCP_BOOTPC);
    }
  } else {
    struct pkt_iphdr_t *iph = pkt_iphdr(req);
    pack_iph->daddr = iph->saddr;
    pack_udph->dst = htons(DHCP_BOOTPC);
  }

  /* Magic cookie */
  pack_dhcp->options[pos++] = 0x63;
  pack_dhcp->options[pos++] = 0x82;
  pack_dhcp->options[pos++] = 0x53;
  pack_dhcp->options[pos++] = 0x63;

  pack_dhcp->options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
  pack_dhcp->options[pos++] = 1;
  pack_dhcp->options[pos++] = type;

  return pos;
}


/**
 * dhcp_hash()
 * Generates a 32 bit hash based on a mac address
 **/
uint32_t dhcp_hash(uint8_t *hwaddr) {
  return lookup(hwaddr, PKT_ETH_ALEN, 0);
}

/**
 * dhcp_hashinit()
 * Initialises hash tables
 **/
int dhcp_hashinit(struct dhcp_t *this, int listsize) {
  /* Determine hashlog */
  for ((this)->hashlog = 0;
       ((1 << (this)->hashlog) < listsize);
       (this)->hashlog++);

  /* Determine hashsize */
  (this)->hashsize = 1 << (this)->hashlog;
  (this)->hashmask = (this)->hashsize -1;

  /* Allocate hash table */
  if (!((this)->hash =
	calloc(sizeof(struct dhcp_conn_t *), (this)->hashsize))) {
    /* Failed to allocate memory for hash members */
    return -1;
  }

//  debug(LOG_DEBUG, "hash table size %d (%d)",   this->hashsize, listsize);
  return 0;

}

/**
 * ()
 * Uses the hash tables to find a connection based on the mac address.
 * Returns -1 if not found.
 **/
int dhcp_hashget(struct dhcp_t *this, struct dhcp_conn_t **conn,
		 uint8_t *hwaddr) {
  struct dhcp_conn_t *p;
  uint32_t hash;

  /* Find in hash table */
  hash = dhcp_hash(hwaddr) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if ((!memcmp(p->hismac, hwaddr, PKT_ETH_ALEN)) && (p->inuse)) {
      *conn = p;
      return 0;
    }
  }
  *conn = NULL;
  return -1; /* Address could not be found */
}


/**
 * dhcp_hashadd()
 * Adds a connection to the hash table
 **/
int dhcp_hashadd(struct dhcp_t *this, struct dhcp_conn_t *conn) {
  uint32_t hash;
  struct dhcp_conn_t *p;
  struct dhcp_conn_t *p_prev = NULL;

  /* Insert into hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;
  if (!p_prev)
    this->hash[hash] = conn;
  else
    p_prev->nexthash = conn;

  return 0; /* Always OK to insert */
}


/**
 * dhcp_hashdel()
 * Removes a connection from the hash table
 **/
int dhcp_hashdel(struct dhcp_t *this, struct dhcp_conn_t *conn) {
  uint32_t hash;
  struct dhcp_conn_t *p = NULL;
  struct dhcp_conn_t *p_prev = NULL;

  if (conn == (struct dhcp_conn_t *)0) {
    debug(LOG_ERR, "%s: Bad input param conn(%p)",  conn);
    return -1;
  }

  /* Find in hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for (p = this->hash[hash]; p; p = p->nexthash) {
    if (p == conn) {
      break;
    }
    p_prev = p;
  }

  if (p != conn) {
    debug(LOG_ERR, "trying to remove connection not in hash table");
    return -1;
  }

  if (!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

static int dhcp_accept_opt(struct dhcp_conn_t *conn, uint8_t *o, int pos) {
  struct dhcp_t *this = conn->parent;

  o[pos++] = DHCP_OPTION_SUBNET_MASK;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->hismask.s_addr, 4);
  pos += 4;

  o[pos++] = DHCP_OPTION_ROUTER_OPTION;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  if (conn->dns1.s_addr && conn->dns2.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 8;
    memcpy(&o[pos], &conn->dns1.s_addr, 4);
    pos += 4;
    memcpy(&o[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }
  else if (conn->dns1.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 4;
    memcpy(&o[pos], &conn->dns1.s_addr, 4);
    pos += 4;
  }
  else if (conn->dns2.s_addr) {
    o[pos++] = DHCP_OPTION_DNS;
    o[pos++] = 4;
    memcpy(&o[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }


  o[pos++] = DHCP_OPTION_LEASE_TIME;
  o[pos++] = 4;
  o[pos++] = (this->lease >> 24) & 0xFF;
  o[pos++] = (this->lease >> 16) & 0xFF;
  o[pos++] = (this->lease >>  8) & 0xFF;
  o[pos++] = (this->lease >>  0) & 0xFF;

  o[pos++] = DHCP_OPTION_INTERFACE_MTU;
  o[pos++] = 2;
  o[pos++] = (conn->mtu >> 8) & 0xFF;
  o[pos++] = (conn->mtu >> 0) & 0xFF;

  o[pos++] = DHCP_OPTION_SERVER_ID;
  o[pos++] = 4;
  memcpy(&o[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  o[pos++] = DHCP_OPTION_END;

  return pos;
}

/**
 * dhcp_lnkconn()
 * Allocates/link a new connection from the pool.
 * Returns -1 if unsuccessful.
 **/
int dhcp_lnkconn(struct dhcp_t *this, struct dhcp_conn_t **conn) {

  s_config *config = config_get_config();

  if (!this->firstfreeconn) {

    if (connections == DHCP_MAX_CLIENTS) {
      debug(LOG_ERR, "reached max connections %d!", DHCP_MAX_CLIENTS);
      return -1;
    }

    ++connections;

    if (!(*conn = calloc(1, sizeof(struct dhcp_conn_t)))) {
      debug(LOG_ERR, "Out of memory!");
      return -1;
    }

  } else {

    *conn = this->firstfreeconn;

    /* Remove from link of free */
    if (this->firstfreeconn->next) {
      this->firstfreeconn->next->prev = NULL;
      this->firstfreeconn = this->firstfreeconn->next;
    }
    else { /* Took the last one */
      this->firstfreeconn = NULL;
      this->lastfreeconn = NULL;
    }

    /* Initialise structures */
    memset(*conn, 0, sizeof(struct dhcp_conn_t));
  }

  /* Insert into link of used */
  if (this->firstusedconn) {
    this->firstusedconn->prev = *conn;
    (*conn)->next = this->firstusedconn;
  }
  else { /* First insert */
    this->lastusedconn = *conn;
  }

  this->firstusedconn = *conn;

  return 0; /* Success */
}


/**
 * dhcp_newconn()
 * Allocates a new connection from the pool.
 * Returns -1 if unsuccessful.
 **/
int dhcp_newconn(struct dhcp_t *this,
		 struct dhcp_conn_t **conn,
		 uint8_t *hwaddr)
{

  debug(LOG_DEBUG, "DHCP newconn: "MAC_FMT"", MAC_ARG(hwaddr));

  if (dhcp_lnkconn(this, conn) != 0)
    return -1;

  (*conn)->inuse = 1;
  (*conn)->parent = this;
  (*conn)->mtu = this->mtu;

  /* Application specific initialisations */
  memcpy((*conn)->hismac, hwaddr, PKT_ETH_ALEN);
  /*memcpy((*conn)->ourmac, dhcp_nexthop(this), PKT_ETH_ALEN);*/

  (*conn)->lasttime = mainclock_now();

  dhcp_hashadd(this, *conn);

    /* Inform application that connection was created */
  /*this->cb_connect = cb_dhcp_connect*/
    if (this->cb_connect)
      this->cb_connect(*conn);

  return 0; /* Success */
}


/**
 * dhcp_freeconn()
 * Returns a connection to the pool.
 **/
int dhcp_freeconn(struct dhcp_conn_t *conn, int term_cause)
{
  /* TODO: Always returns success? */

  struct dhcp_t *this = conn->parent;

  /* Tell application that we disconnected */
  if (this->cb_disconnect)
    this->cb_disconnect(conn, term_cause);

    debug(LOG_DEBUG, "DHCP freeconn: "MAC_FMT,
           MAC_ARG(conn->hismac));


  /* Application specific code */
  /* First remove from hash table */
  dhcp_hashdel(this, conn);

  /* Remove from link of used */
  if ((conn->next) && (conn->prev)) {
    conn->next->prev = conn->prev;
    conn->prev->next = conn->next;
  }
  else if (conn->next) { /* && prev == 0 */
    conn->next->prev = NULL;
    this->firstusedconn = conn->next;
  }
  else if (conn->prev) { /* && next == 0 */
    conn->prev->next = NULL;
    this->lastusedconn = conn->prev;
  }
  else { /* if ((next == 0) && (prev == 0)) */
    this->firstusedconn = NULL;
    this->lastusedconn = NULL;
  }

  /* Initialise structures */
  memset(conn, 0, sizeof(*conn));

  /* Insert into link of free */
  if (this->firstfreeconn) {
    this->firstfreeconn->prev = conn;
  }
  else { /* First insert */
    this->lastfreeconn = conn;
  }

  conn->next = this->firstfreeconn;
  this->firstfreeconn = conn;

  return 0;
}

void dhcp_release_mac(struct dhcp_t *this, uint8_t *hwaddr, int term_cause) {
  struct dhcp_conn_t *conn;
  if (!dhcp_hashget(this, &conn, hwaddr)) {
/* no authstating process
    if (conn->authstate == DHCP_AUTH_DROP &&
	term_cause != RADIUS_TERMINATE_CAUSE_ADMIN_RESET)
      return;
*/
    dhcp_freeconn(conn, term_cause);
  }
}

uint8_t * dhcp_nexthop(struct dhcp_t *this) {
//Jerome TBD, multi-LAN?
  return this->rawif[0].hwaddr;
}

static
int dhcp_ethhdr(struct dhcp_conn_t *conn, uint8_t *packet, uint8_t *hismac,
                uint8_t *nexthop, uint16_t prot) {

    struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(packet);
    copy_mac6(pack_ethh->dst, hismac);
    copy_mac6(pack_ethh->src, nexthop);
    pack_ethh->prot = htons(prot);

  return 0;
}


int dhcp_net_send(struct _net_interface *netif, unsigned char *hismac,
		  uint8_t *packet, size_t length) {

  if (hismac) {
    netif->dest.sll_halen = PKT_ETH_ALEN;
    memcpy(netif->dest.sll_addr, hismac, PKT_ETH_ALEN);
  } else {
    netif->dest.sll_halen = 0;
    memset(netif->dest.sll_addr, 0, sizeof(netif->dest.sll_addr));
  }

  return net_write_eth(netif, packet, length, &netif->dest);
}


int dhcp_send(struct dhcp_t *this, int idx,
              unsigned char *hismac, uint8_t *packet, size_t length) {
  net_interface *iface = 0;

//  if (_options.tcpwin)
//    pkt_shape_tcpwin(pkt_iphdr(packet), _options.tcpwin);

//  if (_options.tcpmss)
//    pkt_shape_tcpmss(packet, &length);

#ifdef ENABLE_MULTILAN
  if (idx < 0) {
    int i, ret = -1;
    for (i=0; i < MAX_RAWIF && this->rawif[i].fd; i++)
      ret = dhcp_net_send(&this->rawif[i], hismac, packet, length);
    return ret;
  }
  iface = &this->rawif[idx];
#else
  iface = &this->rawif[0];
#endif

  return dhcp_net_send(iface, hismac, packet, length);
}

/*Jerome TBD for relay mode*/
int dhcp_relay_decaps(struct dhcp_t *this, int idx) {
  struct dhcp_tag_t *message_type = 0;
  struct dhcp_conn_t *conn = 0;
  struct dhcp_packet_t packet;
  struct sockaddr_in addr;
  socklen_t fromlen = sizeof(addr);
  ssize_t length;

  uint8_t fullpack[1500];
  s_config *config = config_get_config();

  if ((length = recvfrom(this->relayfd, &packet, sizeof(packet), 0,
                         (struct sockaddr *) &addr, &fromlen)) <= 0) {
    debug(LOG_ERR, "%s: recvfrom() failed", strerror(errno));
    return -1;
  }

  if (length < 44) {
    debug(LOG_DEBUG, "DHCP packet too short");
    return -1;
  }

  if (packet.op != 2) {
    debug(LOG_DEBUG, "Ignored non-relay reply DHCP packet");
    return -1;
  }

  debug(LOG_DEBUG, "DHCP relay response from %s of length %d received",
           inet_ntoa(addr.sin_addr), (int)length);

  if (addr.sin_addr.s_addr != config->dhcpgwip.s_addr &&
      addr.sin_addr.s_addr != config->tundevip.s_addr) {
    debug(LOG_DEBUG, "Received DHCP response from host (%s) other than our gateway",
             inet_ntoa(addr.sin_addr));
    return -1;
  }

  if (addr.sin_port != htons(config->dhcpgwport)) {
    debug(LOG_DEBUG, "Received DHCP response from port (%d) other than our gateway",
             ntohs(addr.sin_port));
    return -1;
  }

  if (dhcp_gettag(&packet, length, &message_type,
		  DHCP_OPTION_MESSAGE_TYPE)) {
    debug(LOG_ERR, "no message type");
    return -1;
  }

  if (message_type->l != 1) {
    debug(LOG_ERR, "wrong message type length");
    return -1; /* Wrong length of message type */
  }

  if (dhcp_hashget(this, &conn, packet.chaddr)) {
    /* Allocate new connection */
    if (dhcp_newconn(this, &conn, packet.chaddr)) {
      debug(LOG_ERR, "out of connections");
      return 0; /* Out of connections */
    }
  }

  if (conn->authstate == DHCP_AUTH_NONE ||
      conn->authstate == DHCP_AUTH_DNAT)
    this->cb_request(conn, (struct in_addr *)&packet.yiaddr, 0, 0);

  packet.giaddr = 0;

  memset(&fullpack, 0, sizeof(fullpack));

  dhcp_ethhdr(conn, fullpack, conn->hismac,
	      dhcp_nexthop(this), PKT_ETH_PROTO_IP);

  {
    struct pkt_iphdr_t *fullpack_iph = pkt_iphdr(fullpack);
    struct pkt_udphdr_t *fullpack_udph = NULL;

    fullpack_iph->version_ihl = PKT_IP_VER_HLEN;
    fullpack_iph->tot_len = htons(length + PKT_UDP_HLEN + PKT_IP_HLEN);
    fullpack_iph->ttl = 0x10;
    fullpack_iph->protocol = 0x11;
    fullpack_iph->saddr = config->dhcplisten.s_addr;

    /* init udph here because pkt_udphdr needs the ip version to get the correct offset */
    fullpack_udph = pkt_udphdr(fullpack);
    fullpack_udph->src = htons(DHCP_BOOTPS);
    fullpack_udph->len = htons(length + PKT_UDP_HLEN);

    fullpack_udph->dst = htons(DHCP_BOOTPC);
    fullpack_iph->daddr = ~0;

    if (packet.ciaddr) {
      debug(LOG_DEBUG, "DHCP: CIAddr");
      fullpack_iph->daddr = packet.ciaddr;
    } else if ((packet.flags[0] & 0x80) || message_type->v[0] == DHCPNAK) {
      debug(LOG_DEBUG, "DHCP: Nak or Broadcast");
      packet.flags[0] = 0x80;
      dhcp_ethhdr(conn, fullpack, bmac, dhcp_nexthop(this), PKT_ETH_PROTO_IP);
    } else if (packet.yiaddr) {
      debug(LOG_DEBUG, "DHCP: YIAddr");
      fullpack_iph->daddr = packet.yiaddr;
    }

    /*
     * Copy DHCP packet for forwarding
     */
    memcpy(pkt_dhcppkt(fullpack), &packet, length);

    {
      /*
       * Rewrite the server-id, otherwise will not get
       * subsequent requests
       */
      struct dhcp_tag_t *tag = 0;
      if (!dhcp_gettag(pkt_dhcppkt(fullpack), length,
		       &tag, DHCP_OPTION_SERVER_ID)) {
	memcpy(tag->v, &config->dhcplisten.s_addr, 4);
      }
    }

    chksum(fullpack_iph);

    addr.sin_addr.s_addr = fullpack_iph->daddr;
    debug(LOG_DEBUG, "Sending DHCP relay response %s:%d %d",
           inet_ntoa(addr.sin_addr),
           ntohs(fullpack_udph->dst),
           (int)(length + sizeofudp(fullpack)));

    addr.sin_addr.s_addr = fullpack_iph->saddr;
    debug(LOG_DEBUG, "Sending DHCP from %s:%d",
           inet_ntoa(addr.sin_addr),
           ntohs(fullpack_udph->src));

    return dhcp_send(this, 0, conn->hismac, fullpack,
		     length + sizeofudp(fullpack));
  }
}

/**
 * dhcp_sendGARP()
 * Send Gratuitous ARP message to network
 * http://wiki.wireshark.org/Gratuitous_ARP
 **/
int
dhcp_sendGARP(struct dhcp_t *this, int idx) {
  uint8_t packet[1500];

  struct pkt_ethhdr_t *packet_ethh;
  struct arp_packet_t *packet_arp;

  memset(packet, 0, sizeof(packet));

  packet_ethh = pkt_ethhdr(packet);
  packet_arp = pkt_arppkt(packet);

  /* ARP Payload */
  packet_arp->hrd = htons(DHCP_HTYPE_ETH);
  packet_arp->pro = htons(PKT_ETH_PROTO_IP);
  packet_arp->hln = PKT_ETH_ALEN;
  packet_arp->pln = PKT_IP_ALEN;
  packet_arp->op  = htons(DHCP_ARP_REPLY);

  /* Source address */
  memcpy(packet_arp->sha, dhcp_nexthop(this), PKT_ETH_ALEN);
  memcpy(packet_arp->spa, &this->ourip.s_addr, PKT_IP_ALEN);

  /* Target address */
  memcpy(packet_arp->tha, bmac, PKT_ETH_ALEN);
  memcpy(packet_arp->tpa, &this->ourip.s_addr, PKT_IP_ALEN);

  debug(LOG_DEBUG, "DHCP %s GARP with "MAC_FMT": Replying to broadcast",
		  inet_ntoa(this->ourip), MAC_ARG(this->rawif[0].hwaddr));

  /* Ethernet header */
  memcpy(packet_ethh->dst, bmac, PKT_ETH_ALEN);
  memcpy(packet_ethh->src, dhcp_nexthop(this), PKT_ETH_ALEN);
  packet_ethh->prot = htons(PKT_ETH_PROTO_ARP);

  return dhcp_send(this, idx, bmac, packet, sizeofarp(packet));
}


/**
 * dhcp_sendOFFER()
 * Send of a DHCP offer message to a peer.
 **/
int dhcp_sendOFFER(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {

  struct dhcp_t *this = conn->parent;

  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = dhcp_create_pkt(DHCPOFFER, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  pos = dhcp_accept_opt(conn, packet_dhcp->options, pos);

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
  chksum(packet_iph);

  uint16_t length = udp_len + sizeofip(packet);

  return dhcp_send(this, dhcp_conn_idx(conn), conn->hismac, packet, length);
}

/**
 * dhcp_sendACK()
 * Send of a DHCP acknowledge message to a peer.
 **/
int dhcp_sendACK(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {

  struct dhcp_t *this = conn->parent;

  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = dhcp_create_pkt(DHCPACK, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  pos = dhcp_accept_opt(conn, packet_dhcp->options, pos);

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
  chksum(packet_iph);

  uint16_t length = udp_len + sizeofip(packet);

  return dhcp_send(this, dhcp_conn_idx(conn), conn->hismac, packet, length);
}

/**
 * dhcp_sendNAK()
 * Send of a DHCP negative acknowledge message to a peer.
 * NAK messages are always sent to broadcast IP address (
 * except when using a DHCP relay server)
 **/
int dhcp_sendNAK(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {

  struct dhcp_t *this = conn->parent;
  uint8_t packet[1500];

  struct pkt_iphdr_t *packet_iph;
  struct pkt_udphdr_t *packet_udph;
  struct dhcp_packet_t *packet_dhcp;

  size_t pos = 0;

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  pos = dhcp_create_pkt(DHCPNAK, packet, pack, conn);

  packet_iph  = pkt_iphdr(packet);
  packet_udph = pkt_udphdr(packet);
  packet_dhcp = pkt_dhcppkt(packet);

  packet_dhcp->options[pos++] = DHCP_OPTION_SERVER_ID;
  packet_dhcp->options[pos++] = 4;
  memcpy(&packet_dhcp->options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  packet_dhcp->options[pos++] = DHCP_OPTION_END;

  uint16_t udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
  packet_udph->len = htons(udp_len);
  packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);

  chksum(packet_iph);
  uint16_t length = udp_len + sizeofip(packet);

  return dhcp_send(this, dhcp_conn_idx(conn), conn->hismac, packet, length);
}


static
int dhcp_uam_unnat(struct dhcp_conn_t *conn,
		   struct pkt_ethhdr_t *ethh,
		   struct pkt_iphdr_t  *iph,
		   struct pkt_tcphdr_t *tcph) {
  int n;
  for (n=0; n < DHCP_DNAT_MAX; n++) {

    if (iph->daddr == conn->dnat[n].src_ip &&
	tcph->dst == conn->dnat[n].src_port) {

      iph->saddr = conn->dnat[n].dst_ip;
      tcph->src = conn->dnat[n].dst_port;

      chksum(iph);

      return 0;
    }
  }
  return 0;
}
/**
 * dhcp_undoDNAT()
 * Change source address back to original server
 **/
static
int dhcp_undoDNAT(struct dhcp_conn_t *conn,
		  uint8_t *pack, size_t *plen,
		  char do_reset, char *do_checksum) {
  struct dhcp_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *tcph = pkt_tcphdr(pack);

  /* Allow localhost through network... */
  if (iph->saddr == INADDR_LOOPBACK)
    return 0;

  if (iph->protocol == PKT_IP_PROTO_ICMP) {
    /* Was it an ICMP reply from us? */
    if (iph->saddr == conn->ourip.s_addr) {

      return 0;
    }
  }

  /* Was it a reply from redir server? */
  if ( (iph->saddr == this->uamlisten.s_addr) &&
       (iph->protocol == PKT_IP_PROTO_TCP) &&
       (tcph->src == htons(this->uamport)
	) ) {

    *do_checksum = 1;

    return dhcp_uam_unnat(conn, ethh, iph, tcph);
  }

  return -1; /* Something else */
}


ssize_t
dns_fullname(char *data, size_t dlen,      /* buffer to store name */
	     uint8_t *res, size_t reslen,  /* current resource */
	     uint8_t *opkt, size_t olen,   /* original packet */
	     int lvl) {
  int ret = 0;
  char *d = data;
  unsigned char l;

  if (lvl >= 15) return -1;

  debug(LOG_DEBUG, "dlen=%zd reslen=%zd olen=%zd lvl=%d", dlen, reslen, olen, lvl);

  /* only capture the first name in query */
  if (d && d[0]) d = 0;

  while (reslen-- > 0 && ++ret && (l = *res++) != 0) {

    if (l >= dlen || l >= olen) {
      debug(LOG_DEBUG, "bad value %d/%zu/%zu", l, dlen, olen);
      return -1;
    }

    debug(LOG_DEBUG, "part[%.*s] reslen=%zd l=%d dlen=%zd", l, res, reslen, l, dlen);

    if (d) {
      memcpy(d, res, l);
      d += l;
      dlen -= l;
    }
    res += l;
    reslen -= l;
    ret += l;

    if (d) {
      *d = '.';
      d += 1;
      dlen -= 1;
    }
  }

  if (lvl == 0 && d) {
    int len = strlen((char *)data);
    if (len && len == (d - data) && data[len-1] == '.')
      data[len-1]=0;
  }

  return ret;
}

int
dns_copy_res(struct dhcp_conn_t *conn,
	     uint8_t **pktp, size_t *left,
	     uint8_t *opkt,  size_t olen,
	     uint8_t *question, size_t qsize) {
  uint8_t *p_pkt = *pktp;
  size_t len = *left;

  ssize_t namelen = 0;

  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlen;
  uint8_t *pkt_ttl=0;
  uint32_t ul;
  uint16_t us;

  debug(LOG_DEBUG, "left=%zd olen=%zd qsize=%zd", *left, olen, qsize);

  namelen = dns_fullname((char*)question, qsize-1,
			 p_pkt, len, opkt, olen, 0);

  if (namelen < 0 || namelen > len){
	debug(LOG_DEBUG, "Failed parsing DNS packet");
	return -1;
  }
  debug(LOG_DEBUG, "DNS: %s", question);

    return 0;
}


static
int dhcp_nakDNS(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {
  struct dhcp_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t *iph = pkt_iphdr(pack);
  struct pkt_udphdr_t *udph = pkt_udphdr(pack);

  uint8_t answer[len];

  struct pkt_ethhdr_t *answer_ethh;
  struct pkt_iphdr_t *answer_iph;
  struct pkt_udphdr_t *answer_udph;
  struct dns_packet_t *answer_dns;

  memcpy(answer, pack, len);

  answer_ethh = pkt_ethhdr(answer);
  answer_iph  = pkt_iphdr(answer);
  answer_udph = pkt_udphdr(answer);
  answer_dns  = pkt_dnspkt(answer);

  /* DNS response, with no host error code */
  answer_dns->flags = htons(0x8583);

  /* UDP */
  answer_udph->src = udph->dst;
  answer_udph->dst = udph->src;

  /* IP */
  answer_iph->check = 0; /* Calculate at end of packet */
  memcpy(&answer_iph->daddr, &iph->saddr, PKT_IP_ALEN);
  memcpy(&answer_iph->saddr, &iph->daddr, PKT_IP_ALEN);

  /* Ethernet */
  memcpy(&answer_ethh->dst, &ethh->src, PKT_ETH_ALEN);
  memcpy(&answer_ethh->src, &ethh->dst, PKT_ETH_ALEN);

  /* checksums */
  chksum(answer_iph);

  dhcp_send(this, dhcp_conn_idx(conn), conn->hismac, answer, len);
  return 0;
}

static
int dhcp_matchDNS(uint8_t *r, char *name) {
  int r_len = strlen((char *)r);
  int name_len = strlen(name);

  debug(LOG_DEBUG, "checking dns for %s in %s", name, r);

  if (r_len == name_len && !memcmp(r, name, name_len)) {
    return 1;
  }

  return 0;
}

/*
 *   dhcp_dns() - Checks DNS for bad packets or locally handled DNS.
 *   returns: 0 = do not forward, 1 = forward DNS
 */
static
int dhcp_dns(struct dhcp_conn_t *conn, uint8_t *pack, size_t *plen) {
  s_config *config = config_get_config();

  if (*plen < DHCP_DNS_HLEN + sizeofudp(pack)) {
    debug(LOG_DEBUG, "bad DNS packet of length %zu",   *plen);
    return 0;
  } else {

	debug(LOG_DEBUG, "DNS packet of length %zu",   *plen);

    struct dns_packet_t *dnsp = pkt_dnspkt(pack);

    size_t dlen = *plen - DHCP_DNS_HLEN - sizeofudp(pack);
    size_t olen = dlen;

    uint16_t flags   = ntohs(dnsp->flags);
    uint16_t qdcount = ntohs(dnsp->qdcount);

    uint8_t *dptr = (uint8_t *)dnsp->records;
    uint8_t q[512];

    int mode = 0;
    int qmatch = -1;
    int i;

    uint16_t id = ntohs(dnsp->id);
      debug(LOG_DEBUG, "dhcp_dns plen=%zd dlen=%zd olen=%zd",   *plen, dlen, olen);
      debug(LOG_DEBUG, "DNS ID:    %d",   id);
      debug(LOG_DEBUG, "DNS Flags: %d",   flags);

        /* it was a response? shouldn't be */
	if (((flags & 0x8000) >> 15) == 1) {
		debug(LOG_DEBUG, "Dropping unexpected DNS response");
		return 0;
	}

	memset(q, 0, sizeof(q));

	for (i=0; dlen && i < qdcount; i++) {
		if (dns_copy_res(conn, &dptr, &dlen,
				(uint8_t *)dnsp, olen, q, sizeof(q))) {
			syslog(LOG_WARNING, "dropping malformed DNS");
			return dhcp_nakDNS(conn,pack,*plen);
		}
	}

      if (flags == 0x0100 && qdcount >= 0x0001) {

        char *hostname = config->redirhost;

        uint8_t *p;
        uint8_t query[256];
        uint8_t reply[4];
        int match = 0;

        if (!match && hostname) {
        	match = dhcp_matchDNS(q, hostname);
        	if (match) {
        		memcpy(reply, &config->tundevip.s_addr, 4);
        	}
        }

        if (match) {

        	uint8_t answer[1500];

        	struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
        	struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
        	struct pkt_udphdr_t *udph = pkt_udphdr(pack);

        	struct pkt_ethhdr_t *answer_ethh;
        	struct pkt_iphdr_t  *answer_iph;
        	struct pkt_udphdr_t *answer_udph;
        	struct dns_packet_t *answer_dns;

        	size_t query_len = 0;
        	size_t udp_len;
        	size_t length;

        	int n;

        	p = dnsp->records;

        	debug(LOG_DEBUG, "It was a matching query!\n");

        	do {
        		if (query_len < 256)
        			query[query_len++] = *p;
        		else
        			break;
        	}
        	while (*p++ != 0); /* TODO */

          for (n=0; n<4; n++) {
            if (query_len < 256)
              query[query_len++] = *p++;
          }

          query[query_len++] = 0xc0;
          query[query_len++] = 0x0c;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x00;
          query[query_len++] = 0x00;
          query[query_len++] = 0x01;
          query[query_len++] = 0x2c;
          query[query_len++] = 0x00;
          query[query_len++] = 0x04;
          memcpy(query + query_len, reply, 4);
          query_len += 4;

          memcpy(answer, pack, *plen); /* TODO */

          answer_ethh = pkt_ethhdr(answer);
          answer_iph = pkt_iphdr(answer);
          answer_udph = pkt_udphdr(answer);
          answer_dns = pkt_dnspkt(answer);

          /* DNS Header */
          answer_dns->id      = dnsp->id;
          answer_dns->flags   = htons(0x8000);
          answer_dns->qdcount = htons(0x0001);
          answer_dns->ancount = htons(0x0001);
          answer_dns->nscount = htons(0x0000);
          answer_dns->arcount = htons(0x0000);
          memcpy(answer_dns->records, query, query_len);

          /* UDP header */
          udp_len = query_len + DHCP_DNS_HLEN + PKT_UDP_HLEN;
          answer_udph->len = htons(udp_len);
          answer_udph->src = udph->dst;
          answer_udph->dst = udph->src;

          /* Ip header */
          answer_iph->version_ihl = PKT_IP_VER_HLEN;
          answer_iph->tos = 0;
          answer_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
          answer_iph->id = 0;
          answer_iph->opt_off_high = 0;
          answer_iph->off_low = 0;
          answer_iph->ttl = 0x10;
          answer_iph->protocol = 0x11;
          answer_iph->check = 0; /* Calculate at end of packet */
          memcpy(&answer_iph->daddr, &iph->saddr, PKT_IP_ALEN);
          memcpy(&answer_iph->saddr, &iph->daddr, PKT_IP_ALEN);

          /* Ethernet header */
          memcpy(answer_ethh->dst, &ethh->src, PKT_ETH_ALEN);
          memcpy(answer_ethh->src, &ethh->dst, PKT_ETH_ALEN);

          /* Work out checksums */
          chksum(answer_iph);

          /* Calculate total length */
          length = udp_len + sizeofip(answer);

          dhcp_send(conn->parent, dhcp_conn_idx(conn), conn->hismac, answer, length);
          return 0;
        }
      }
  }

  return 1;
}


/**
 * dhcp_data_req()
 * Call this function to send an IP packet to the peer.
 * Called from the tun_ind function. This method is passed either
 * an Ethernet frame or an IP packet.
 **/
int dhcp_data_req(struct dhcp_conn_t *conn,
		  struct pkt_buffer *pb, int ethhdr) {
  struct dhcp_t *this = conn->parent;

  uint8_t *packet = pkt_buffer_head(pb);
  size_t length = pkt_buffer_length(pb);


  char do_checksum = 0;
  char allowed = 0;

  int authstate = 0;

  if (ethhdr) {
    /*
     * Ethernet frame
     */
    size_t hdrplus = sizeofeth2(tag) - sizeofeth(packet);
    if (hdrplus > 0) {
      if (pb->offset < hdrplus) {
	debug(LOG_ERR, "bad buffer off=%d hdrplus=%d",
               (int) pb->offset, (int) hdrplus);
	return 0;
      }
      pkt_buffer_grow(pb, hdrplus);
      packet = pkt_buffer_head(pb);
      length = pkt_buffer_length(pb);
    }
  } else {
    size_t hdrlen = sizeofeth2(tag);
    if (pb->offset < hdrlen) {
      debug(LOG_ERR, "bad buffer off=%d hdr=%d",
             (int) pb->offset, (int) hdrlen);
      return 0;
    }
    pkt_buffer_grow(pb, hdrlen);
    packet = pkt_buffer_head(pb);
    length = pkt_buffer_length(pb);
	debug(LOG_DEBUG, "adding %zd to IP frame length %zd",   hdrlen, length);
  }

  if (!this) {
    debug(LOG_WARNING, "DHCP connection no longer valid");
    return 0;
  }

  authstate = conn->authstate;

  dhcp_ethhdr(conn, packet, conn->hismac, dhcp_nexthop(this), PKT_ETH_PROTO_IP);

  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(packet);
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(packet);

  /* Was it a DNS response? */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->src == htons(DHCP_DNS)) {
  	debug(LOG_DEBUG, "A DNS response");
  	allowed = 1; /* Is allowed DNS */

  }

  switch (authstate) {

    case DHCP_AUTH_PASS:
//      dhcp_postauthDNAT(conn, packet, length, 1, &do_checksum);
      break;

    case DHCP_AUTH_DNAT:
    case DHCP_AUTH_NONE:
      /* undo destination NAT */
      if (dhcp_undoDNAT(conn, packet, &length, 1, &do_checksum) && !allowed) {
    	debug(LOG_DEBUG, "dhcp_undoDNAT() returns true");
        return 0;
      }
      break;

    case DHCP_AUTH_DROP:
		debug(LOG_DEBUG, "drop");
    	return 0;
    default:
		debug(LOG_DEBUG, "unhandled authstate %d",   authstate);
    	return 0;
  }

  if (do_checksum)
      chksum(pkt_iphdr(packet));

  return dhcp_send(this, 0, conn->hismac, packet, length);
}


/**
 * dhcp_checkconn()
 * Checks connections to see if the lease has expired
 **/
int dhcp_checkconn(struct dhcp_t *this) {
  struct dhcp_conn_t *conn = this->firstusedconn;

  while (conn) {
//    debug(LOG_DEBUG, "dhcp_checkconn: %d %d", mainclock_diff(conn->lasttime), (int) this->lease);

    struct dhcp_conn_t *check_conn = conn;
    conn = conn->next;
    if (mainclock_diff(check_conn->lasttime) > (int)this->lease ) {
      debug(LOG_DEBUG, "DHCP timeout: Removing connection");
      dhcp_freeconn(check_conn, 0);
    }
  }

  return 0;
}

/**
 * dhcp_timeout()
 * Need to call this function at regular intervals to clean up old connections.
 **/
int dhcp_timeout(struct dhcp_t *this)
{
  /*dhcp_validate(this);*/

  dhcp_checkconn(this);

  return 0;
}


/**
 * dhcp_creat()
 * Allocates a new instance of the library
 **/
int dhcp_creat(struct dhcp_t **pdhcp, char *interface, struct in_addr *listen,
	     struct in_addr *uamlisten, uint16_t uamport) {
  s_config *config = config_get_config();

  struct dhcp_t *dhcp;

  if (!(dhcp = *pdhcp = calloc(sizeof(struct dhcp_t), 1))) {
    debug(LOG_ERR, "calloc() failed");
    return -1;
  }

  if (net_init(&dhcp->rawif[0], interface, ETH_P_ALL, 1) < 0) {
    free(dhcp);
    return -1;
  }
  debug(LOG_DEBUG, "Set DHCP inst[0] socket fd %d of dev %s", dhcp->rawif[0].fd, dhcp->rawif[0].devname);

#ifdef ENABLE_MULTILAN
  {
    int idx, i;
    for (i=1, idx=1; i < MAX_MOREIF && config->internalif[i]; i++, idx++) {
      if (net_init(&dhcp->rawif[idx], config->internalif[i],
		   0, 1) < 0) {
    	  debug(LOG_ERR, "could not setup interface %s", config->internalif[i]);
      } else {
    	  debug(LOG_DEBUG, "Configured interface %s fd=%d",
			config->internalif[i],
            dhcp->rawif[idx].fd);
      }
    }
  }
#endif


  /*
   * ====[http://tools.ietf.org/id/draft-ietf-dhc-implementation-02.txt]====
   * 4.7.2 Relay Agent Port Usage
   *    Relay agents should use port 67 as the source port number.  Relay
   *    agents always listen on port 67, but port 68 has sometimes been used
   *    as the source port number probably because it was copied from the
   *    source port of the incoming packet.
   *
   *    Cable modem vendors would like to install filters blocking outgoing
   *    packets with source port 67.
   *
   *    RECOMMENDATIONS:
   *      O  Relay agents MUST use 67 as their source port number.
   *      O  Relay agents MUST NOT forward packets with non-zero giaddr
   *         unless the source port number on the packet is 67.
   */
  if (config->dhcpgwip.s_addr != 0) {
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int on = 1;

    if (fd > 0) {

      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = config->tundevip.s_addr;
      addr.sin_port = htons(config->dhcpgwport);

      if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    	  debug(LOG_ERR, "%s: Can't set reuse option", strerror(errno));
      }

      if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    	  debug(LOG_ERR, "%s: socket or bind failed for dhcp relay!", strerror(errno));
    	  close(fd);
    	  fd = -1;
      }
    }

    if (fd > 0) {
      dhcp->relayfd = fd;
    } else {
      /*Jerome TBD for multi-LAN*/
      close(dhcp->rawif[0].fd);
      free(dhcp);
      return -1;
    }
  }

  if (dhcp_hashinit(dhcp, DHCP_HASH_TABLE))
    return -1; /* Failed to allocate hash tables */

  /* Initialise various variables */
  dhcp->ourip.s_addr = listen->s_addr;
  debug(LOG_DEBUG, "Set DHCP listener of IP %s", inet_ntoa(dhcp->ourip));
  dhcp->lease = DHCP_LEASE_TIME;
//  dhcp->numconn = DHCP_MAX_CLIENTS;

  dhcp->uamlisten.s_addr = uamlisten->s_addr;
  dhcp->uamport = uamport;
  dhcp->mtu = dhcp->rawif[0].mtu;

  /* Initialise call back functions */
  dhcp->cb_data_ind = NULL;
  dhcp->cb_request = NULL;
  dhcp->cb_disconnect = NULL;
  dhcp->cb_connect = NULL;

  dhcp_sendGARP(dhcp, -1);

  return 0;
}


int chilli_new_conn(struct app_conn_t **conn) {
  int n;
  s_config *config = config_get_config();

  if (!firstfreeconn) {

    if (connections == DHCP_MAX_CLIENTS) {
      debug(LOG_ERR, "reached max connections %d!", DHCP_MAX_CLIENTS);
      return -1;
    }

    n = ++connections;

    if (!(*conn = calloc(1, sizeof(struct app_conn_t)))) {
      debug(LOG_ERR, "Out of memory!");
      connections--;
      return -1;
    }

  } else {

    *conn = firstfreeconn;
    n = (*conn)->unit;

    /* Remove from link of free */
    if (firstfreeconn->next) {
      firstfreeconn->next->prev = NULL;
      firstfreeconn = firstfreeconn->next;
    }
    else { /* Took the last one */
      firstfreeconn = NULL;
      lastfreeconn = NULL;
    }

    /* Initialise structures */
    memset(*conn, 0, sizeof(struct app_conn_t));
  }

  /* Initalise connection with default options */
  /*Jerome withdrawn*/
//  session_param_defaults(&(*conn)->s_params);

  /* Insert into link of used */
  if (firstusedconn) {
    firstusedconn->prev = *conn;
    (*conn)->next = firstusedconn;
  }
  else { /* First insert */
    lastusedconn = *conn;
  }

  firstusedconn = *conn;

  (*conn)->inuse = 1;
  (*conn)->unit = n;

  return 0; /* Success */
}


int chilli_connect(struct _t_client **client, struct dhcp_conn_t *conn) {
  struct _t_client *newclient;

  debug(LOG_DEBUG, "New Chilli Connection of "MAC_FMT"", MAC_ARG(conn->hismac));

  /* Allocate new application connection */
  /*Jerome: J-Module changes it to */
//  if (chilli_new_conn(client)) {
  *client = client_list_add(inet_ntoa(conn->hisip), conn->hismac, NULL);
  if (!(*client)) {
    debug(LOG_ERR, "Failed to allocate connection");
    return -1;
  }

  newclient = *client;
//  newclient->dnprot =  DNPROT_DHCP_NONE;

//Jerome  aconn->net.s_addr = _options.net.s_addr;
//Jerome  aconn->mask.s_addr = _options.mask.s_addr;
//Jerome  aconn->dns1.s_addr = _options.dns1.s_addr;
//Jerome  aconn->dns2.s_addr = _options.dns2.s_addr;

  if (conn) {
    memcpy(newclient->hismac, conn->hismac, PKT_ETH_ALEN);
    newclient->dnlink =  conn;
  }

  newclient->rt = (int) mainclock_rt();
//  set_sessionid(aconn, 1);

  return 0;
}
/*Jerome: J-Module modified from session_disconnect without the function of terminate_appconn*/
static int
client_disconnect(struct _t_client *client,
		   struct dhcp_conn_t *dhcpconn,
		   int term_cause) {

  if (client->uplink) {
    struct ippoolm_t *member = (struct ippoolm_t *) client->uplink;

    if (member->in_use && (!dhcpconn || !dhcpconn->is_reserved)) {
      if (ippool_freeip(ippool, member)) {
	debug(LOG_ERR, "ippool_freeip(%s) failed!",
               inet_ntoa(member->addr));
      }
    }
  }

  if (!dhcpconn || !dhcpconn->is_reserved) {
  /*Jerome TBD, for check remove client from the list*/
	  client_list_delete(client);
    if (dhcpconn)     dhcpconn->peer = 0;
  }

  return 0;
}


/**
 * dhcp_sendARP()
 * Send ARP message to peer
 **/
static
int dhcp_sendARP(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {
  uint8_t packet[1500];
  struct dhcp_t *this = conn->parent;
  struct in_addr reqaddr;

  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

  struct pkt_ethhdr_t *packet_ethh;
  struct arp_packet_t *packet_arp;

  /* Get local copy */
  memcpy(&reqaddr.s_addr, pack_arp->tpa, PKT_IP_ALEN);

  /* Check that request is within limits */

  /* Get packet default values */
  memset(packet, 0, sizeof(packet));
  copy_ethproto(pack, packet);

  packet_ethh = pkt_ethhdr(packet);
  packet_arp = pkt_arppkt(packet);

  /* ARP Payload */
  packet_arp->hrd = htons(DHCP_HTYPE_ETH);
  packet_arp->pro = htons(PKT_ETH_PROTO_IP);
  packet_arp->hln = PKT_ETH_ALEN;
  packet_arp->pln = PKT_IP_ALEN;
  packet_arp->op  = htons(DHCP_ARP_REPLY);

  /* Source address */
  memcpy(packet_arp->spa, &reqaddr.s_addr, PKT_IP_ALEN);
  memcpy(packet_arp->sha, dhcp_nexthop(this), PKT_ETH_ALEN);

  /* Target address */
  memcpy(packet_arp->tha, &conn->hismac, PKT_ETH_ALEN);
  memcpy(packet_arp->tpa, &conn->hisip.s_addr, PKT_IP_ALEN);

  debug(LOG_DEBUG, "ARP: Replying to %s / "MAC_FMT,
           inet_ntoa(conn->hisip),
           MAC_ARG(conn->hismac));

  /* Ethernet header */
  memcpy(packet_ethh->dst, conn->hismac, PKT_ETH_ALEN);
  memcpy(packet_ethh->src, dhcp_nexthop(this), PKT_ETH_ALEN);

  return dhcp_send(this, 0, conn->hismac,
		   packet, sizeofarp(packet));
}


int dhcp_getconn(struct dhcp_t *this,
		 struct dhcp_conn_t **conn,
		 uint8_t *mac, uint8_t *pkt,
		 char do_alloc) {
  if (dhcp_hashget(this, conn, mac)) {
    if (!do_alloc)
      return -1;

    if (dhcp_newconn(this, conn, mac))
      return -1;
  }

  if (!*conn)
    return -1;

  return 0;
}

/**
 * dhcp_gettag()
 * Search a DHCP packet for a particular tag.
 * Returns -1 if not found.
 **/
int dhcp_gettag(struct dhcp_packet_t *pack, size_t length, struct dhcp_tag_t **tag, uint8_t tagtype)
{
  struct dhcp_tag_t *t;
  size_t offset = DHCP_MIN_LEN + DHCP_OPTION_MAGIC_LEN;

  while ((offset + 2) < length) {
    t = (struct dhcp_tag_t *)(((uint8_t *)pack) + offset);
    if (t->t == tagtype) {
      if ((offset + 2 + (size_t)(t->l)) > length)
	return -1; /* Tag length too long */
      *tag = t;
      return 0;
    }
    offset += 2 + t->l;
  }

  return -1; /* Not found  */
}


/**
 *  dhcp_getreq()
 *  Process a received DHCP request and sends a response.
 **/
int dhcp_getreq(struct dhcp_ctx *ctx, uint8_t *pack, size_t len) {
  struct dhcp_t *this = ctx->parent;
  uint8_t mac[PKT_ETH_ALEN];
  struct dhcp_tag_t *message_type = 0;
  struct dhcp_tag_t *requested_ip = 0;
  struct dhcp_conn_t *conn;
  struct in_addr addr;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
  struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);

  s_config *config = config_get_config();

  debug(LOG_DEBUG, "function dhcp_getreq "MAC_FMT, MAC_ARG(pack_ethh->src));

  if (pack_udph->dst != htons(DHCP_BOOTPS))
    return 0; /* Not a DHCP packet */

  if (dhcp_gettag(pkt_dhcppkt(pack), ntohs(pack_udph->len)-PKT_UDP_HLEN,
		  &message_type, DHCP_OPTION_MESSAGE_TYPE)) {
	  debug(LOG_ERR, "Failed to get DHCP tag");
    return -1;
  }

  if (message_type->l != 1)
    return -1; /* Wrong length of message type */

  if (memcmp(pack_dhcp->chaddr, nmac, PKT_ETH_ALEN))
    memcpy(mac, pack_dhcp->chaddr, PKT_ETH_ALEN);
  else
    memcpy(mac, pack_ethh->src, PKT_ETH_ALEN);

  switch(message_type->v[0]) {

    case DHCPDECLINE:
        debug(LOG_DEBUG,"DHCP-Decline");
        dhcp_release_mac(this, mac, 0);
        break;

    case DHCPRELEASE:
        debug(LOG_DEBUG,"DHCP-Release");
        dhcp_release_mac(this, mac, 0);
        break;

    case DHCPDISCOVER:
        debug(LOG_DEBUG,"DHCP-DISCOVER");
        break;
    case DHCPREQUEST:
        debug(LOG_DEBUG,"DHCP-REQUEST");
        break;
    case DHCPINFORM:
        debug(LOG_DEBUG,"DHCP-INFORM");
      break;

    default:
      return 0; /* Unsupported message type */
  }

  if (message_type->v[0] == DHCPDECLINE || message_type->v[0] == DHCPRELEASE) {
    /* No Reply to client is sent */
    return 0;
  }

  if (dhcp_getconn(this, &conn, mac, pack, 1)) {
    /* Could not allocate address */
      debug(LOG_ERR,"Could not allocate address");
    return 0;
  }

  dhcp_conn_set_idx(conn, ctx);

  if (this->relayfd > 0) {
    /** Relay the DHCP request **/
    return dhcp_relay(this, pack, len);
  }

/* no authstating process
  if (conn->authstate == DHCP_AUTH_DROP)
    return 0;
*/

  addr.s_addr = pack_dhcp->ciaddr;

  if (!dhcp_gettag(pkt_dhcppkt(pack), ntohs(pack_udph->len)-PKT_UDP_HLEN,
		   &requested_ip, DHCP_OPTION_REQUESTED_IP))
    memcpy(&addr.s_addr, requested_ip->v, 4);

  /*Jerome
  if (addr.s_addr &&
      (addr.s_addr & config->netmask.s_addr) != config->tundevip.s_addr) {
    debug(LOG_DEBUG, "NAK: strictdhcp and address not in net");
    return dhcp_sendNAK(conn, pack, len);
  }
*/

  /* Request an IP address */
  /** if (conn->authstate == DHCP_AUTH_NONE) XXX **/
  {
    if (this->cb_request &&
	this->cb_request(conn, &addr, pack, len)) {
      debug(LOG_DEBUG, "NAK: auth-none");
      return dhcp_sendNAK(conn, pack, len);
    }
  }

  conn->lasttime = mainclock_now();

  /* Discover message */
  /* If an IP address was assigned offer it to the client */
  /* Otherwise ignore the request */
  switch (message_type->v[0]) {
    case DHCPDISCOVER:
      if (conn->hisip.s_addr)
        dhcp_sendOFFER(conn, pack, len);
      	debug(LOG_DEBUG, "Sending offer to "MAC_FMT" with IP %s",
      			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
      return 0;

    case DHCPREQUEST:
      {
        char send_ack = 0;

        if (!conn->hisip.s_addr) {
          debug(LOG_DEBUG, "hisip not set!");
          return dhcp_sendNAK(conn, pack, len);
        }

        if (!memcmp(&conn->hisip.s_addr, &pack_dhcp->ciaddr, 4))
          send_ack = 1;

        if (!send_ack)
          if (!memcmp(&conn->hisip.s_addr, &addr.s_addr, 4))
            send_ack = 1;

        if (send_ack) {
          debug(LOG_DEBUG, "Sending ACK to "MAC_FMT" with IP %s",
          			MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));
          return dhcp_sendACK(conn, pack, len);
        }

        debug(LOG_DEBUG, "Sending NAK to client");
        return dhcp_sendNAK(conn, pack, len);
      }
  }

  /*
   *  Unsupported DHCP message: Ignore
   */
  debug(LOG_DEBUG, "Unsupported DHCP message ignored");
  return 0;
}



static
int dhcp_uam_nat(struct dhcp_conn_t *conn,
		 struct pkt_ethhdr_t *ethh,
		 struct pkt_iphdr_t  *iph,
		 struct pkt_tcphdr_t *tcph,
		 struct in_addr *addr,
		 uint16_t port) {
  int n;
  int pos = -1;

  debug(LOG_DEBUG, "uam_nat %s:%d",   inet_ntoa(*addr), port);

  for (n=0; n < DHCP_DNAT_MAX; n++) {
    if (conn->dnat[n].src_ip == iph->saddr &&
	conn->dnat[n].src_port == tcph->src) {
      pos = n;
      debug(LOG_DEBUG, "uam_nat pos %d",  pos);

      break;
    }
  }

  if (pos == -1) {
    pos = conn->nextdnat;
    conn->dnat[pos].src_ip = iph->saddr;
    conn->dnat[pos].src_port = tcph->src;
    conn->nextdnat = (conn->nextdnat + 1) % DHCP_DNAT_MAX;
  }

  conn->dnat[pos].dst_ip = iph->daddr;
  conn->dnat[pos].dst_port = tcph->dst;

  iph->daddr = addr->s_addr;
  tcph->dst = htons(port);

  chksum(iph);

  return 0;
}


/**
 * dhcp_doDNAT()
 * Change destination address to authentication server.
 **/
int dhcp_doDNAT(struct dhcp_conn_t *conn, uint8_t *pack,
		size_t len, char do_reset,
		char *do_checksum) {
  struct dhcp_t *this = conn->parent;
  struct pkt_ethhdr_t *ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *tcph = pkt_tcphdr(pack);

  /* Allow localhost through network... */
  if (iph->daddr == INADDR_LOOPBACK)
    return 0;

  /* Was it an ICMP request for us? */
  if (iph->protocol == PKT_IP_PROTO_ICMP) {
    if (iph->daddr == conn->ourip.s_addr) {
      return 0;
    }
  }

  /* Was it a request for local redirection server? */
  if ( ( iph->protocol == PKT_IP_PROTO_TCP )    &&
       ( iph->daddr == this->uamlisten.s_addr ) &&
       ( tcph->dst == htons(this->uamport)
	 ) ) {
    return 0; /* Destination was local redir server */
  }

  if (iph->protocol == PKT_IP_PROTO_TCP) {
    if (tcph->dst == htons(DHCP_HTTP)) {
      /* Was it a http request for another server? */
      /* We are changing dest IP and dest port to local UAM server */

      *do_checksum = 1;

      return dhcp_uam_nat(conn, ethh, iph, tcph,
			  &this->uamlisten, this->uamport);
    }
  }

  return -1; /* Something else */
}


int dhcp_relay(struct dhcp_t *this,
		      uint8_t *pack, size_t len) {
  struct pkt_udphdr_t *pack_udph = pkt_udphdr(pack);
  struct dhcp_packet_t *pack_dhcp = pkt_dhcppkt(pack);
  struct sockaddr_in addr;

  s_config *config = config_get_config();

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = config->dhcpgwip.s_addr;
  addr.sin_port = htons(config->dhcpgwport);

  // -- http://www.faqs.org/rfcs/rfc1542.html
  // If the relay agent does decide to relay the request, it MUST examine
  // the 'giaddr' ("gateway" IP address) field.  If this field is zero,
  // the relay agent MUST fill this field with the IP address of the
  // interface on which the request was received.   ...
  // --
  // If the 'giaddr' field contains some non-zero value, the 'giaddr' field MUST
  //   NOT be modified.
  // --
    pack_dhcp->giaddr = config->tundevip.s_addr;


    /* rewrite the server-id, to match the
       upstream server (should be taken from
       previous replies) */
    struct dhcp_tag_t *tag = 0;
    if (!dhcp_gettag(pack_dhcp, ntohs(pack_udph->len) - PKT_UDP_HLEN,
		     &tag, DHCP_OPTION_SERVER_ID)) {
      memcpy(tag->v, &config->dhcpgwip.s_addr, 4);
    }


  pack_dhcp->hops++;

  debug(LOG_DEBUG, "Sending DHCP relay packet to %s",
           inet_ntoa(addr.sin_addr));

  /* if we can't send, lets do dhcp ourselves */
  if (sendto(this->relayfd, pack_dhcp,
	     ntohs(pack_udph->len) - PKT_UDP_HLEN, 0,
	     (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    debug(LOG_ERR, "%s: could not relay DHCP request!", strerror(errno));
    return -1;
  }

  return 0;
}


/**
 * dhcp_free()
 * Releases ressources allocated to the instance of the library
 **/
void dhcp_free(struct dhcp_t *dhcp) {
  struct dhcp_conn_t *conn, *c;

  if (!dhcp) return;
  if (dhcp->hash)
    free(dhcp->hash);

  for (int i=0; i < MAX_RAWIF && dhcp->rawif[i].fd > 0; i++) {
      dev_set_flags(dhcp->rawif[i].devname,
    		  dhcp->rawif[i].devflags);
      net_close(&dhcp->rawif[i]);
  }


  for (conn = dhcp->firstfreeconn; conn; ) {
    c = conn;
    conn = conn->next;
    free(c);
  }

  for (conn = dhcp->firstusedconn; conn; ) {
    c = conn;
    conn = conn->next;
    free(c);
  }

  free(dhcp);
}


/* Callback when a dhcp connection is deleted */
int cb_dhcp_disconnect(struct dhcp_conn_t *conn, int term_cause) {
  struct _t_client *client;

  debug(LOG_INFO, "DHCP Released MAC="MAC_FMT" IP=%s",
         MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));

  debug(LOG_DEBUG, "DHCP connection removed");

  if (!conn->peer) {
    /* No appconn allocated. Stop here */

    return 0;
  }

  client = (struct _t_client*) conn->peer;

  return client_disconnect(client, conn, term_cause);
}

/***********************************************************
 *
 * dhcp callback functions
 *
 ***********************************************************/

/* DHCP callback for allocating new IP address */
/* In the case of WPA it is allready allocated,
 * for UAM address is allocated before authentication */
int cb_dhcp_request(struct dhcp_conn_t *conn, struct in_addr *addr,
		    uint8_t *dhcp_pkt, size_t dhcp_len) {

  s_config *config = config_get_config();
  struct _t_client *client = conn->peer;
  struct ippoolm_t *ipm = 0;
//  char domacauth = (char) _options.macauth;
//  char allocate = 1;

  debug(LOG_DEBUG, "DHCP request for MAC "MAC_FMT" with IP address %s",
		  MAC_ARG(conn->hismac),
         addr ? inet_ntoa(*addr) : "n/a");

  if (!client) {
    debug(LOG_ERR, "Peer protocol not defined");
    return -1;
  }

  /* Jerome: J-module modified */
  struct in_addr reqip;
  reqip.s_addr = addr ? addr->s_addr : 0;

  if (client->uplink) {

    /*
     *  IP Address is already known and allocated.
     */
    ipm = (struct ippoolm_t*) client->uplink;

  } else {

	    if (client->hisip.s_addr) {
	      debug(LOG_WARNING, "Requested IP address when already allocated (hisip %s)",
	             inet_ntoa(client->hisip));
	      reqip.s_addr = client->hisip.s_addr;
	    }

	    /* Allocate dynamic IP address */
	    /* XXX  if (ippool_newip(ippool, &ipm, &appconn->reqip, 0)) {*/
	    if (newip(&ipm, &reqip, conn->hismac)) {
	      debug(LOG_ERR, "Failed allocate dynamic IP address");
	      return -1;
	    }

	    client->hisip.s_addr = ipm->addr.s_addr;
	    client->hismask.s_addr = config->netmask.s_addr;

	    debug(LOG_DEBUG, "Client MAC="MAC_FMT" assigned IP %s" ,
	             MAC_ARG(conn->hismac), inet_ntoa(client->hisip));


	    /* TODO: Too many "listen" and "our" addresses hanging around */
	    if (!client->ourip.s_addr)
	      client->ourip.s_addr = config->dhcplisten.s_addr;

	    client->uplink = ipm;
	    ipm->peer = client;

  }


   if (ipm) {
	  conn->hisip.s_addr = ipm->addr.s_addr;
	  conn->hismask.s_addr = config->netmask.s_addr;
	  conn->ourip.s_addr = client->ourip.s_addr;
	  /*Jerome, deleted function
	  dhcp_set_addrs(conn,
		   &ipm->addr, &_options.mask,
		   &appconn->ourip, &appconn->mask,
		   &_options.dns1, &_options.dns2);
		   */
   }


  /* If IP was requested before authentication it was UAM */
  if (conn->authstate != DHCP_AUTH_PASS)
	  conn->authstate = DHCP_AUTH_DNAT;

  /*Jerome, TBD*/
  //conn->authstate = DHCP_AUTH_PASS;

  /*Jerome, withdrow
  if (_options.dhcpnotidle)
    appconn->s_state.last_up_time = mainclock.tv_sec;
	End. Jerome */
  return 0;
}


/* DHCP callback for establishing new connection */
int cb_dhcp_connect(struct dhcp_conn_t *conn) {
  struct _t_client *client;
  s_config *config = config_get_config();

  debug(LOG_DEBUG, "New DHCP request from MAC="MAC_FMT"", MAC_ARG(conn->hismac));

  if (chilli_connect(&client, conn))
    return 0;

  if ((config->macoklen) && !maccmp(conn->hismac, config)) {
	  conn->authstate = DHCP_AUTH_PASS;
	  debug(LOG_DEBUG, "cb_dhcp_connect. MAC "MAC_FMT" is allowed.\n", MAC_ARG(conn->hismac));
  }else{
	  conn->authstate = DHCP_AUTH_DNAT;
  }
  conn->peer = client;
  conn->dns1 = config->dns1;
  conn->dns2 = config->dns2;

  return 0;
}

/* Callback for receiving messages from dhcp */
int cb_dhcp_data_ind(struct dhcp_conn_t *conn, uint8_t *pack, size_t len) {
  struct _t_client *client = conn ? conn->peer : 0;


  if (!client) {
    {
      debug(LOG_ERR, "No peer protocol defined");
      return -1;
    }
  }

  debug(LOG_DEBUG, "cb_dhcp_data_ind. Packet is sending via Tun. DHCP authstate: %d",
    conn->authstate);
  /*Jerome: J-Module modified. Not judged by client's authstate, but by DHCP conn's
  switch (conn->authstate) {
    case DHCP_AUTH_NONE:
    case DHCP_AUTH_DROP:
    case DHCP_AUTH_DNAT:
      debug(LOG_DEBUG, "NULL: %d",  conn->authstate);
      return -1;

    case DHCP_AUTH_PASS:

      break;

    default:
      debug(LOG_ERR, "Unknown downlink protocol: %d", conn->authstate);
      break;
  }
End Jerome*/
  return tun_encaps(tun, pack, len, 0);
}


/**
 *  dhcp_receive_ip()
 *  Received a packet from the dhcpif
 */
int dhcp_receive_ip(struct dhcp_ctx *ctx, uint8_t *pack, size_t len) {
  struct dhcp_t *this = ctx->parent;
  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct pkt_iphdr_t  *pack_iph  = pkt_iphdr(pack);
  struct pkt_tcphdr_t *pack_tcph = 0;
  struct pkt_udphdr_t *pack_udph = 0;
  struct dhcp_conn_t *conn = 0;
  struct in_addr ourip;
  struct in_addr srcaddr, dstaddr;

  char do_checksum = 0;
  char allowed = 0;
  char has_ip = 0;
  char is_dhcp = 0;

  int authstate = 0;

  s_config *config = config_get_config();
//  struct _t_client *client;

  uint16_t iph_tot_len;
  uint16_t eth_tot_len;

  if (len < PKT_IP_HLEN + PKT_ETH_HLEN + 4) {
    debug(LOG_ERR, "IP: too short");
    return 0;
  }

  if ((pack_iph->version_ihl & 0xf0) != 0x40) {
    debug(LOG_DEBUG, "IP: dropping non-IPv4");
    return 0;
  }

  srcaddr.s_addr = pack_iph->saddr;
  dstaddr.s_addr = pack_iph->daddr;
  debug(LOG_DEBUG, "DHCP Get packet from IP %s", inet_ntoa(srcaddr));
  debug(LOG_DEBUG, "DHCP Get packet to IP %s", inet_ntoa(dstaddr));

  /*
   *  Check to see if we know MAC address
   */
  if (!dhcp_hashget(this, &conn, pack_ethh->src)) {

    debug(LOG_DEBUG, "IP: MAC Address "MAC_FMT" found", MAC_ARG(pack_ethh->src));
//    ourip.s_addr = conn->ourip.s_addr;

  } else {

    struct in_addr reqaddr;

    memcpy(&reqaddr.s_addr, &pack_iph->saddr, PKT_IP_ALEN);

    debug(LOG_DEBUG, "IP: MAC address "MAC_FMT" not found with IP (%s), add new connection",
    		MAC_ARG(pack_ethh->src),
			inet_ntoa(reqaddr));

    /* Allocate new connection */
    if (dhcp_newconn(this, &conn, pack_ethh->src)) {
      debug(LOG_DEBUG, "dropping packet; out of connections");
      return 0; /* Out of connections */
    }
  }

  /* Return if we do not know peer */
  if (!conn) {
    debug(LOG_ERR, "dropping packet; no peer");
    return 0;
  }

  dhcp_conn_set_idx(conn, ctx);
  /*
   * Sanity check on IP total length
   */
  iph_tot_len = ntohs(pack_iph->tot_len);
  eth_tot_len = iph_tot_len + sizeofeth(pack);

  if (eth_tot_len > (uint16_t) len) {
    debug(LOG_ERR, "dropping ip packet; ip-len=%d + eth-hdr=%d > read-len=%d",
             iph_tot_len,
             sizeofeth(pack), (int)len);

    if (pack_iph->opt_off_high & 64) { /* Don't Defrag Option */
      uint8_t icmp_pack[1500];

      debug(LOG_ERR, "Sending fragmentation ICMP");
      dhcp_send(this, ctx->idx, pack_ethh->src, icmp_pack,
		icmpfrag(conn, icmp_pack, sizeof(icmp_pack), pack));
    }

    return 0;
  }

  /* Validate IP header length */
  if ((pack_iph->version_ihl & 0xf) < 5 ||
      (pack_iph->version_ihl & 0xf) * 4 > iph_tot_len) {
    debug(LOG_ERR, "dropping invalid-IPv4");
    return 0;
  }

  /*
   * Do not drop all fragments, only if they have DF bit.
   * Note: this is as in SVN before R462 / git e4a934 (2012-03-01 15:46:22).
   */

  if (iph_tot_len > conn->mtu && (pack_iph->opt_off_high & 64)) {
    uint8_t icmp_pack[1500];
    debug(LOG_ERR, "ICMP frag forbidden for IP packet with length %d > %d",
             iph_tot_len, conn->mtu);
    dhcp_send(this, ctx->idx, pack_ethh->src, icmp_pack,
	      icmpfrag(conn, icmp_pack, sizeof(icmp_pack), pack));
    return 0;
  }

  /*
   *  Chop off any trailer length
   */
  if (len > (size_t) eth_tot_len) {
    //log_dbg("chopping off trailer length %d", len - eth_tot_len);
    len = eth_tot_len;
  }

  /*
   * Sanity check on UDP total length
   * Note: we cannot check fragments.
   */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP) {
    pack_udph = pkt_udphdr(pack);
    uint16_t udph_len = ntohs(pack_udph->len);
    if (udph_len < PKT_UDP_HLEN || iph_tot_len < PKT_IP_HLEN + PKT_UDP_HLEN ||
        (iph_tot_len != udph_len + PKT_IP_HLEN && iphdr_more_frag(pack_iph) == 0 && iphdr_offset(pack_iph) == 0)) {
    	debug(LOG_ERR, "dropping udp packet; ip-len=%d != udp-len=%d + ip-hdr=20",
               (int) iph_tot_len,
               (int) udph_len);
    	return 0;
    }
  }

  if (pack_iph->protocol == PKT_IP_PROTO_TCP) {
    pack_tcph = pkt_tcphdr(pack);
    if (iph_tot_len < PKT_IP_HLEN + PKT_TCP_HLEN) {
      debug(LOG_ERR, "dropping tcp packet; ip-len=%d",
               (int) iph_tot_len);
      return 0;
    }
  }

  /*
   *  Check that the destination MAC address is our MAC or Broadcast
   */
  if ((memcmp(pack_ethh->dst, dhcp_nexthop(this), PKT_ETH_ALEN)) &&
      (memcmp(pack_ethh->dst, bmac, PKT_ETH_ALEN))) {

	  debug(LOG_ERR, "Not for our MAC or broadcast: "MAC_FMT"",
               MAC_ARG(pack_ethh->dst));

      return 0;
  }

  ourip.s_addr = this->ourip.s_addr;

  /*
   *  DHCP (BOOTPS) packets for broadcast or us specifically
   */
  is_dhcp = (((pack_iph->daddr == 0) ||
	      (pack_iph->daddr == 0xffffffff) ||
	      (pack_iph->daddr == ourip.s_addr)) &&
	     (pack_udph && (pack_udph->dst == htons(DHCP_BOOTPS))));

  if (is_dhcp) {
    debug(LOG_DEBUG, "IP: new dhcp/bootps request being processed for "MAC_FMT"",
               MAC_ARG(pack_ethh->src));
    (void) dhcp_getreq(ctx, pack, len);
    return 0;
  }


  has_ip = conn->hisip.s_addr != 0;
  if (!has_ip){
    debug(LOG_ERR, "no hisip; packet-drop");
    return 0;
  }

  authstate = conn->authstate;

  /*Jerome: 判断是否本DHCP分配过地址，没有的话先接受client使用的IP*/
  if ((!conn->hisip.s_addr) &&
      (((pack_iph->daddr != 0) &&
           (pack_iph->daddr != 0xffffffff)))) {
	  struct in_addr addr;
	  addr.s_addr = pack_iph->saddr;
    if (this->cb_request)
      if (this->cb_request(conn, &addr, 0, 0)) {
        debug(LOG_DEBUG, "dropping packet; ip not known: %s",   inet_ntoa(addr));
	return 0; // Ignore request if IP address was not allocated
      }
  }
  /*End. Jerome*/

  /*Jerome Changes procedure. Ignore request if IP address was not allocated by this DHCP*/
  struct ippoolm_t *ipm = 0;
  if(conn->peer){
	  struct _t_client *client = conn->peer;
	  if(client->uplink){
		    /*
		     *  IP Address is already known and allocated.
		     */
		    ipm = (struct ippoolm_t*) client->uplink;
	  }
  }
  if(!ipm){
	  debug(LOG_ERR, "IP: failed to allocated IP!");
	    return -1;
  }
  /*End. Jereome */

  conn->lasttime = mainclock_now();

  if (pack_iph->saddr != conn->hisip.s_addr) {
	debug(LOG_ERR, "Received packet with spoofed source!");
    /*dhcp_sendRENEW(conn, pack, len);*/
    return 0;
  }

  switch (pack_iph->protocol) {

    case PKT_IP_PROTO_UDP:

      if ((pack_iph->daddr & config->netmask.s_addr) ==
          (0xffffffff & ~config->netmask.s_addr)) {

        debug(LOG_DEBUG, "Broadcasted UDP to port %d",   ntohs(pack_udph->dst));

        return 0;
      }

      break; /* UDP */

    case PKT_IP_PROTO_TCP:

      /* Was it a request for the auto-logout service? */
      /*Jerome: no uamlogout
      if ((pack_iph->daddr == _options.uamlogout.s_addr) &&
          (pack_tcph->dst == htons(DHCP_HTTP))) {
        if (!appconn)
          appconn = dhcp_get_appconn_pkt(conn, pack_iph, 0);
        if (appconn) {
          if (appconn->s_state.authenticated) {
            terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);
            debug(LOG_DEBUG, "Dropping session due to request for auto-logout ip");
            appconn->uamexit = 1;
          }
        }
      }End, Jerome*/

      break; /* TCP */
  }

  /* Jerome: uamlias are not used
  if (_options.uamalias.s_addr &&
      pack_iph->daddr == _options.uamalias.s_addr &&
      pack_tcph) {

    do_checksum = 1;
    dhcp_uam_nat(conn, pack_ethh, pack_iph, pack_tcph, &this->uamlisten,
		 this->uamport);
  }
	End, Jerome*/

  /* Was it a DNS request? */
  if (pack_iph->protocol == PKT_IP_PROTO_UDP &&
		  pack_udph->dst == htons(DHCP_DNS)) {

	  debug(LOG_DEBUG, "A DNS request!");

	    if (!dhcp_dns(conn, pack, &len)) {
	      debug(LOG_DEBUG, "A DNS is handled in dhcp_dns()!");
	      return 0; /* Drop DNS if dhcp_dns returns 0*/
	    }

	    allowed = 1; /* Is allowed DNS */

  }

  debug(LOG_DEBUG, "DHCP received packet with authstate %d", authstate);
  switch (authstate) {

    case DHCP_AUTH_PASS:

      /* Check for post-auth proxy, otherwise pass packets unmodified */
      /*Jerome: no post DNAT for proxy*/
      //dhcp_postauthDNAT(conn, pack, len, 0, &do_checksum);
      break;

      /* Destination NAT if request to unknown web server */
    case DHCP_AUTH_DNAT:

      if (dhcp_doDNAT(conn, pack, len, 1, &do_checksum) && !allowed) {
        debug(LOG_DEBUG, "dropping packet; not nat'ed");
        return 0;
      }
      break;

      /*Jerome, no splash state
    case DHCP_AUTH_SPLASH:
      dhcp_doDNAT(conn, pack, len, 0, &do_checksum);
      break;
end, Jerome*/

    case DHCP_AUTH_DROP:
      debug(LOG_DEBUG, "dropping packet; auth-drop");

      return 0;

    default:
      debug(LOG_DEBUG, "dropping packet; unhandled auth state %d",   authstate);

      return 0;
  }

  /*done:*/


  if (do_checksum)
    chksum(pack_iph);

  if (this->cb_data_ind) {
	  srcaddr.s_addr = pack_iph->saddr;
	  dstaddr.s_addr = pack_iph->daddr;
	  debug(LOG_DEBUG, "DHCP Get packet from IP %s", inet_ntoa(srcaddr));
	  debug(LOG_DEBUG, "DHCP Get packet to IP %s", inet_ntoa(dstaddr));

    this->cb_data_ind(conn, pack, len);
  } else {
    debug(LOG_DEBUG, "Call cb_date_ind fail; packet-drop");
  }

  return 0;
}

int dhcp_receive_arp(struct dhcp_ctx *ctx, uint8_t *pack, size_t len) {
  struct dhcp_t *this = ctx->parent;

  struct dhcp_conn_t *conn = 0;
  struct in_addr reqaddr;
  struct in_addr taraddr;

  struct pkt_ethhdr_t *pack_ethh = pkt_ethhdr(pack);
  struct arp_packet_t *pack_arp = pkt_arppkt(pack);

  s_config *config = config_get_config();

  if (len < sizeofeth(pack) + sizeof(struct arp_packet_t)) {
    debug(LOG_ERR, "ARP too short %d < %d", (int) len,
           (int) (sizeofeth(pack) + sizeof(struct arp_packet_t)));
    return 0;
  }

  if (ntohs(pack_arp->hrd) != 1 ||       /* Ethernet Hardware */
      pack_arp->hln != PKT_ETH_ALEN ||   /* MAC Address Size */
      pack_arp->pln != PKT_IP_ALEN) {    /* IP Address Size */
	  	  debug(LOG_ERR, "ARP reject hrd=%d hln=%d pln=%d",
           ntohs(pack_arp->hrd), pack_arp->hln, pack_arp->pln);
    return 0;
  }

  /* Check that this is ARP request */
  if (pack_arp->op != htons(DHCP_ARP_REQUEST)) {
    debug(LOG_DEBUG, "ARP OP %d: Received other ARP than request!", ntohl(pack_arp->op));
    return 0;
  }

  /* Check that MAC address is our MAC or Broadcast */
  if ((memcmp(pack_ethh->dst, dhcp_nexthop(this), PKT_ETH_ALEN)) &&
      (memcmp(pack_ethh->dst, bmac, PKT_ETH_ALEN))) {
    debug(LOG_DEBUG, "ARP: Received ARP request for other destination!");
    return 0;
  }

  /* get sender IP address */
  memcpy(&reqaddr.s_addr, &pack_arp->spa, PKT_IP_ALEN);

  /* get target IP address */
  memcpy(&taraddr.s_addr, &pack_arp->tpa, PKT_IP_ALEN);

  /* Check to see if we know MAC address. */
  if (dhcp_hashget(this, &conn, pack_arp->sha)) {
    debug(LOG_DEBUG, "ARP: Address not found with IP: %s", inet_ntoa(reqaddr));

    /*Insert new connection of ARP for reused IP allocated during last connection*/
    if (dhcp_newconn(this, &conn, pack_arp->sha)) {
      debug(LOG_WARNING, "ARP: out of connections for allocating new access");
      return 0;
    }
  }

  dhcp_conn_set_idx(conn, ctx);

  debug(LOG_DEBUG, "ARP: "MAC_FMT" asking about target IP: %s",
           MAC_ARG(conn->hismac),
           inet_ntoa(taraddr));

/*Jerome: respond to ARP without authatation
  if (conn->authstate == DHCP_AUTH_DROP) {
    return 0;
  }
End, Jerome*/

  /* if no sender ip, then client is checking their own ip*/
  /* XXX: lookup in ippool to see if we really do know who has this */
  /* XXX: it should also ack if *we* are that ip */
  /*Jerome, RARP procedure without real response
  if (!reqaddr.s_addr) {

    debug(LOG_DEBUG, "ARP: Ignoring self-discovery: %s",
             inet_ntoa(taraddr));

     	this->cb_request(conn, &taraddr, 0, 0);

    return 0;
  }
  End, Jerome, don't know why to do it*/

  if (!memcmp(&reqaddr.s_addr, &taraddr.s_addr, 4)) {
    /* Request an IP address */
    debug(LOG_DEBUG, "ARP: Ignoring gratuitous arp with IP: %s",
             inet_ntoa(taraddr));
    return 0;
  }

  /* Is ARP request for clients own address: Ignore */
  if (!memcmp(&conn->hisip.s_addr, &taraddr.s_addr, 4)) {
    debug(LOG_DEBUG, "ARP: hisip equals target ip: %s",
             inet_ntoa(conn->hisip));
    return 0;
  }

/*Jerome: no authstating process in ARP
  if (conn->authstate == DHCP_AUTH_NONE)
    this->cb_request(conn, &reqaddr, 0, 0);
End, Jerome*/

  /* Quit. Only reply if he was allocated an address,
     unless it was a request for the gateway dhcplisten. */
  /*JeModuel changed
  if (memcmp(&config->dhcplisten.s_addr, &taraddr.s_addr, 4) &&
      !conn->hisip.s_addr) {

    debug(LOG_DEBUG, "ARP: request did not come from known client");
    return 0;
  }
*/
  /* if ourip differs from target ip */
  /* Only reply if he asked for his router address */
  /*JeModuel changed
    if (memcmp(&conn->ourip.s_addr, &taraddr.s_addr, 4) &&
    		memcmp(&config->tundevip.s_addr, &taraddr.s_addr, 4)) {

       debug(LOG_DEBUG, "ARP: Did not ask for router address: %s",
               inet_ntoa(conn->ourip));
	   debug(LOG_DEBUG, "ARP: Asked for target: %s",
               inet_ntoa(taraddr));
       return 0;
    }
*/
  if (!conn->hisip.s_addr) {
    debug(LOG_DEBUG, "ARP: request did not come from known client asking for target: %s",
    		inet_ntoa(taraddr));
    return 0;
  }
  if (memcmp(&config->dhcplisten.s_addr, &taraddr.s_addr, 4) &&
  		memcmp(&config->tundevip.s_addr, &taraddr.s_addr, 4)) {

     debug(LOG_DEBUG, "ARP: Did not ask for router address: %s or %s, but ask for target: %s",
             inet_ntoa(config->dhcplisten), inet_ntoa(config->tundevip), inet_ntoa(taraddr));
     return 0;
  }

  conn->lasttime = mainclock_now();
  dhcp_sendARP(conn, pack, len);
  return 0;
}
static
int dhcp_decaps_cb(void *pctx, struct pkt_buffer *pb) {
  struct dhcp_ctx *ctx = (struct dhcp_ctx *)pctx;
  uint16_t prot = 0;

  uint8_t *packet = pkt_buffer_head(pb);
  size_t length = pkt_buffer_length(pb);

  int min_length = sizeof(struct pkt_ethhdr_t);

  if (length < min_length) {
    debug(LOG_ERR, "dhcp_decaps_cb: bad packet length %zu", length);
    return 0;
  }

  struct pkt_ethhdr_t *ethh = pkt_ethhdr(packet);
  prot = ntohs(ethh->prot);

  debug(LOG_DEBUG, "dhcp_decaps: src="MAC_FMT" "
           "dst="MAC_FMT" prot=%.4x %d len=%zd",
           MAC_ARG(ethh->src),
           MAC_ARG(ethh->dst),
           prot, (int)prot, length);

  if (prot < 1518) {
	debug(LOG_ERR, "dhcp_decaps_cb: unhandled prot %d", prot);
    return 0;
  }

  switch (prot) {
    case PKT_ETH_PROTO_ARP:
    	debug(LOG_DEBUG, "DHCP receives ARP packet of length %d", length);
        return dhcp_receive_arp(ctx, packet, length);
      break;

    case PKT_ETH_PROTO_IP:
    	debug(LOG_DEBUG, "DHCP receives IP packet of length %d", length);
        return dhcp_receive_ip(ctx, packet, length);
      break;

    case PKT_ETH_PROTO_PPP:
    case PKT_ETH_PROTO_IPX:
    default:
        debug(LOG_ERR, "Layer2 PROT: 0x%.4x dropped", prot);
      break;
  }

  return 0;
}

/**
 * Call this function when a new IP packet has arrived. This function
 * should be part of a select() loop in the application.
 **/
int dhcp_decaps(struct dhcp_t *this, int idx) {
  ssize_t length = -1;
  net_interface *iface = 0;
  struct dhcp_ctx ctx;

#ifdef ENABLE_MULTILAN
  iface = &this->rawif[idx];
#else
  iface = &this->rawif[0];
#endif

  ctx.parent = this;
  ctx.idx = idx;

  if ((length = net_read_dispatch_eth(iface, dhcp_decaps_cb, &ctx)) < 0)
  {
	  debug(LOG_ERR, "DHCP receives unhandled packet of length %d", length);
	  return -1;
  }

  return length;
}

