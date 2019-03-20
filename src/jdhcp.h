/*
 * jdhcp.h
 *
 *  Created on: 2018年7月22日
 *      Author: jerome
 */

#ifndef SRC_JDHCP_H_
#define SRC_JDHCP_H_

#include "jnet.h"
#include "jconfig.h"

/* Option constants */
#define DHCP_OPTION_MAGIC_LEN       4


#define DHCP_OPTION_PAD             0
#define DHCP_OPTION_SUBNET_MASK     1
#define DHCP_OPTION_ROUTER_OPTION   3
#define DHCP_OPTION_DNS             6
#define DHCP_OPTION_HOSTNAME       12
#define DHCP_OPTION_DOMAIN_NAME    15
#define DHCP_OPTION_INTERFACE_MTU  26
#define DHCP_OPTION_STATIC_ROUTES  33
#define DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION 43
#define DHCP_OPTION_REQUESTED_IP   50
#define DHCP_OPTION_LEASE_TIME     51
#define DHCP_OPTION_MESSAGE_TYPE   53
#define DHCP_OPTION_SERVER_ID      54
#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55
#define DHCP_OPTION_VENDOR_CLASS_IDENTIFIER 60
#define DHCP_OPTION_CLIENT_IDENTIFIER 61
#define DHCP_OPTION_CLIENT_FQDN    81
#define DHCP_OPTION_82    82
#define DHCP_OPTION_CAPTIVE_PORTAL_URI 160

/* DHCP states */
#define DNPROT_NULL       1
#define DNPROT_DHCP_NONE  2
#define DNPROT_DHCP_DONE  3

/* Authentication states */
#define DHCP_AUTH_NONE        0
#define DHCP_AUTH_DROP        1
#define DHCP_AUTH_PASS        2
#define DHCP_AUTH_DNAT        5

#define DHCP_DNAT_MAX       128


#define DHCP_ARP_REQUEST 1
#define DHCP_ARP_REPLY   2

/* BOOTP Message Types */
#define DHCP_BOOTREQUEST  1
#define DHCP_BOOTREPLY    2

/* DHCP Message Types */
#define DHCPDISCOVER      1
#define DHCPOFFER         2
#define DHCPREQUEST       3
#define DHCPDECLINE       4
#define DHCPACK           5
#define DHCPNAK           6
#define DHCPRELEASE       7
#define DHCPINFORM        8
#define DHCPFORCERENEW    9

/* UDP Ports */
#define DHCP_BOOTPS 67
#define DHCP_BOOTPC 68
#define DHCP_DNS    53
#define DHCP_MDNS   5353

/* TCP Ports */
#define DHCP_HTTP   80
#define DHCP_HTTPS 443

#define DHCP_OPTION_END           255

#define DHCP_ARP_REQUEST 1
#define DHCP_ARP_REPLY   2

#define DHCP_DNS_HLEN  12

#define CHILLI_DHCP_OFFER    1
#define CHILLI_DHCP_ACK      2
#define CHILLI_DHCP_NAK      3
#define CHILLI_DHCP_RELAY    4
#define CHILLI_DHCP_PROXY    5

struct ippoolm_t;                /* Forward declaration */

struct ippool_t {
  int dynsize;                   /* Total number of dynamic addresses */
  int statsize;                  /* Total number of static addresses */
  int listsize;                  /* Total number of addresses */
  int allowdyn;                  /* Allow dynamic IP address allocation */
  int allowstat;                 /* Allow static IP address allocation */
  struct in_addr stataddr;       /* Static address range network address */
  struct in_addr statmask;       /* Static address range network mask */
  struct ippoolm_t *member;      /* Listsize array of members */
  int hashsize;                  /* Size of hash table */
  int hashlog;                   /* Log2 size of hash table */
  int hashmask;                  /* Bitmask for calculating hash */
  struct ippoolm_t **hash;       /* Hashsize array of pointer to member */
  struct ippoolm_t *firstdyn;    /* Pointer to first free dynamic member */
  struct ippoolm_t *lastdyn;     /* Pointer to last free dynamic member */
  struct ippoolm_t *firststat;   /* Pointer to first free static member */
  struct ippoolm_t *laststat;    /* Pointer to last free static member */
};

struct ippoolm_t {
  struct in_addr addr;           /* IP address of this member */
  char in_use;                   /* 0=available; 1= used */
  char is_static;                /* 0= dynamic; 1 = static */
  struct ippoolm_t *nexthash;    /* Linked list part of hash table */
  struct ippoolm_t *prev, *next; /* Linked list of free dynamic or static */
  void *peer;                    /* Pointer to peer protocol handler */
};

struct dhcp_nat_t {
  uint8_t mac[PKT_ETH_ALEN];
  uint32_t dst_ip;
  uint16_t dst_port;
  uint32_t src_ip;
  uint16_t src_port;
};

struct dhcp_conn_t {
  struct dhcp_conn_t *nexthash; /* Linked list part of hash table */
  struct dhcp_conn_t *next;     /* Next in linked list. 0: Last */
  struct dhcp_conn_t *prev;     /* Previous in linked list. 0: First */
  struct dhcp_t *parent;        /* Parent of all connections */
  void *peer;                   /* Peer protocol handler */

  uint8_t inuse:1;             /* Free = 0; Inuse = 1 */
  uint8_t noc2c:1;             /* Prevent client to client access using /32 subnets */
  uint8_t is_reserved:1;       /* If this is a static/reserved mapping */
  uint8_t padding:5;

  time_t lasttime;             /* Last time we heard anything from client */
  uint8_t hismac[PKT_ETH_ALEN];/* Peer's MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in_addr hismask;      /* Client Network Mask */
  struct in_addr dns1;         /* Client DNS address */
  struct in_addr dns2;         /* Client DNS address */
//Jerome  char domain[DHCP_DOMAIN_LEN];/* Domain name to use for DNS lookups */
  int authstate;               /* 0: Unauthenticated, 1: Authenticated */
  uint8_t unauth_cp;           /* Unauthenticated codepoint */
  uint8_t auth_cp;             /* Authenticated codepoint */
  int nextdnat;                /* Next location to use for DNAT */
  uint32_t dnatdns;            /* Destination NAT for dns mapping */
  struct dhcp_nat_t dnat[DHCP_DNAT_MAX]; /* Destination NAT */
  uint16_t mtu;                /* Maximum transfer unit */

  struct in_addr migrateip;    /* Client IP address to migrate to */
  /*time_t last_nak;*/

#ifdef ENABLE_MULTILAN
#define dhcp_conn_idx(x)       ((x)->lanidx)
#define dhcp_conn_set_idx(x,c) ((x)->lanidx = (c)->idx)
  int lanidx;
#else
#define dhcp_conn_idx(x) 0
#define dhcp_conn_set_idx(x,c)
#endif
};


/* ***********************************************************
 * Information storage for each dhcp instance
 *
 * Normally each instance of the application corresponds to
 * one instance of a dhcp instance.
 *
 *************************************************************/

struct dhcp_t {

  /* network interfaces */
  struct _net_interface rawif[MAX_RAWIF];

//  int numconn;          /* Maximum number of connections */

  int debug;            /* Set to print debug messages */

  struct in_addr ourip; /* IP address to listen to */
  int mtu;              /* Maximum transfer unit */

  uint32_t lease;       /* Seconds before reneval */

  int usemac;           /* Use given mac address */

  int promisc;          /* Set interface in promisc mode */

  struct in_addr uamlisten; /* IP address to redirect HTTP requests to */
  uint16_t uamport;     /* TCP port to redirect HTTP requests to */

  //struct in_addr *authip; /* IP address of authentication server */
  //int authiplen;        /* Number of authentication server IP addresses */

  int anydns;           /* Allow any dns server */

  int relayfd;          /* DHCP relay socket, 0 if not relaying */

  /* Connection management */
  struct dhcp_conn_t *firstfreeconn; /* First free in linked list */
  struct dhcp_conn_t *lastfreeconn;  /* Last free in linked list */
  struct dhcp_conn_t *firstusedconn; /* First used in linked list */
  struct dhcp_conn_t *lastusedconn;  /* Last used in linked list */

  /* Hash related parameters */
  int hashsize;                 /* Size of hash table */
  int hashlog;                  /* Log2 size of hash table */
  int hashmask;                 /* Bitmask for calculating hash */
  struct dhcp_conn_t **hash;    /* Hashsize array of pointer to member */

//  pass_through pass_throughs[MAX_PASS_THROUGHS];
//  uint32_t num_pass_throughs;

  /* Call back functions */
  int (*cb_data_ind) (struct dhcp_conn_t *conn, uint8_t *pack, size_t len);
  int (*cb_eap_ind)  (struct dhcp_conn_t *conn, uint8_t *pack, size_t len);
  int (*cb_request) (struct dhcp_conn_t *conn, struct in_addr *addr,
                     uint8_t *pack, size_t len);
  int (*cb_connect) (struct dhcp_conn_t *conn);
  int (*cb_disconnect) (struct dhcp_conn_t *conn, int term_cause);
};

int parse_ip_aton(struct in_addr *addr, struct in_addr *mask, char *pool);
int ippool_getip(struct ippool_t *this, struct ippoolm_t **member, struct in_addr *addr);
int ippool_new(struct ippool_t **this, char *dyn, int start, int end);
int ippool_free(struct ippool_t *this);

int dhcp_data_req(struct dhcp_conn_t *conn, struct pkt_buffer *pb, int ethhdr);
int dhcp_creat(struct dhcp_t **dhcp, char *interface, struct in_addr *listen,
	     struct in_addr *uamlisten, uint16_t uamport);
int dhcp_gettag(struct dhcp_packet_t *pack, size_t length, struct dhcp_tag_t **tag, uint8_t tagtype);

uint8_t * dhcp_nexthop(struct dhcp_t *this);

int dhcp_set_cb_data_ind(struct dhcp_t *this,
                         int (*cb_data_ind) (struct dhcp_conn_t *conn,
                                             uint8_t *pack, size_t len));

int dhcp_set_cb_request(struct dhcp_t *this,
                        int (*cb_request) (struct dhcp_conn_t *conn,
                                           struct in_addr *addr,
                                           uint8_t *pack, size_t len));

int dhcp_set_cb_disconnect(struct dhcp_t *this,
                           int (*cb_disconnect) (struct dhcp_conn_t *conn,
                                                 int term_cause));

int dhcp_set_cb_connect(struct dhcp_t *this,
                        int (*cb_connect) (struct dhcp_conn_t *conn));

int cb_dhcp_request(struct dhcp_conn_t *conn, struct in_addr *addr, uint8_t *dhcp_pkt, size_t dhcp_len);
int cb_dhcp_connect(struct dhcp_conn_t *conn);
int cb_dhcp_disconnect(struct dhcp_conn_t *conn, int term_cause);
int cb_dhcp_data_ind(struct dhcp_conn_t *conn, uint8_t *pack, size_t len);

int dhcp_decaps(struct dhcp_t *this, int idx);
int dhcp_relay_decaps(struct dhcp_t *this, int idx);
void dhcp_free(struct dhcp_t *dhcp);
int dhcp_timeout(struct dhcp_t *this);
#endif /* SRC_JDHCP_H_ */
