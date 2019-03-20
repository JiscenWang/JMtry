/*
 * jmodule.c
 *
 *  Created on: 2018年7月22日
 *      Author: jerome
 */

#include <sys/types.h>
#include <string.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#include "jmodule.h"
#include "jnet.h"
#include "jdhcp.h"
#include "safe.h"
#include "jhttp.h"

#include "debug.h"
#include "jconfig.h"
#include "httpd.h"
#include "client_list.h"
#include "jgateway.h"

extern struct ippool_t *ippool;
extern struct timespec mainclock;

struct tundecap {
  struct tun_t *this;
  int idx;
};

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}


time_t mainclock_rt() {
  time_t rt = 0;
  if (time(&rt) == (time_t)-1) {
    debug(LOG_ERR, "%s: time()", strerror(errno));
  }
  return rt;
}

time_t mainclock_tick() {
  if (time(&mainclock.tv_sec) == (time_t)-1) {
    debug(LOG_ERR, "%s: time()", strerror(errno));
  }
  return mainclock.tv_sec;
}


int mainclock_diff(time_t past) {
  return (int) (mainclock.tv_sec - past);
}

int tuntap_interface(struct _net_interface *netif) {
  struct ifreq ifr;
  s_config *config = config_get_config();

  memset(netif, 0, sizeof(*netif));

  /*  memcpy(netif->gwaddr, _options.nexthop, PKT_ETH_ALEN);*/

  /* Open the actual tun device */
  if ((netif->fd = open("/dev/net/tun", O_RDWR)) < 0) {
    debug(LOG_ERR, "%s: open() failed", strerror(errno));
    return -1;
  }

  ndelay_on(netif->fd);
  coe(netif->fd);

  /* Set device flags. For some weird reason this is also the method
     used to obtain the network interface name */

  memset(&ifr, 0, sizeof(ifr));

  /* Tun device, no packet info */
  ifr.ifr_flags = (IFF_TUN) | IFF_NO_PI;

  if (config->tundevname && *config->tundevname && strcmp(config->tundevname, "tap") && strcmp(config->tundevname, "tun"))
	  strlcpy(ifr.ifr_name, config->tundevname, IFNAMSIZ);

  if (ioctl(netif->fd, TUNSETIFF, (void *) &ifr) < 0) {
    debug(LOG_ERR, "%s: ioctl() failed", strerror(errno));
    close(netif->fd);
    return -1;
  }

  strlcpy(netif->devname, ifr.ifr_name, IFNAMSIZ);

  ioctl(netif->fd, TUNSETNOCSUM, 1); /* Disable checksums */

  return 0;
}

int tun_new(struct tun_t **ptun) {
  struct tun_t *tun;
  if (!(tun = *ptun = calloc(1, sizeof(struct tun_t)))) {
    debug(LOG_ERR, "%s: calloc() failed", strerror(errno));
    return -1;
  }

  tuntap_interface(&tun->_tuntap);

  return 0;
}

int tun_setaddr(struct tun_t *this, struct in_addr *addr, struct in_addr *dstaddr, struct in_addr *netmask) {
  net_set_address(&tuntap(this), addr, dstaddr, netmask);

  return 0;
}

int tun_set_cb_ind(struct tun_t *this,
		   int (*cb_ind) (struct tun_t *tun, struct pkt_buffer *pb, int idx)) {
  this->cb_ind = cb_ind;
  return 0;
}


/*
 * Tun callbacks
 *
 * Called from the tun_decaps function. This method is passed either
 * a Ethernet frame or an IP packet.
 */

int cb_tun_ind(struct tun_t *tun, struct pkt_buffer *pb, int idx) {
  struct in_addr dst;
  struct ippoolm_t *ipm;
  t_client *client = 0;
  struct pkt_udphdr_t *udph = 0;
  struct pkt_ipphdr_t *ipph;

  uint8_t *pack = pkt_buffer_head(pb);
  size_t len = pkt_buffer_length(pb);

  int ethhdr = (tun(tun, idx).flags & NET_ETHHDR) != 0;
  size_t ip_len = len;

  ipph = (struct pkt_ipphdr_t *)pack;

  size_t hlen = (ipph->version_ihl & 0x0f) << 2;
  if (ntohs(ipph->tot_len) > ip_len || hlen > ip_len) {
	  debug(LOG_DEBUG, "invalid IP packet %d / %zu",
             ntohs(ipph->tot_len),
             len);
    return 0;
  }

  /*
   *  Filter out unsupported / unhandled protocols,
   *  and check some basic length sanity.
   */
  switch(ipph->protocol) {
    case PKT_IP_PROTO_GRE:
    case PKT_IP_PROTO_TCP:
    case PKT_IP_PROTO_ICMP:
    case PKT_IP_PROTO_ESP:
    case PKT_IP_PROTO_AH:
      break;
    case PKT_IP_PROTO_UDP:
      {
        /*
         * Only the first IP fragment has the UDP header.
         */
        if (iphdr_offset((struct pkt_iphdr_t*)ipph) == 0) {
          udph = (struct pkt_udphdr_t *)(((void *)ipph) + hlen);
        }
        if (udph && !iphdr_more_frag((struct pkt_iphdr_t*)ipph) && (ntohs(udph->len) > ip_len)) {

        	debug(LOG_DEBUG, "invalid UDP packet %d / %d / %zu",
                   ntohs(ipph->tot_len),
                   udph ? ntohs(udph->len) : -1, ip_len);
          return 0;
        }
      }
      break;
    default:
       	debug(LOG_DEBUG, "dropping unhandled packet: %x",   ipph->protocol);
       return 0;
  }

  dst.s_addr = ipph->daddr;

  debug(LOG_DEBUG, "TUN sending packet to : %s", inet_ntoa(dst));

  if (ippool_getip(ippool, &ipm, &dst)) {

    /*
     *  TODO: If within statip range, allow the packet through (?)
     */

		debug(LOG_DEBUG, "dropping packet with unknown destination: %s",   inet_ntoa(dst));

    return 0;
  }

  client = (t_client *)ipm->peer;

  if (client == NULL || client->dnlink == NULL) {
    debug(LOG_ERR, "No %s protocol defined for %s",
           client ? "dnlink" : "peer", inet_ntoa(dst));
    return 0;
  }

  struct dhcp_conn_t *conn = (struct dhcp_conn_t *)client->dnlink;

  /*Jerome: J-Module modified. Not judged by client's authstate, but by DHCP conn's

  switch (conn->authstate) {
    case DHCP_AUTH_NONE:
    case DHCP_AUTH_DROP:
    case DHCP_AUTH_DNAT:
		debug(LOG_DEBUG, "Dropping...");
      break;

    case DHCP_AUTH_PASS:
      dhcp_data_req((struct dhcp_conn_t *)client->dnlink, pb, ethhdr);
      break;

    default:
      debug(LOG_ERR, "Unknown downlink protocol: %d", conn->authstate);
      break;
  }
End Jerome*/
  dhcp_data_req((struct dhcp_conn_t *)client->dnlink, pb, ethhdr);
  return 0;

}


/*
  static uint32_t dnatip[1024];
  static uint16_t dnatport[1024];
*/

int tun_write(struct tun_t *tun, uint8_t *pack, size_t len, int idx) {
	  return safe_write(tun(tun, idx).fd, pack, len);
}

int tun_encaps(struct tun_t *tun, uint8_t *pack, size_t len, int idx) {
  int result;
/*Jerome: deactivated
  if (_options.tcpwin)
    pkt_shape_tcpwin(pkt_iphdr(pack), _options.tcpwin);

  if (_options.tcpmss)
    pkt_shape_tcpmss(pack, &len);
End. Jerome*/

  /*Jerome: deactivated*/
//  if (tun(tun, idx).flags & NET_ETHHDR) {
//    uint8_t *gwaddr = _options.nexthop; /*tun(tun, idx).gwaddr;*/
//    struct pkt_ethhdr_t *ethh = (struct pkt_ethhdr_t *)pack;
    /* memcpy(ethh->src, tun(tun, idx).hwaddr, PKT_ETH_ALEN); */

    /*
     * TODO: When using ieee8021q, the vlan tag has to be stripped
     * off for the non-vlan WAN.
     */
//    if (gwaddr[0] == 0 && gwaddr[1] == 0 && gwaddr[2] == 0 &&
//	gwaddr[3] == 0 && gwaddr[4] == 0 && gwaddr[5] == 0) {
      /*
       *  If there isn't a 'nexthop' (gwaddr) for the interface,
       *  default to the tap interface's MAC instead, so that the kernel
       *  will route it.
       */

    size_t ethlen = sizeofeth(pack);
    pack += ethlen;
    len  -= ethlen;

  debug(LOG_DEBUG, "tun_encaps(%s) len=%zd", tun(tun,idx).devname, len);

  result = tun_write(tun, pack, len, idx);

  debug(LOG_ERR, "%s: tun_write(%zu) = %d", strerror(errno), len, result);

  return result;
}


static int tun_decaps_cb(void *ctx, struct pkt_buffer *pb) {
  struct tundecap *c = (struct tundecap *)ctx;
  struct pkt_iphdr_t *iph;
  int ethsize = 0;

  char ethhdr = 0;

  size_t length = pkt_buffer_length(pb);
  uint8_t *packet = pkt_buffer_head(pb);

  s_config *config = config_get_config();
  struct in_addr addr;

  if (c->idx) ethhdr = 0;

  if (length < PKT_IP_HLEN){
		debug(LOG_DEBUG, "tun_decaps invalid length < PKT_IP_HLEN");
	    return -1;
  }

  if (ethhdr) {

    if (length < PKT_IP_HLEN + PKT_ETH_HLEN){
		debug(LOG_DEBUG, "tun_decaps invalid length < PKT_IP_HLEN");
	    return -1;
    }

    ethsize = PKT_ETH_HLEN;
    iph = pkt_iphdr(packet);

  } else {

    iph = (struct pkt_iphdr_t *)packet;

  }

  addr.s_addr = iph->saddr;
  debug(LOG_DEBUG, "tun_decaps(len=%zd) from IP %s", length, inet_ntoa(addr));
  addr.s_addr = iph->daddr;
  debug(LOG_DEBUG, "tun_decaps send to IP %s", inet_ntoa(addr));

  if (c->idx > 0) {
	if ((iph->daddr & config->netmask.s_addr) != config->tundevip.s_addr) {
      addr.s_addr = iph->daddr;
      debug(LOG_DEBUG, "pkt not for our network %s", inet_ntoa(addr));
      return -1;
    }
  }

    if (iph->version_ihl != PKT_IP_VER_HLEN) {
      debug(LOG_DEBUG, "dropping non-IPv4");
      return -1;
    }

    if ((int)ntohs(iph->tot_len) + ethsize > length) {
      debug(LOG_DEBUG, "dropping ip packet; ip-len=%d + eth-hdr=%d > read-len=%d",
               (int)ntohs(iph->tot_len),
               ethsize, (int)length);
      return -1;
    }


  return c->this->cb_ind(c->this, pb, c->idx);
}

int tun_decaps(struct tun_t *this, int idx) {

  ssize_t length;
  struct tundecap c;

  c.this = this;
  c.idx = idx;

  if (idx > 0)
    length = net_read_dispatch_eth(&tun(this, idx), tun_decaps_cb, &c);
  else
    length = net_read_dispatch(&tun(this, idx), tun_decaps_cb, &c);

  if (length < 0)
    return -1;

  return length;
}


int tun_free(struct tun_t *tun) {

  tun_close(tun);
  free(tun);
  return 0;
}

/*Adapter callback func of mainloop select for hpptd API func of httpdGetConnection*/
int jmodulehttpconnect(httpd *server, int index){
    request *r;
    void **params;
    int result;
    pthread_t tid;

    r = httpdGetConnection(server, NULL);

    /* We can't convert this to a switch because there might be
     * values that are not -1, 0 or 1. */
	/*Jerome: seems will not happen to be -1*/
    if (server->lastError == -1) {
        /* Interrupted system call */
        if (NULL != r) {
            httpdEndRequest(r);
        }
    } else if (server->lastError < -1) {
        /*
         * FIXME
         * An error occurred - should we abort?
         * reboot the device ?
         */
        debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.");
        termination_handler(0);
    } else if (r != NULL) {
        /*
         * We got a connection
         *
         * We should create another thread
         */
        debug(LOG_INFO, "Received connection from %s, spawning worker thread", r->clientAddr);
        /* The void**'s are a simulation of the normal C
         * function calling sequence. */
        params = safe_malloc(2 * sizeof(void *));
        *params = server;
        *(params + 1) = r;

        result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid);
    } else {
        /* webserver->lastError should be 2 */
        /* XXX We failed an ACL.... No handling because
         * we don't set any... */
    }

    return 0;
}
