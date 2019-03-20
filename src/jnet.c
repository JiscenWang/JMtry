/*
 * net.c
 *
 *  Created on: 2018年7月21日
 *      Author: jerome
 */

#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>

#include "jnet.h"
#include "safe.h"
#include "jconfig.h"
#include "jdhcp.h"
#include "jmodule.h"

#include "debug.h"

#define cksum_wrap(c) (c=(c>>16)+(c&0xffff),(~(c+(c>>16))&0xffff))

static uint32_t default_sndbuf = 0;
static uint32_t default_rcvbuf = 0;

struct select_ctx *sctx;

int net_open_eth(net_interface *netif);
int net_init(net_interface *netif, char *ifname,
	     uint16_t protocol, int promisc);


inline void copy_mac6(uint8_t *dst, uint8_t *src) {
  dst[0]=src[0]; dst[1]=src[1];
  dst[2]=src[2]; dst[3]=src[3];
  dst[4]=src[4]; dst[5]=src[5];
}

uint32_t
in_cksum(uint16_t *addr, int len) {
  int         nleft = len;
  uint32_t    sum = 0;
  uint16_t  * w = addr;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    uint16_t ans = 0;
    *(unsigned char *)(&ans) = *(unsigned char *)w ;
    sum += ans;
  }

  return(sum);
}

int chksum(struct pkt_iphdr_t *iph) {
  uint16_t hlen;
  uint32_t sum;
  uint16_t len;

  /* Only IPv4 currently */
  if ((iph->version_ihl & 0xf0) != 0x40)
    return -1;

  /* Header length */
  hlen = iph->version_ihl & 0x0f;
  hlen <<= 2;

  len = ntohs(iph->tot_len);

  /* XXX: redundant */
  if (hlen < PKT_IP_HLEN)
    return -1;

#if(PKT_BUFFER < 65535)
  if (len > PKT_BUFFER)
    return -1; /* too long? */
#endif
  if (len < hlen)
    return -1; /* too short? */

  switch(iph->protocol) {
    case PKT_IP_PROTO_TCP:
      {
        struct pkt_tcphdr_t *tcph =
            (struct pkt_tcphdr_t *)(((void *)iph) + hlen);

        len -= hlen; /* length of tcp header + data */

        tcph->check = 0;
        sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
        sum += ntohs(IPPROTO_TCP + len);
        sum += in_cksum((uint16_t *)tcph, len);
        tcph->check = cksum_wrap(sum);
      }
      break;

    case PKT_IP_PROTO_UDP:
      {
        struct pkt_udphdr_t *udph =
            (struct pkt_udphdr_t *)(((void *)iph) + hlen);
        uint16_t udplen = ntohs(udph->len);

        if (udplen > len)
          return -1;

        udph->check = 0;
        sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
        sum += ntohs(IPPROTO_UDP + udplen);
        sum += in_cksum((uint16_t *)udph, udplen);
        udph->check = cksum_wrap(sum);
      }
      break;

    case PKT_IP_PROTO_ICMP:
      {
        struct pkt_icmphdr_t *icmph =
            (struct pkt_icmphdr_t *)(((void *)iph) + hlen);
        len -= hlen;
        icmph->check = 0;
        sum = in_cksum((uint16_t *)icmph, len);
        icmph->check = cksum_wrap(sum);
      }
      break;
  }

  iph->check = 0;
  sum = in_cksum((uint16_t *)iph, hlen);
  iph->check = cksum_wrap(sum);

  return 0;
}


int dev_get_flags(char const *dev, int *flags) {
  struct ifreq ifr;
  int fd;

  memset(&ifr, 0, sizeof(ifr));
  strlcpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    debug(LOG_ERR, "%s: socket() failed", strerror(errno));
    return -1;
  }

  if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
	    debug(LOG_ERR, "%s: ioctl(SIOCSIFFLAGS) failed on %s", strerror(errno), dev);
    close(fd);
    return -1;
  }

  close(fd);

  *flags = ifr.ifr_flags;

  return 0;
}

int dev_set_flags(char const *dev, int flags) {
  struct ifreq ifr;
  int fd;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;
  strlcpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    debug(LOG_ERR, "%s: socket() failed", strerror(errno));
    return -1;
  }

  if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
    debug(LOG_ERR, "%s: ioctl(SIOCSIFFLAGS) failed", strerror(errno));
    close(fd);
    return -1;
  }

  close(fd);

  return 0;
}


int ndelay_on (int fd) {
  register int got = fcntl(fd, F_GETFL);
  return (got == -1) ? -1 : fcntl(fd, F_SETFL, got | O_NONBLOCK);
}

int coe (int fd) {
  register int flags = fcntl(fd, F_GETFD, 0);
  if (flags == -1) return -1;
  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}


int net_select_prepare(select_ctx *sctx) {

  fd_zero(&sctx->rfds);
  fd_zero(&sctx->wfds);
  fd_zero(&sctx->efds);
  {
    int i;
    for (i=0; i < sctx->count; i++) {
      if (sctx->desc[i].fd) {
	if (sctx->desc[i].evts & SELECT_READ) {
	  fd_set(sctx->desc[i].fd, &sctx->rfds);
	  fd_set(sctx->desc[i].fd, &sctx->efds);
	}
	if (sctx->desc[i].evts & SELECT_WRITE)
	  fd_set(sctx->desc[i].fd, &sctx->wfds);
      } else if (sctx->desc[i].evts & SELECT_RESET) {
	sctx->desc[i].cb(&sctx->desc[i], -1);
      }
    }
  }

  return 0;
}

int net_select_reg(select_ctx *sctx, int fd, char evts,
		   select_callback cb, void *ctx, int idx) {
  if (!evts) return -3;
  if (fd <= 0) return -2;
  if (sctx->count == MAX_SELECT) return -1;
  sctx->desc[sctx->count].fd = fd;
  sctx->desc[sctx->count].cb = cb;
  sctx->desc[sctx->count].ctx = ctx;
  sctx->desc[sctx->count].idx = idx;
  sctx->desc[sctx->count].evts = evts;

  if (fd > sctx->maxfd) sctx->maxfd = fd;

  sctx->count++;
  debug(LOG_DEBUG, "net select count: %d", sctx->count);
  return 0;
}

ssize_t net_write_eth(net_interface *netif, void *d, size_t dlen, struct sockaddr_ll *dest) {
  int fd = netif->fd;
  ssize_t len;

  len = safe_sendto(fd, d, dlen, 0,
		    (struct sockaddr *)dest,
		    sizeof(struct sockaddr_ll));

  if (len < 0) {
    switch (errno) {
      case EWOULDBLOCK:
        debug(LOG_ERR, "%s: packet dropped due to congestion", strerror(errno));
        break;
    }

    debug(LOG_ERR, "%s: net_write_eth(fd=%d, len=%zu) failed", strerror(errno), netif->fd, dlen);
    return -1;
  }

  return len;
}

int net_select(select_ctx *sctx) {
  int status;

  do {

    sctx->idleTime.tv_sec = 1;
    sctx->idleTime.tv_usec = 0;

    status = select(sctx->maxfd + 1,
		    &sctx->rfds,
		    &sctx->wfds,
		    &sctx->efds,
		    &sctx->idleTime);

    if (status == -1) net_select_prepare(sctx); /* reset */

  } while (status == -1 && errno == EINTR);
  return status;
}


int net_run_selected(select_ctx *sctx, int status) {
  int i;

  for (i=0; i < sctx->count; i++) {
    if (sctx->desc[i].fd) {
      char has_read = fd_isset(sctx->desc[i].fd, &sctx->rfds);
      if (has_read) {
	sctx->desc[i].cb(sctx->desc[i].ctx, sctx->desc[i].idx);
      }
    }
  }

  return 0;
}

int dev_set_address(char const *devname, struct in_addr *address,
		    struct in_addr *dstaddr, struct in_addr *netmask) {
  struct ifreq ifr;

  int fd;

  memset(&ifr, 0, sizeof (ifr));

  /* Create a channel to the NET kernel. */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    debug(LOG_ERR, "%s: socket() failed", strerror(errno));
    return -1;
  }

  strlcpy(ifr.ifr_name, devname, IFNAMSIZ);
  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;
  ifr.ifr_name[IFNAMSIZ-1] = 0; /* Make sure to terminate */

  if (address) { /* Set the interface address */
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = address->s_addr;
    if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
      if (errno != EEXIST) {
	debug(LOG_ERR, "%s: ioctl(SIOCSIFADDR) failed", strerror(errno));
      }
      else {
	debug(LOG_WARNING, "%d ioctl(SIOCSIFADDR): Address already exists",
               errno);
      }
      close(fd);
      return -1;
    }
  }

  if (dstaddr) { /* Set the destination address */
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr = dstaddr->s_addr;
    if (ioctl(fd, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0) {
      debug(LOG_ERR, "%s: ioctl(SIOCSIFDSTADDR) failed", strerror(errno));
      close(fd);
      return -1;
    }
  }

  if (netmask) { /* Set the netmask */
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr =  netmask->s_addr;
    if (ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
      debug(LOG_ERR, "%s: ioctl(SIOCSIFNETMASK) failed", strerror(errno));
      close(fd);
      return -1;
    }
  }

  close(fd);

  return dev_set_flags(devname, IFF_UP | IFF_RUNNING);
}


static int net_setsockopt(int s, int l, int op, void *v, socklen_t vl) {

  if (setsockopt(s, l, op, v, vl) < 0) {
    debug(LOG_ERR, "%d setsockopt(s=%d, level=%d, optname=%d, optlen=%d) failed",
           errno, s, l, op, (int) vl);
    return -1;
  }

  return 0;
}

int net_set_address(net_interface *netif, struct in_addr *address,
		    struct in_addr *dstaddr, struct in_addr *netmask) {
  netif->address.s_addr = address->s_addr;
  netif->gateway.s_addr = dstaddr->s_addr;
  netif->netmask.s_addr = netmask->s_addr;

  return dev_set_address(netif->devname, address, dstaddr, netmask);
}


int net_close(net_interface *netif) {
  if (netif->fd) close(netif->fd);
  netif->fd = 0;
  return 0;
}

int net_open(net_interface *netif) {
  net_close(netif);
  net_gflags(netif);

  if (( !(netif->devflags & IFF_UP) || !(netif->devflags & IFF_RUNNING) )) {
    struct in_addr noaddr;
    net_sflags(netif, netif->devflags | IFF_NOARP);
    memset(&noaddr, 0, sizeof(noaddr));
    debug(LOG_DEBUG, "removing ip address from %s", netif->devname);

    dev_set_address(netif->devname, &noaddr, NULL, NULL);
  }

  return net_open_eth(netif);
}

int net_init(net_interface *netif, char *ifname,
	     uint16_t protocol, int promisc) {

  if (ifname) {
	    memset(netif, 0, sizeof(net_interface));
    strlcpy(netif->devname, ifname, IFNAMSIZ);
  }

  netif->protocol = protocol;

  if (promisc) {
    netif->flags |= NET_PROMISC;
  }

  return net_open(netif);
}


/**
 * Opens an Ethernet interface. As an option the interface can be set in
 * promisc mode. If not null macaddr and ifindex are filled with the
 * interface mac address and index
 **/
int net_open_eth(net_interface *netif) {
  struct ifreq ifr;
  struct sockaddr_ll sa;
  int option;

  memset(&ifr, 0, sizeof(ifr));

  /* Create socket */
  if ((netif->fd = socket(PF_PACKET,
			  /*XXX netif->idx ? SOCK_DGRAM : */SOCK_RAW,
			  htons(netif->protocol))) < 0) {
    if (errno == EPERM) {
      debug(LOG_ERR, "%s: Cannot create raw socket. Must be root.", strerror(errno));
    }

    debug(LOG_ERR, "%d socket(domain=%d, type=%d, protocol=%d) failed",
           errno, PF_PACKET, SOCK_RAW, netif->protocol);

    return -1;
  }

    /* Let's make this non-blocking */
    ndelay_on(netif->fd);
    coe(netif->fd);

    option = 1;
    if (net_setsockopt(netif->fd, SOL_SOCKET, TCP_NODELAY,
		       &option, sizeof(option)) < 0)
      return -1;

    /* Enable reception and transmission of broadcast frames */
    option = 1;
    if (net_setsockopt(netif->fd, SOL_SOCKET, SO_BROADCAST,
		       &option, sizeof(option)) < 0)
      return -1;

    /*Jerome TBD send and receive buffer
    if (_options.sndbuf > 0) {
      option = _options.sndbuf;
      net_setsockopt(netif->fd, SOL_SOCKET, SO_SNDBUF, &option, sizeof(option));
    }

    if (_options.rcvbuf > 0) {
      option = _options.rcvbuf;
      net_setsockopt(netif->fd, SOL_SOCKET, SO_RCVBUF, &option, sizeof(option));
    }

      socklen_t len;
      len = sizeof(default_sndbuf);
      getsockopt(netif->fd, SOL_SOCKET, SO_SNDBUF, &default_sndbuf, &len);
      debug(LOG_DEBUG, "Net SNDBUF %d", default_sndbuf);

      len = sizeof(default_rcvbuf);
      getsockopt(netif->fd, SOL_SOCKET, SO_RCVBUF, &default_rcvbuf, &len);
      debug(LOG_DEBUG, "Net RCVBUF %d", default_rcvbuf);
*/
  /* Get the MAC address of our interface */
  strlcpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFHWADDR, (caddr_t)&ifr) < 0) {
    debug(LOG_ERR, "%s: ioctl(d=%d, request=%d) failed", strerror(errno), netif->fd, SIOCGIFHWADDR);
    return -1;
  }

  if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
    netif->flags |= NET_ETHHDR;
    if ((netif->flags & NET_USEMAC) == 0) {
      memcpy(netif->hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
    } else{
    	/*Jerome, not use mac
    	if (_options.dhcpmacset) {
      strlcpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
      memcpy(ifr.ifr_hwaddr.sa_data, netif->hwaddr, PKT_ETH_ALEN);
      if (ioctl(netif->fd, SIOCSIFHWADDR, (caddr_t)&ifr) < 0) {
	debug(LOG_ERR, "%s: ioctl(d=%d, request=%d) failed", strerror(errno), netif->fd, SIOCSIFHWADDR);
	return -1;
      }
    }
    */
        debug(LOG_ERR, "%s: Mac address set (d=%d, request=%d) failed", strerror(errno), netif->fd, SIOCGIFHWADDR);
        return -1;
    	}

  }

  if (netif->hwaddr[0] & 0x01) {
    debug(LOG_ERR, "Ethernet has broadcast or multicast address: %.16s",
           netif->devname);
  }

  /* Get the current interface address, network, and any destination address */
  /* Get the IP address of our interface */

  /* Verify that MTU = ETH_DATA_LEN */
  strlcpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
    debug(LOG_ERR, "%s: ioctl(d=%d, request=%d) failed", strerror(errno), netif->fd, SIOCGIFMTU);
    return -1;
  }
  if (ifr.ifr_mtu > PKT_BUFFER) {
    debug(LOG_ERR, "MTU is larger than PKT_BUFFER: %d > %d",
           ifr.ifr_mtu, PKT_BUFFER);
    return -1;
  }
  netif->mtu = ifr.ifr_mtu;

  /* Get ifindex */
  strlcpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFINDEX, (caddr_t)&ifr) < 0) {
    debug(LOG_ERR, "%s: ioctl(SIOCFIGINDEX) failed", strerror(errno));
  }
  netif->ifindex = ifr.ifr_ifindex;

//  debug(LOG_DEBUG, "device %s ifindex %d", netif->devname, netif->ifindex);
  /* Set interface in promisc mode */
  if (netif->flags & NET_PROMISC) {
    struct packet_mreq mr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
    if (ioctl(netif->fd, SIOCGIFFLAGS, (caddr_t)&ifr) == -1) {
      debug(LOG_ERR, "%s: ioctl(SIOCGIFFLAGS)", strerror(errno));
    } else {
      netif->devflags = ifr.ifr_flags;
      ifr.ifr_flags |= IFF_PROMISC;
      if (ioctl (netif->fd, SIOCSIFFLAGS, (caddr_t)&ifr) == -1) {
	debug(LOG_ERR, "%s: Could not set flag IFF_PROMISC", strerror(errno));
      }
    }

    memset(&mr,0,sizeof(mr));
    mr.mr_ifindex = netif->ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    if (net_setsockopt(netif->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       (char *)&mr, sizeof(mr)) < 0)
      return -1;
  }

  /* Bind to particular interface */
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(netif->protocol);
  sa.sll_ifindex = netif->ifindex;

  if (bind(netif->fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    debug(LOG_ERR, "%s: bind(sockfd=%d) failed", strerror(errno), netif->fd);
    return -1;
  }

  memset(&netif->dest, 0, sizeof(netif->dest));
  netif->dest.sll_family = AF_PACKET;
  netif->dest.sll_protocol = htons(netif->protocol);
  netif->dest.sll_ifindex = netif->ifindex;

  return 0;
}


ssize_t
net_read_eth(net_interface *netif, void *d, size_t dlen) {
  ssize_t len = 0;
    if (netif->fd) {

      struct sockaddr_ll s_addr;


      int addr_len;
      memset (&s_addr, 0, sizeof (struct sockaddr_ll));

      addr_len = sizeof (s_addr);

      len = safe_recvfrom(netif->fd, d, dlen,
                          MSG_DONTWAIT | MSG_TRUNC,
                          (struct sockaddr *) &s_addr,
                          (socklen_t *) &addr_len);

      if (len < 0) {

        debug(LOG_ERR, "%s: could not read packet", strerror(errno));

      } else {

        if (len == 0) {
          debug(LOG_DEBUG, "read zero, enable ieee8021q?");
        }

        if (len > dlen) {
          debug(LOG_WARNING, "data truncated %zu/%zd, sending ICMP error",
		 len, dlen);
          return -1;
        }
      }

      if (len < 0) {
        debug(LOG_ERR, "%d net_read_eth(fd=%d, len=%zu, mtu=%d) == %zd",
               errno, netif->fd, dlen, netif->mtu, len);
        return -1;
      }
    }

  return len;
}


ssize_t
net_read_dispatch(net_interface *netif, net_handler func, void *ctx) {
  struct pkt_buffer pb;
  uint8_t packet[PKT_MAX_LEN];
  ssize_t length;
  pkt_buffer_init(&pb, packet, sizeof(packet), PKT_BUFFER_IPOFF);
  length = safe_read(netif->fd,
		     pkt_buffer_head(&pb),
		     pkt_buffer_size(&pb));
  if (length <= 0) return length;
  pb.length = length;
  return func(ctx, &pb);
}

ssize_t
net_read_dispatch_eth(net_interface *netif, net_handler func, void *ctx) {

    struct pkt_buffer pb;
    uint8_t packet[PKT_MAX_LEN];
    ssize_t length;
    pkt_buffer_init(&pb, packet, sizeof(packet), PKT_BUFFER_IPOFF);
    length = net_read_eth(netif,
			  pkt_buffer_head(&pb),
			  pkt_buffer_size(&pb));
    if (length <= 0) return length;
    pb.length = length;
    return func(ctx, &pb);

}

