/*
 * jnet.h
 *
 *  Created on: 2018年7月21日
 *      Author: jerome
 */

#ifndef SRC_JNET_H_
#define SRC_JNET_H_

#include <net/if.h>

#include <asm/types.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/time.h>

/*
 * http://www.iana.org/assignments/ethernet-numbers
 */
#define PKT_ETH_PROTO_IP     0x0800
#define PKT_ETH_PROTO_ARP    0x0806
#define PKT_ETH_PROTO_WOL    0x0842
#define PKT_ETH_PROTO_ETHBR  0x6558
#define PKT_ETH_PROTO_8021Q  0x8100
#define PKT_ETH_PROTO_IPX    0x8137
#define PKT_ETH_PROTO_IPv6   0x86dd
#define PKT_ETH_PROTO_PPP    0x880b
#define PKT_ETH_PROTO_PPPOED 0x8863
#define PKT_ETH_PROTO_PPPOES 0x8864
#define PKT_ETH_PROTO_EAPOL  0x888e
#define PKT_ETH_PROTO_CHILLI 0xbeef

#define PKT_IP_PLEN            1500 /* IP Payload Length */
#define PKT_IP_VER_HLEN        0x45
#define PKT_IP_ALEN               4
#define PKT_IP_HLEN              20
#define PKT_IPv6_HLEN            40

#define PKT_IP_PROTO_ICMP         1 /* ICMP Protocol number */
#define PKT_IP_PROTO_IGMP         2 /* IGMP Protocol number */
#define PKT_IP_PROTO_TCP          6 /* TCP Protocol number */
#define PKT_IP_PROTO_UDP         17 /* UDP Protocol number */
#define PKT_IP_PROTO_GRE         47 /* GRE Protocol number */
#define PKT_IP_PROTO_ESP         50
#define PKT_IP_PROTO_AH          51
#define PKT_IP_PROTO_SKIP        57
#define PKT_IP_PROTO_EIGRP       88
#define PKT_IP_PROTO_OSPF        89
#define PKT_IP_PROTO_L2TP       115

#define PKT_UDP_HLEN              8
#define PKT_TCP_HLEN             20
#define PKT_DOT1X_HLEN            4

#define PKT_EAP_PLEN          10240 /* Dot1x Payload length */

#define DHCP_TAG_VLEN           255 /* Tag value always shorter than this */
#define EAPOL_TAG_VLEN          255 /* Tag value always shorter than this */

#define DHCP_HTYPE_ETH            1
#define DHCP_CHADDR_LEN          16 /* Length of client hardware address */
#define DHCP_SNAME_LEN           64 /* Length of server host name */
#define DHCP_FILE_LEN           128 /* Length of boot file name*/
#define DHCP_OPTIONS_LEN        312 /* Length of optional parameters field */
#define DHCP_MIN_LEN   28+16+64+128 /* Length of packet excluding options */
#define DHCP_LEN  (DHCP_MIN_LEN+DHCP_OPTIONS_LEN)

#define PKT_ETH_ALEN              6 /* Ethernet Address Length */
#define PKT_ETH_HLEN             14 /* Ethernet Header Length */

#define PKT_BUFFER 9000

#define pkt_buffer_head(pb)    ((pb)->buf + (pb)->offset)
#define pkt_buffer_length(pb)  ((pb)->length)
#define pkt_buffer_size(pb)    ((pb)->buflen - (pb)->offset)
#define pkt_buffer_grow(pb,l)  (pb)->offset -= (l); (pb)->length += (l)

#define iphdr_more_frag(p) ((p)->opt_off_high & 0x20)
#define iphdr_offset(p) ntohs((((p)->opt_off_high & 0x13) << 8)|(p)->off_low)

#define sizeofeth2(x)     (PKT_ETH_HLEN)
#define sizeofeth(pkt)    (PKT_ETH_HLEN)

#define sizeofip(pkt)     (sizeofeth(pkt)+((pkt_iphdr(pkt)->version_ihl & 0xf)*4))
#define sizeofdot1x(pkt)  (sizeofeth(pkt)+PKT_DOT1X_HLEN)
#define sizeofudp(pkt)    (sizeofip(pkt)+PKT_UDP_HLEN)
#define sizeoftcp(pkt)    (sizeofip(pkt)+PKT_TCP_HLEN)
#define sizeofarp(pkt)    (sizeofeth(pkt)+sizeof(struct arp_packet_t))

#define pkt_ethhdr(pkt)   ((struct pkt_ethhdr_t *)pkt)
#define pkt_ipphdr(pkt)   ((struct pkt_ipphdr_t *)  (((uint8_t*)(pkt)) + sizeofeth(pkt)))
#define pkt_iphdr(pkt)    ((struct pkt_iphdr_t *)   (((uint8_t*)(pkt)) + sizeofeth(pkt)))
#define pkt_icmphdr(pkt)  ((struct pkt_icmphdr_t *) (((uint8_t*)(pkt)) + sizeofip(pkt)))
#define pkt_udphdr(pkt)   ((struct pkt_udphdr_t *)  (((uint8_t*)(pkt)) + sizeofip(pkt)))
#define pkt_tcphdr(pkt)   ((struct pkt_tcphdr_t *)  (((uint8_t*)(pkt)) + sizeofip(pkt)))
#define pkt_dot1xhdr(pkt) ((struct pkt_dot1xhdr_t *)(((uint8_t*)(pkt)) + sizeofeth(pkt)))
#define pkt_dhcppkt(pkt)  ((struct dhcp_packet_t *) (((uint8_t*)(pkt)) + sizeofudp(pkt)))
#define pkt_arppkt(pkt)   ((struct arp_packet_t *)  (((uint8_t*)(pkt)) + sizeofeth(pkt)))
#define pkt_dnspkt(pkt)   ((struct dns_packet_t *)  (((uint8_t*)(pkt)) + sizeofudp(pkt)))
#define pkt_eappkt(pkt)   ((struct eap_packet_t *)  (((uint8_t*)(pkt)) + sizeofdot1x(pkt)))

struct pkt_ethhdr8021q_t {
  uint8_t  dst[PKT_ETH_ALEN];
  uint8_t  src[PKT_ETH_ALEN];
  uint16_t tpid;
#define PKT_8021Q_MASK_VID htons(0x0FFF)
#define PKT_8021Q_MASK_PCP htons(0xE000)
#define PKT_8021Q_MASK_CFI htons(0x1000)
  uint16_t pcp_cfi_vid;
  uint16_t prot;
} __attribute__((packed));

#define PKT_BUFFER_IPOFF  (sizeof(struct pkt_ethhdr8021q_t))

#define MAC_FMT "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X"
#define MAC_ARG(x) (x)[0],(x)[1],(x)[2],(x)[3],(x)[4],(x)[5]

#define MAX_SELECT    16

#define net_sflags(n,f) dev_set_flags((n)->devname, (f))
#define net_gflags(n) dev_get_flags((n)->devname, &(n)->devflags)

#define fd_zero(fds)       FD_ZERO((fds));
#define fd_set(fd,fds)     if ((fd) > 0) FD_SET((fd), (fds))
#define fd_isset(fd,fds)   ((fd) > 0) && FD_ISSET((fd), (fds))
#define fd_max(fd,max)     (max) = (max) > (fd) ? (max) : (fd)

typedef int (*select_callback) (void *data, int idx);

#define copy_ethproto(o,n) {                                            \
    ((struct pkt_ethhdr_t *)n)->prot = ((struct pkt_ethhdr_t *)o)->prot; \
  }


typedef struct {
  int fd;
  int idx;
  char evts;
  select_callback cb;
  void *ctx;
} select_fd;

typedef struct{
  int count;
  select_fd desc[MAX_SELECT];

  int maxfd;
  fd_set rfds, wfds, efds;
  struct timeval idleTime;
} select_ctx;


typedef struct _net_interface {
  uint8_t idx;

  /* hardware/link */
  uint16_t protocol;
  uint8_t hwtype;
  uint8_t hwaddr[PKT_ETH_ALEN];
  char devname[IFNAMSIZ+1];
  int devflags;
  int ifindex;
  int mtu;

  /* network/address */
  struct in_addr address;
  struct in_addr network;
  struct in_addr netmask;
  struct in_addr broadcast;
  struct in_addr gateway;

  /* socket/descriptor */
  int fd;
  struct sockaddr_ll dest;

  /* routing */
  uint8_t gwaddr[PKT_ETH_ALEN];

  select_ctx *sctx;

  uint8_t flags;
#define NET_PROMISC (1<<0)
#define NET_USEMAC  (1<<1)
#define NET_ETHHDR  (1<<2)
#define NET_PPPHDR  (1<<3)
} net_interface;

#define SELECT_READ 1
#define SELECT_WRITE 2
#define SELECT_RESET 4

struct pkt_buffer {
  uint8_t *   buf;
  size_t      buflen;
  size_t      offset;
  size_t      length;
};

#define pkt_buffer_init(pb, b, blen, off)	\
  (pb)->buf = (b);				\
  (pb)->buflen = (blen);			\
  (pb)->offset = (off);                         \
  (pb)->length = 0

struct pkt_ethhdr_t {
  uint8_t  dst[PKT_ETH_ALEN];
  uint8_t  src[PKT_ETH_ALEN];
  uint16_t prot;
} __attribute__((packed));

struct pkt_iphdr_t {
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint8_t opt_off_high;
  uint8_t off_low;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));

struct pkt_ipphdr_t {
  /* Convenience structure:
     Same as pkt_iphdr_t, but also
     with ports (UDP and TCP packets) */
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
} __attribute__((packed));


struct pkt_icmphdr_t {
  uint8_t type;
  uint8_t code;
  uint16_t check;
} __attribute__((packed));


/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
  +---------------+---------------+---------------+---------------+
  |                            xid (4)                            |
  +-------------------------------+-------------------------------+
  |           secs (2)            |           flags (2)           |
  +-------------------------------+-------------------------------+
  |                          ciaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          yiaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          siaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          giaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          chaddr  (16)                         |
  |                             (cont)                            |
  +---------------------------------------------------------------+
  |                          sname   (64)                         |
  |                             (cont)                            |
  +---------------------------------------------------------------+
  |                          file    (128)                        |
  |                             (cont)                            |
  +---------------------------------------------------------------+
  |                          options (variable)                   |
  |                             (cont)                            |
  +---------------------------------------------------------------+
*/

struct dhcp_packet_t { /* From RFC 2131 */
uint8_t op;       /* 1 Message op code / message type.  1 = BOOTREQUEST, 2 = BOOTREPLY */
uint8_t htype;    /* 1 Hardware address type, see ARP section in "Assigned Numbers" RFC */
uint8_t hlen;     /* 1 Hardware address length (e.g. '6' for 10mb ethernet).*/
uint8_t hops;     /* 1 Client sets to zero, optionally used by relay agents when booting via a relay agent.*/
uint32_t xid;     /* 4 Transaction ID, a random number chosen by the client, used by the client and
	       server to associate messages and responses between a client and a server. */
uint16_t secs;    /* 2 Filled in by client, seconds elapsed since client began address acquisition or renewal process.*/
uint8_t flags[2]; /* 2  Flags (see figure 2).*/
uint32_t ciaddr;  /* 4 Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state
	       and can respond to ARP requests.*/
uint32_t yiaddr;  /* 4 'your' (client) IP address.*/
uint32_t siaddr;  /* 4 IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.*/
uint32_t giaddr;  /* 4 Relay agent IP address, used in booting via a relay agent.*/
uint8_t chaddr[DHCP_CHADDR_LEN];   /* 16 Client hardware address.*/
uint8_t sname[DHCP_SNAME_LEN];     /* 64 Optional server host name, null terminated string.*/
uint8_t file[DHCP_FILE_LEN];       /* 128 Boot file name, null terminated string; "generic" name or null in
				DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER.*/
uint8_t options[DHCP_OPTIONS_LEN]; /* var Optional parameters field.  See the options documents for a list
				of defined options.*/
} __attribute__((packed));


struct dhcp_tag_t {
uint8_t t;
uint8_t l;
uint8_t v[DHCP_TAG_VLEN];
} __attribute__((packed));


struct dns_packet_t { /* From RFC 1035 */
  uint16_t id;      /* 16 bit: Generated by requester. Copied in reply */
  uint16_t flags;   /* 16 bit: Flags */
  uint16_t qdcount; /* 16 bit: Number of questions */
  uint16_t ancount; /* 16 bit: Number of answer records */
  uint16_t nscount; /* 16 bit: Number of name servers */
  uint16_t arcount; /* 16 bit: Number of additional records */
  uint8_t  records[PKT_IP_PLEN];
} __attribute__((packed));



/*
  0      7 8     15 16    23 24    31
  +--------+--------+--------+--------+
  |     Source      |   Destination   |
  |      Port       |      Port       |
  +--------+--------+--------+--------+
  |                 |                 |
  |     Length      |    Checksum     |
  +--------+--------+--------+--------+
  |
  |          data octets ...
  +---------------- ...

  User Datagram Header Format
*/

struct pkt_udphdr_t {
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t check;
} __attribute__((packed));

/*
  TCP Header Format

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Data |           |U|A|P|R|S|F|                               |
  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  |       |           |G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pkt_tcphdr_t {
  uint16_t src;
  uint16_t dst;
  uint32_t seq;
  uint32_t ack;
  uint8_t  offres;
  uint8_t  flags;
  uint16_t win;
  uint16_t check;
  uint16_t urgent;
  uint8_t options[4];
} __attribute__((packed));


struct arp_packet_t { /* From RFC 826 */
  uint16_t hrd; /* 16.bit: (ar$hrd) Hardware address space (e.g.,
                   Ethernet, Packet Radio Net.) */
  uint16_t pro; /* 16.bit: (ar$pro) Protocol address space.  For
                   Ethernet hardware, this is from the set of type
                   fields ether_typ$<protocol>. */
  uint8_t hln;  /* 8.bit: (ar$hln) byte length of each hardware address */
  uint8_t pln;  /* 8.bit: (ar$pln) byte length of each protocol address */
  uint16_t op;  /* 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY) */
  uint8_t sha[PKT_ETH_ALEN]; /* nbytes: (ar$sha) Hardware address of
                                sender of this packet, n from the ar$hln field. */
  uint8_t spa[PKT_IP_ALEN];  /* mbytes: (ar$spa) Protocol address of
                                sender of this packet, m from the ar$pln field. */
  uint8_t tha[PKT_ETH_ALEN]; /* nbytes: (ar$tha) Hardware address of
                                target of this packet (if known). */
  uint8_t tpa[PKT_IP_ALEN]; /* mbytes: (ar$tpa) Protocol address of
                               target.*/
} __attribute__((packed));


typedef int (*net_handler)(void *ctx, struct pkt_buffer *pb);

int ndelay_on (int fd);
int coe (int fd);

int dev_set_flags(char const *dev, int flags);

int net_init(net_interface *netif, char *ifname,
	     uint16_t protocol, int promisc);
int net_close(net_interface *netif);
int net_select_reg(select_ctx *sctx, int fd, char evts,
		   select_callback cb, void *ctx, int idx);
int net_set_address(net_interface *netif, struct in_addr *address,
		    struct in_addr *dstaddr, struct in_addr *netmask);
int net_select_prepare(select_ctx *sctx);
int net_select(select_ctx *sctx);
int net_run_selected(select_ctx *sctx, int status);
ssize_t
net_read_dispatch_eth(net_interface *netif, net_handler func, void *ctx);
ssize_t
net_read_dispatch(net_interface *netif, net_handler func, void *ctx);
ssize_t net_write_eth(net_interface *netif, void *d, size_t dlen, struct sockaddr_ll *dest);

void copy_mac6(uint8_t *, uint8_t *);
int chksum(struct pkt_iphdr_t *iph);

#endif /* SRC_JNET_H_ */
