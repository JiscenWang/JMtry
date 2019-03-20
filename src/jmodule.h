/*
 * jmodule.h
 *
 *  Created on: 2018年7月22日
 *      Author: jerome
 */

#ifndef SRC_JMODULE_H_
#define SRC_JMODULE_H_

#include "jnet.h"
#include "httpd.h"


/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
  int addrs;   /* Number of allocated IP addresses */
  int routes;  /* One if we allocated an automatic route */
  int (*cb_ind) (struct tun_t *tun, struct pkt_buffer *pb, int idx);
  struct _net_interface _tuntap;

#define tun(x,i) ((x)->_tuntap)
#define tuntap(x) tun((x),0)

#define tun_close(tun) net_close(&(tun)->_tuntap)

//  void *table;
};

/* Struct information for each connection */
/*Jerome TBD, combined with client structure, change name from app_conn_t to app_conn_tmp*/
struct app_conn_t {

  struct app_conn_t *next;    /* Next in linked list. 0: Last */
  struct app_conn_t *prev;    /* Previous in linked list. 0: First */

  /* Pointers to protocol handlers */
  void *uplink;                  /* Uplink network interface (Internet) */
  void *dnlink;                  /* Downlink network interface (Wireless) */

  uint8_t inuse:1;
  uint8_t is_adminsession:1;
  uint8_t uamabort:1;
  uint8_t uamexit:1;

  /* Management of connections */
  int unit;
  int dnprot;                    /* Downlink protocol, to be deleted */
  time_t rt;

  /* Parameters for radius accounting */
  /* These parameters are set when an access accept is sent back to the
     NAS */

  uint32_t nasip;              /* Set by access request */
  uint32_t nasport;            /* Set by access request */
  uint8_t hismac[PKT_ETH_ALEN];/* His MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in_addr hismask;      /* Client IP address mask */
  struct in_addr reqip;        /* IP requested by client */
  uint16_t mtu;

  /* Information for each connection */
//Jerome  struct in_addr net;
  //Jerome    struct in_addr mask;
  //Jerome    struct in_addr dns1;
  //Jerome    struct in_addr dns2;

};

size_t strlcpy(char *dst, const char *src, size_t dsize);
time_t mainclock_tick();
int mainclock_diff(time_t past);
time_t mainclock_rt();

int tun_new(struct tun_t **ptun);
int tun_setaddr(struct tun_t *this, struct in_addr *addr, struct in_addr *dstaddr, struct in_addr *netmask);
int tun_set_cb_ind(struct tun_t *this,
		   int (*cb_ind) (struct tun_t *tun, struct pkt_buffer *pb, int idx));
int cb_tun_ind(struct tun_t *tun, struct pkt_buffer *pb, int idx);
int tun_decaps(struct tun_t *this, int idx);
int tun_encaps(struct tun_t *tun, uint8_t *pack, size_t len, int idx);
int tun_write(struct tun_t *tun, uint8_t *pack, size_t len, int idx);
int tun_free(struct tun_t *tun);

int jmodulehttpconnect(httpd *server, int index);

#endif /* SRC_JMODULE_H_ */
