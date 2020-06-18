/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip_mip.c lwIP multi IP support.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#define __MS_NET
#define __MS_IO
#include "ms_kern.h"
#include "ms_io_core.h"
#include "ms_net_core.h"
#include "ms_net_lwip.h"

#include "arpa/inet.h"
#include "net/if.h"
#include "net/if_types.h"
#include "net/if_arp.h"
#include "net/if_hwaddr.h"
#include "netinet/in.h"
#include "sys/socket.h"
#include "netdb.h"
#include "lwip/tcpip.h"
#include "lwip/api.h"
#include "lwip/snmp.h"
#include "lwip/etharp.h"
#include "lwip/netifapi.h"

#include "ms_net_lwip_mip.h"

/**
 * @brief lwIP multi IP support.
 */

#if MS_LWIP_NETIF_MIP_EN > 0

#ifdef __GNUC__
#define LW_LIKELY(x)            __builtin_expect(!!(x), 1)
#define LW_UNLIKELY(x)          __builtin_expect(!!(x), 0)
#else
#define LW_LIKELY(x)            (x)
#define LW_UNLIKELY(x)          (x)
#endif

struct netif *netif_mipif_ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
  struct netif *netif;
  u8_t match = 0;

  NETIF_FOREACH(netif) {
    if (ip4_addr_cmp(src, netif_ip4_addr(netif))) {
      match = 1;
      break;
    }
  }

  if (!match) {
    netif = NULL;
  }

  return netif;
}

/*
 * add a IP to netif init callback
 */
static err_t netif_mipif_init (struct netif *mipif)
{
  struct netif *netif = (struct netif *)mipif->state;

#if LWIP_NETIF_HOSTNAME
  mipif->hostname = netif->hostname;
#endif /* LWIP_NETIF_HOSTNAME */

  mipif->name[0] = 'm';
  mipif->name[1] = 'i';

  MIB2_INIT_NETIF(mipif, netif->link_type, netif->link_speed);

  /* no ipv6, no multicast, no promisc */
  mipif->flags = (u8_t)(netif->flags & ~(NETIF_FLAG_IGMP | NETIF_FLAG_MLD6));

  mipif->output = netif->output;
  mipif->linkoutput = netif->linkoutput;

  mipif->mtu = netif->mtu;

  mipif->hwaddr_len = netif->hwaddr_len;
  MEMCPY(mipif->hwaddr, netif->hwaddr, netif->hwaddr_len);

  /* link to list */
  mipif->mipif = netif->mipif;
  netif->mipif = mipif;
  mipif->is_mipif = 1;

  return (ERR_OK);
}

/*
 * add a IP to netif (use slave interface)
 */
int netif_mipif_add (struct netif *netif, const ip4_addr_t *ip4,
                     const ip4_addr_t *netmask4, const ip4_addr_t *gw4)
{
  struct netif *mipif;

  if (!netif || (netif_is_mipif(netif))) {
    errno = EINVAL;
    return (-1);
  }

  if (ip4_addr_isany(ip4)) {
    errno = EINVAL;
    return (-1);
  }

  if (ip4_addr_cmp(netif_ip4_addr(netif), ip4)) {
    errno = EADDRINUSE;
    return (-1);
  }

  NETIF_MIPIF_FOREACH(netif, mipif) {
    if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
      errno = EADDRINUSE;
      return (-1);
    }
  }

  mipif = (struct netif *)mem_malloc(sizeof(struct netif));
  if (!mipif) {
    errno = ENOMEM;
    return (-1);
  }
  bzero(mipif, sizeof(struct netif));

  if (netifapi_netif_add(mipif, ip4, netmask4, gw4, netif, netif_mipif_init, tcpip_input)) {
    errno = ENOSPC;
    return (-1);
  }

  return (0);
}

/*
 * delete a IP from netif (use slave interface)
 */
int netif_mipif_delete (struct netif *netif, const ip4_addr_t *ip4)
{
  struct netif *mipif, *tmp;

  if (!netif || (netif_is_mipif(netif))) {
    errno = EINVAL;
    return (-1);
  }

  if (ip4_addr_isany(ip4)) {
    errno = EINVAL;
    return (-1);
  }

  if (!netif->mipif) {
    errno = EINVAL;
    return (-1);
  }

  mipif = netif->mipif;

  if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
    netif->mipif = mipif->mipif;

  } else {
    tmp = mipif;
    for (mipif = mipif->mipif; mipif != NULL; mipif = mipif->mipif) {
      if (ip4_addr_cmp(netif_ip4_addr(mipif), ip4)) {
        tmp->mipif = mipif->mipif;
        break;
      }
      tmp = mipif;
    }
  }

  if (mipif) {
    netifapi_netif_remove(mipif);
    mem_free(mipif);
    return (0);
  }

  errno = EINVAL;
  return (-1);
}

/*
 * clean all slave interface
 */
void netif_mipif_clean (struct netif *netif)
{
  struct netif *mipif, *tmp;

  if (!netif || (netif_is_mipif(netif))) {
    return;
  }

  mipif = netif->mipif;

  while (mipif) {
    tmp = mipif->mipif;
    netifapi_netif_remove(mipif);
    mem_free(mipif);
    mipif = tmp;
  }
}

/*
 * set all slave interface update mtu, linkup, updown
 */
void netif_mipif_update (struct netif *netif)
{
  struct netif *mipif;

  if (!netif || (netif_is_mipif(netif))) {
    return;
  }

  NETIF_MIPIF_FOREACH(netif, mipif) {
    mipif->mtu = netif->mtu;
    mipif->link_speed = netif->link_speed;
    if ((mipif->flags & NETIF_FLAG_UP) && !(netif->flags & NETIF_FLAG_UP)) {
      netif_set_down(mipif);
    } else if (!(mipif->flags & NETIF_FLAG_UP) && (netif->flags & NETIF_FLAG_UP)) {
      netif_set_up(mipif);
    }
    mipif->flags = (u8_t)(netif->flags & ~(NETIF_FLAG_IGMP | NETIF_FLAG_MLD6));
  }
}

/*
 * set all slave interface hwaddr
 */
void netif_mipif_hwaddr (struct netif *netif)
{
  struct netif *mipif;

  if (!netif || (netif_is_mipif(netif))) {
    return;
  }

  NETIF_MIPIF_FOREACH(netif, mipif) {
    MEMCPY(mipif->hwaddr, netif->hwaddr, netif->hwaddr_len);
  }
}

/*
 * set all slave interface find
 */
struct netif *netif_mipif_search (struct netif *netif, struct pbuf *p)
{
  u16_t next_offset;
  u16_t type;
  ip4_addr_t destip;
  struct netif *mipif;

  destip.addr = IPADDR_ANY;

  if (netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {
    struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
    next_offset = SIZEOF_ETH_HDR;
    if (LW_UNLIKELY(p->len < SIZEOF_ETH_HDR)) {
      return (netif);
    }

    type = ethhdr->type;
    if (type == PP_HTONS(ETHTYPE_VLAN)) {
      struct eth_vlan_hdr *vlan = (struct eth_vlan_hdr *)(((char *)ethhdr) + SIZEOF_ETH_HDR);
      if (LW_UNLIKELY(p->len < SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR)) {
        return (netif);
      }
      next_offset = SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR;
      type = vlan->tpid;
    }

    switch (type) {

    case PP_HTONS(ETHTYPE_ARP):
    case PP_HTONS(ETHTYPE_RARP): {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((u8_t *)p->payload + next_offset);
        if (LW_UNLIKELY(p->len < next_offset + SIZEOF_ETHARP_HDR)) {
          return (netif);
        }
#if BYTE_ORDER == BIG_ENDIAN
        destip.addr = (arphdr->dipaddr.addrw[0] << 16) | arphdr->dipaddr.addrw[1];
#else
        destip.addr = (arphdr->dipaddr.addrw[1] << 16) | arphdr->dipaddr.addrw[0];
#endif
      }
      break;

    case PP_HTONS(ETHTYPE_IP): {
        struct ip_hdr *iphdr = (struct ip_hdr *)((char *)p->payload + next_offset);
        if (LW_UNLIKELY(p->len < next_offset + IP_HLEN)) {
          return (netif);
        }
        if (IPH_V(iphdr) != 4) {
          return (netif);
        }
        destip.addr = iphdr->dest.addr;
      }
      break;

    default:
      return (netif);
    }

  } else {
    struct ip_hdr *iphdr = (struct ip_hdr *)((char *)p->payload);
    if (LW_UNLIKELY(p->len < IP_HLEN)) {
      return (netif);
    }
    if (IPH_V(iphdr) != 4) {
      return (netif);
    }
    destip.addr = iphdr->dest.addr;
  }

  if (ip4_addr_cmp(netif_ip4_addr(netif), &destip)) {
    return (netif);
  }

  NETIF_MIPIF_FOREACH(netif, mipif) {
    if (ip4_addr_cmp(netif_ip4_addr(mipif), &destip)) {
      return (mipif);
    }
  }

  return (netif);
}

#endif
