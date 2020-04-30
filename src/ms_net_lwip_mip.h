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

#ifndef MS_NET_LWIP_MIP_H
#define MS_NET_LWIP_MIP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE

/* add a IP to netif (use slave interface) */
int netif_mipif_add(struct netif *netif, const ip4_addr_t *ip4,
                    const ip4_addr_t *netmask4, const ip4_addr_t *gw4);

/* delete a IP from netif (use slave interface) */
int netif_mipif_delete(struct netif *netif, const ip4_addr_t *ip4);

/* clean all slave interface */
void netif_mipif_clean(struct netif *netif);

/* set all slave interface update mtu, linkup, updown */
void netif_mipif_update(struct netif *netif);

/* set all slave interface hwaddr */
void netif_mipif_hwaddr(struct netif *netif);

/* set all slave interface find */
struct netif *netif_mipif_search(struct netif *netif, struct pbuf *p);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_LWIP_MIP_H */
