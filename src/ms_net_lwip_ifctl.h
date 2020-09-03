/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip_ifctl.h lwIP netif control.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef MS_NET_LWIP_IFCTL_H
#define MS_NET_LWIP_IFCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE

int __ms_lwip_if_ioctl_inet(int cmd, void *arg);

#define LWIP_IF_LIST_LOCK(write)    LOCK_TCPIP_CORE()
#define LWIP_IF_LIST_UNLOCK()       UNLOCK_TCPIP_CORE()

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_LWIP_IFCTL_H */
