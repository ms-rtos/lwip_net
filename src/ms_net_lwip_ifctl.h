/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip_ifctl.c lwIP if control.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef MS_NET_LWIP_IFCTL_H
#define MS_NET_LWIP_IFCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE

int __ms_lwip_if_ioctl_inet(int cmd, void *arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_LWIP_IFCTL_H */
