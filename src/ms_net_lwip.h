/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip.h lwIP network implement.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef MS_NET_LWIP_H
#define MS_NET_LWIP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MS_KERNEL_SPACE

ms_err_t ms_lwip_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* MS_NET_LWIP_H */
