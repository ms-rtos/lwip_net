/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip.c lwIP network implement.
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
#include "sys/socket.h"
#include "netdb.h"
#include "lwip/tcpip.h"
#include "lwip/api.h"

/**
 * @brief LwIP Network implement.
 */

extern ms_bool_t lwip_msrtos_socket_readable_check(int s);
extern ms_bool_t lwip_msrtos_socket_writable_check(int s);
extern ms_bool_t lwip_msrtos_socket_except_check(int s);
extern int       lwip_msrtos_socket_ctx_set(int s, void *ctx);

#define MS_LWIP_NET_IMPL_NAME       "ms_lwip_net"
#define MS_LWIP_SOCKET_DRV_NAME     "ms_lwip_socket"

static ms_bool_t ms_lwip_inited = MS_FALSE;

/*
 * Open socket device
 */
static int __ms_lwip_socket_open(ms_ptr_t ctx, ms_io_file_t *file, int oflag, ms_mode_t mode)
{
    int ret;

    if (ms_atomic_inc(MS_IO_DEV_REF(file)) == 2) {
        ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
        ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

        file->type |= MS_IO_FILE_TYPE_SOCK;
        ret = lwip_msrtos_socket_ctx_set((int)ctx, sock_dev);

    } else {
        ms_atomic_dec(MS_IO_DEV_REF(file));
        ms_thread_set_errno(EBUSY);
        ret = -1;
    }

    return ret;
}

/*
 * Close socket device
 */
static int __ms_lwip_socket_close(ms_ptr_t ctx, ms_io_file_t *file)
{
    int ret;

    if (ms_atomic_dec(MS_IO_DEV_REF(file)) == 0) {
        ret = lwip_close((int)ctx);
        if (ret == 0) {
            ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
            ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

            (void)ms_io_device_unregister(dev);
            (void)ms_kfree(sock_dev);
        }
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * Read socket device
 */
static ssize_t __ms_lwip_socket_read(ms_ptr_t ctx, ms_io_file_t *file, ms_ptr_t buf, size_t len)
{
    return lwip_read((int)ctx, buf, len);
}

/*
 * Write socket device
 */
static ssize_t __ms_lwip_socket_write(ms_ptr_t ctx, ms_io_file_t *file, ms_const_ptr_t buf, size_t len)
{
    return lwip_write((int)ctx, buf, len);
}

/*
 * Control socket device
 */
static int __ms_lwip_socket_ioctl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, void *arg)
{
    return lwip_ioctl((int)ctx, cmd, arg);
}

/*
 * Control socket device
 */
static int __ms_lwip_socket_fcntl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, int arg)
{
    int ret;

    ret = lwip_fcntl((int)ctx, cmd, arg);
    if ((ret == 0) && (cmd == F_SETFL)) {
        file->flags = arg;
    }

    return ret;
}

/*
 * Check socket device readable
 */
static ms_bool_t __ms_lwip_socket_readable_check(ms_ptr_t ctx)
{
    return lwip_msrtos_socket_readable_check((int)ctx);
}

/*
 * Check socket device writable
 */
static ms_bool_t __ms_lwip_socket_writable_check(ms_ptr_t ctx)
{
    return lwip_msrtos_socket_writable_check((int)ctx);
}

/*
 * Check socket device exception
 */
static ms_bool_t __ms_lwip_socket_except_check(ms_ptr_t ctx)
{
    return lwip_msrtos_socket_except_check((int)ctx);
}

/*
 * Socket device notify
 */
int ms_lwip_socket_poll_notify(ms_ptr_t ctx, ms_pollevent_t event)
{
    ms_net_socket_device_t *sock_dev = (ms_net_socket_device_t *)ctx;

    return ms_io_poll_notify_heaper(sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), event);
}

/*
 * Poll socket device
 */
static int __ms_lwip_socket_poll(ms_ptr_t ctx, ms_io_file_t *file, ms_pollfd_t *fds, ms_bool_t setup)
{
    ms_io_device_t *dev = MS_IO_FILE_TO_DEV(file);
    ms_net_socket_device_t *sock_dev = MS_CONTAINER_OF(dev, ms_net_socket_device_t, dev);

    return ms_io_poll_heaper(fds, sock_dev->slots, MS_ARRAY_SIZE(sock_dev->slots), setup, ctx,
                             __ms_lwip_socket_readable_check, __ms_lwip_socket_writable_check,
                             __ms_lwip_socket_except_check);
}

/*
 * Socket device operating function set
 */
static ms_io_driver_ops_t ms_lwip_socket_drv_ops = {
        .type     = MS_IO_DRV_TYPE_SOCK,
        .open     = __ms_lwip_socket_open,
        .close    = __ms_lwip_socket_close,
        .write    = __ms_lwip_socket_write,
        .read     = __ms_lwip_socket_read,
        .ioctl    = __ms_lwip_socket_ioctl,
        .fcntl    = __ms_lwip_socket_fcntl,
        .poll     = __ms_lwip_socket_poll,
};

/*
 * Socket device driver
 */
static ms_io_driver_t ms_lwip_socket_drv = {
        .nnode = {
            .name = MS_LWIP_SOCKET_DRV_NAME,
        },
        .ops = &ms_lwip_socket_drv_ops,
};

static int __ms_lwip_socket(int domain, int type, int protocol)
{
    int lwip_fd = lwip_socket(domain, type, protocol);
    int fd;

    if (lwip_fd >= 0) {
        fd = ms_net_socket_attach(MS_LWIP_SOCKET_DRV_NAME, (ms_ptr_t)lwip_fd);
        if (fd < 0) {
            int err = ms_thread_get_errno();
            (void)lwip_close(lwip_fd);
            ms_thread_set_errno(err);
        }
    } else {
        fd = -1;
    }

    return fd;
}

static int __ms_lwip_accept(ms_ptr_t ctx, ms_io_file_t *file, struct sockaddr *addr, socklen_t *addrlen)
{
    int accept_lwip_fd;
    int accept_fd;

    accept_lwip_fd = lwip_accept((int)ctx, addr, addrlen);
    if (accept_lwip_fd >= 0) {
        accept_fd = ms_net_socket_attach(MS_LWIP_SOCKET_DRV_NAME, (ms_ptr_t)accept_lwip_fd);
        if (accept_fd < 0) {
            int err = ms_thread_get_errno();
            (void)lwip_close(accept_lwip_fd);
            ms_thread_set_errno(err);
        }
    } else {
        accept_fd = -1;
    }

    return accept_fd;
}

static int __ms_lwip_gethostname(char *name, size_t len)
{
    int ret;

    if (name != MS_NULL) {
        if (len >= sizeof("MS-RTOS")) {
            strlcpy(name, "MS-RTOS", len);
            ret = 0;
        } else {
            ms_thread_set_errno(EINVAL);
            ret = -1;
        }
    } else {
        ms_thread_set_errno(EFAULT);
        ret = -1;
    }

    return ret;
}

static int __ms_lwip_sethostname(const char *name, size_t len)
{
    ms_thread_set_errno(EOPNOTSUPP);
    return -1;
}

static ms_net_impl_ops_t ms_lwip_net_impl_ops = {
        .socket                 = (ms_net_socket_func_t)__ms_lwip_socket,
        .accept                 = (ms_net_accept_func_t)__ms_lwip_accept,
        .bind                   = (ms_net_bind_func_t)lwip_bind,
        .getpeername            = (ms_net_getpeername_func_t)lwip_getpeername,
        .getsockname            = (ms_net_getsockname_func_t)lwip_getsockname,
        .getsockopt             = (ms_net_getsockopt_func_t)lwip_getsockopt,
        .setsockopt             = (ms_net_setsockopt_func_t)lwip_setsockopt,
        .connect                = (ms_net_connect_func_t)lwip_connect,
        .listen                 = (ms_net_listen_func_t)lwip_listen,
        .shutdown               = (ms_net_shutdown_func_t)lwip_shutdown,
        .recv                   = (ms_net_recv_func_t)lwip_recv,
        .recvfrom               = (ms_net_recvfrom_func_t)lwip_recvfrom,
        .recvmsg                = (ms_net_recvmsg_func_t)lwip_recvmsg,
        .send                   = (ms_net_send_func_t)lwip_send,
        .sendmsg                = (ms_net_sendmsg_func_t)lwip_sendmsg,
        .sendto                 = (ms_net_sendto_func_t)lwip_sendto,
        .if_indextoname         = (ms_net_if_indextoname_func_t)lwip_if_indextoname,
        .if_nametoindex         = (ms_net_if_nametoindex_func_t)lwip_if_nametoindex,
        .gethostbyname_addrtype = (ms_net_gethostbyname_addrtype_func_t)netconn_gethostbyname_addrtype,
        .gethostname            = (ms_net_gethostname_func_t)__ms_lwip_gethostname,
        .sethostname            = (ms_net_sethostname_func_t)__ms_lwip_sethostname,
};

static ms_net_impl_t ms_lwip_net_impl = {
        .nnode = {
            .name = MS_LWIP_NET_IMPL_NAME,
        },
        .ops = &ms_lwip_net_impl_ops,
};

/**
 * @brief Initial lwIP network component.
 *
 * @param[in] init_done_callback Pointer to lwIP network initial done call back function
 * @param[in] arg Argument of init_done_callback
 *
 * @return Error number
 */
ms_err_t ms_lwip_net_init(void (*init_done_callback)(ms_ptr_t arg), ms_ptr_t arg)
{
    ms_err_t err;

    tcpip_init(init_done_callback, arg);

    err = ms_net_impl_register(&ms_lwip_net_impl);
    if (err == MS_ERR_NONE) {
        err = ms_io_driver_register(&ms_lwip_socket_drv);
        if (err == MS_ERR_NONE) {
            ms_lwip_inited = MS_TRUE;
        }
    }

    return err;
}

#if (MS_CFG_NET_SHELL_CMD_EN > 0U) && (LWIP_STATS > 0U) && (LWIP_STATS_DISPLAY > 0U)

#include "ms_shell.h"

ms_printf_func_t ms_lwip_platform_diag = ms_printf;

/**
 * @brief lwIP stat command.
 *
 * @param[in] argc Arguments count
 * @param[in] argv Arguments array
 * @param[in] io Pointer to shell io driver
 *
 * @return N/A
 */
static void __ms_shell_lwip_stat(int argc, char *argv[], const ms_shell_io_t *io)
{
    if (ms_lwip_inited) {
        ms_lwip_platform_diag = io->_printf;

        stats_display();

        ms_lwip_platform_diag = ms_printf;
    } else {
        io->_printf("lwIP no init!\n");
    }
}

MS_SHELL_CMD(lwipstat, __ms_shell_lwip_stat,  "Show lwIP network statistics", __ms_shell_cmd_lwip_stat);

#endif
