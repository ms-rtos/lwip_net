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
#include "ms_net_lwip_ifctl.h"

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
#include "lwip/netifapi.h"

/**
 * @brief LwIP Network implement.
 */

extern ms_bool_t lwip_msrtos_socket_readable_check(int s);
extern ms_bool_t lwip_msrtos_socket_writable_check(int s);
extern ms_bool_t lwip_msrtos_socket_except_check(int s);
extern int       lwip_msrtos_socket_ctx_set(int s, void *ctx);

#define MS_LWIP_NET_IMPL_NAME           "ms_lwip_net"
#define MS_LWIP_SOCKET_DRV_NAME         "ms_lwip_socket"

static ms_bool_t ms_lwip_inited        = MS_FALSE;
ms_printf_func_t ms_lwip_platform_diag = ms_printf;

/*
 * Get the name of netif
 */
char *netif_get_name(struct netif *netif, char *name)
{
    if (netif != MS_NULL) {
        name[0] = netif->name[0];
        name[1] = netif->name[1];
        lwip_itoa(&name[2], NETIF_NAMESIZE - 2, netif->num);
        return name;
    }

    return MS_NULL;
}

/*
 * Get the total number of netif
 */
u32_t netif_get_total(void)
{
    u32_t total = 0;
    struct netif *netif;

    NETIF_FOREACH(netif) {
        total++;
    }

    return total;
}

/*
 * Get the flags of netif
 */
u32_t netif_get_flags(struct netif *pnetif)
{
    u32_t flags = 0;

    if (pnetif->flags & NETIF_FLAG_UP) {
        flags |= IFF_UP;
    }
    if (pnetif->flags & NETIF_FLAG_BROADCAST) {
        flags |= IFF_BROADCAST;
    } else {
        flags |= IFF_POINTOPOINT;
    }
    if (pnetif->flags & NETIF_FLAG_LINK_UP) {
        flags |= IFF_RUNNING;
    }
    if (pnetif->flags & NETIF_FLAG_IGMP) {
        flags |= IFF_MULTICAST;
    }
    if ((pnetif->flags & NETIF_FLAG_ETHARP) == 0) {
        flags |= IFF_NOARP;
    }
    if (pnetif->link_type == snmp_ifType_softwareLoopback) {
        flags |= IFF_LOOPBACK;
    }
    if ((pnetif->flags2 & NETIF_FLAG2_PROMISC)) {
        flags |= IFF_PROMISC;
    }
    if ((pnetif->flags2 & NETIF_FLAG2_ALLMULTI)) {
        flags |= IFF_ALLMULTI;
    }

    return  (flags);
}

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
static int __ms_lwip_socket_ioctl(ms_ptr_t ctx, ms_io_file_t *file, int cmd, ms_ptr_t arg)
{
    int ret;

    switch (cmd) {
#if MS_LWIP_NETIF_CTL_EN > 0
    case SIOCGSIZIFCONF:
    case SIOCGIFNUM:
    case SIOCGIFCONF:
    case SIOCSIFADDR:
    case SIOCSIFNETMASK:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
    case SIOCSIFGATEWAY:
    case SIOCSIFFLAGS:
    case SIOCGIFADDR:
    case SIOCGIFNETMASK:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
    case SIOCGIFGATEWAY:
    case SIOCGIFFLAGS:
    case SIOCGIFTYPE:
    case SIOCGIFNAME:
    case SIOCGIFINDEX:
    case SIOCGIFMTU:
    case SIOCSIFMTU:
    case SIOCGIFHWADDR:
    case SIOCSIFHWADDR:
    case SIOCGIFMETRIC:
    case SIOCSIFMETRIC:
    case SIOCDIFADDR:
    case SIOCAIFADDR:
    case SIOCADDMULTI:
    case SIOCDELMULTI:
    case SIOCGIFTCPAF:
    case SIOCSIFTCPAF:
    case SIOCGIFTCPWND:
    case SIOCSIFTCPWND:
    case SIOCGIFPFLAGS:
    case SIOCSIFPFLAGS:
    case SIOCGSIZIFREQ6:
    case SIOCSIFADDR6:
    case SIOCSIFNETMASK6:
    case SIOCSIFDSTADDR6:
    case SIOCGIFADDR6:
    case SIOCGIFNETMASK6:
    case SIOCGIFDSTADDR6:
    case SIOCDIFADDR6:
    case SIOCGIFSTATS:
        ret = __ms_lwip_if_ioctl_inet(cmd, arg);
        break;
#endif

    default:
        ret = lwip_ioctl((int)ctx, cmd, arg);
        break;
    }

    return ret;
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

/*
 * Create socket
 */
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

/*
 * Do accept
 */
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

/*
 * Get the host name
 */
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

/*
 * Set the host name
 */
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

#include "ms_shell_cfg.h"

#if (MS_CFG_SHELL_MODULE_EN > 0) && (MS_CFG_NET_SHELL_CMD_EN > 0)

#include "ms_shell.h"

#if (LWIP_STATS > 0U) && (LWIP_STATS_DISPLAY > 0U)
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
MS_SHELL_CMD(lwipstat, __ms_shell_lwip_stat, "Show lwIP network statistics", __ms_shell_cmd_lwip_stat);
#endif

static void  __ms_lwip_speed_string(struct netif *netif, char *speed_str, size_t size)
{
    u64_t speed = netif->link_speed;

    if (speed == 0) {
        strlcpy(speed_str, "N/A", size);

    } else if (speed < 1000ull) {
        ms_snprintf(speed_str, size, "%qu bps", speed);

    } else if (speed < 5000000ull) {
        ms_snprintf(speed_str, size, "%qu Kbps", speed / 1000);

    } else if (speed < 5000000000ull) {
        ms_snprintf(speed_str, size, "%qu Mbps", speed / 1000000);

    } else {
        ms_snprintf(speed_str, size, "%qu Gbps", speed / 1000000000);
    }
}

static char *__ms_lwip_octets(u64_t value, char *buffer, size_t size)
{
    if (value > (1024 * 1024 * 1024)) {
        value = (value >> 20);
        ms_snprintf(buffer, size, "%qu.%qu GB", (value >> 10), (value & 0x3ff) / 102);

    } else if (value > (1024 * 1024)) {
        value = (value >> 10);
        ms_snprintf(buffer, size, "%qu.%qu MB", (value >> 10), (value & 0x3ff) / 102);

    } else if (value > 1024) {
        ms_snprintf(buffer, size, "%qu.%qu KB", (value >> 10), (value & 0x3ff) / 102);

    } else {
        ms_snprintf(buffer, size, "%qu.0 B", value);
    }

    return  (buffer);
}

/**
 * @brief lwIP netif show.
 *
 * @param[in] netif Pointer to lwIP netif
 * @param[in] io Pointer to shell io driver
 *
 * @return N/A
 */
static void __ms_lwip_netif_show(struct netif *netif, const ms_shell_io_t *io)
{
#define MIB2_NETIF(netif)   (&((netif)->mib2_counters))
    char             if_name[NETIF_NAMESIZE];
    char             buffer1[32];
    char             buffer2[32];
    const char *     dev_name = "N/A";
    ip4_addr_t       broadcast_addr;
    int              i, flags;

    io->_printf("%-5s%4s ", netif_get_name(netif, if_name), "");        /*  网卡名称                    */

    if (netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {     /*  以太网络                    */
        io->_printf("Link encap: Ethernet HWaddr: ");
        for (i = 0; i < netif->hwaddr_len - 1; i++) {
            io->_printf("%02x:", netif->hwaddr[i]);
        }
        io->_printf("%02x\n", netif->hwaddr[netif->hwaddr_len - 1]);

    } else {
        if ((netif->flags & NETIF_FLAG_BROADCAST) == 0) {               /*  点对点网络接口              */
            if (netif->link_type == snmp_ifType_softwareLoopback) {
                io->_printf("Link encap: Local Loopback\n");
            } else if (netif->link_type == snmp_ifType_ppp) {
                io->_printf("Link encap: PPP Link\n");
            } else if (netif->link_type == snmp_ifType_slip) {
                io->_printf("Link encap: SLIP Link\n");
            } else {
                io->_printf("Link encap: General\n");
            }

        } else {                                                        /*  通用网络接口                */
            io->_printf("Link encap: General\n");
        }
    }

    __ms_lwip_speed_string(netif, buffer1, sizeof(buffer1));

#if MS_LWIP_NETIF_MIP_EN > 0
    if (netif_is_mipif(netif)) {
        io->_printf("%9s Mif: %s Ifidx: %d ", "",
               netif_get_name(netif_get_masterif(netif), if_name), netif_get_index(netif));
    } else
#endif                                                                  /*  MS_LWIP_NETIF_MIP_EN        */
    {
        io->_printf("%9s Dev: %s Ifidx: %d ", "",
               dev_name, netif_get_index(netif));
    }

#if LWIP_DHCP
    io->_printf("DHCP: %s%s %s%s Spd: %s\n",
           (netif->flags2 & NETIF_FLAG2_DHCP) ? "E4" : "D4",
           (netif->flags2 & NETIF_FLAG2_DHCP) ? ((netif_dhcp_data(netif)) ? "(On)" : "(Off)") : "",
#if LWIP_IPV6_DHCP6
           (netif->flags2 & NETIF_FLAG2_DHCP6) ? "E6" : "D6",
           (netif->flags2 & NETIF_FLAG2_DHCP6) ? ((netif_dhcp6_data(netif)) ? "(On)" : "(Off)") : "",
#else
           "", "",
#endif                                                                  /*  LWIP_IPV6_DHCP6             */
           buffer1);
#else
    io->_printf("Spd: %s\n", cBuffer1);
#endif                                                                  /*  LWIP_DHCP                   */

    io->_printf("%9s inet addr: %d.%d.%d.%d ", "",
           ip4_addr1(netif_ip4_addr(netif)), ip4_addr2(netif_ip4_addr(netif)),
           ip4_addr3(netif_ip4_addr(netif)), ip4_addr4(netif_ip4_addr(netif)));
    io->_printf("netmask: %d.%d.%d.%d\n",
           ip4_addr1(netif_ip4_netmask(netif)), ip4_addr2(netif_ip4_netmask(netif)),
           ip4_addr3(netif_ip4_netmask(netif)), ip4_addr4(netif_ip4_netmask(netif)));

    if ((netif->flags & NETIF_FLAG_BROADCAST) == 0) {
        io->_printf("%9s P-to-P: %d.%d.%d.%d ", "",
               ip4_addr1(netif_ip4_gw(netif)), ip4_addr2(netif_ip4_gw(netif)),
               ip4_addr3(netif_ip4_gw(netif)), ip4_addr4(netif_ip4_gw(netif)));
        io->_printf("broadcast: N/A\n");

    } else {
        io->_printf("%9s gateway: %d.%d.%d.%d ", "",
               ip4_addr1(netif_ip4_gw(netif)), ip4_addr2(netif_ip4_gw(netif)),
               ip4_addr3(netif_ip4_gw(netif)), ip4_addr4(netif_ip4_gw(netif)));
        broadcast_addr.addr = (netif_ip4_addr(netif)->addr | (~netif_ip4_netmask(netif)->addr));
        io->_printf("broadcast: %d.%d.%d.%d\n",
               ip4_addr1(&broadcast_addr), ip4_addr2(&broadcast_addr),
               ip4_addr3(&broadcast_addr), ip4_addr4(&broadcast_addr));
    }

#if LWIP_IPV6
    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        const char *addr_type;
        char        buffer[64];

        if (ip6_addr_isglobal(ip_2_ip6(&netif->ip6_addr[i]))) {
            addr_type = "Global";
        } else if (ip6_addr_islinklocal(ip_2_ip6(&netif->ip6_addr[i]))) {
            addr_type = "Link";
        } else if (ip6_addr_issitelocal(ip_2_ip6(&netif->ip6_addr[i]))) {
            addr_type = "Site";
        } else if (ip6_addr_isuniquelocal(ip_2_ip6(&netif->ip6_addr[i]))) {
            addr_type = "Unique";
        } else if (ip6_addr_isloopback(ip_2_ip6(&netif->ip6_addr[i]))) {
            addr_type = "Loopback";
        } else {
            addr_type = "Unknown";
        }

        if (ip6_addr_isvalid(netif->ip6_addr_state[i])) {
            io->_printf("%9s inet6 addr: %s Scope:%s\n", "",
                   ip6addr_ntoa_r(ip_2_ip6(&netif->ip6_addr[i]), buffer, sizeof(buffer)),
                   addr_type);

        } else if (ip6_addr_istentative(netif->ip6_addr_state[i])) {
            io->_printf("%9s inet6 addr: %s Scope:%s<T%d>\n", "",
                   ip6addr_ntoa_r(ip_2_ip6(&netif->ip6_addr[i]), buffer, sizeof(buffer)),
                   addr_type, (netif->ip6_addr_state[i] & IP6_ADDR_TENTATIVE_7) - 8);
        }
    }
#endif                                                                  /*  LWIP_IPV6                   */

    io->_printf("%9s ", "");
    flags = netif_get_flags(netif);
    if (flags & IFF_UP) {
        io->_printf("UP ");
    }
    if (flags & IFF_BROADCAST) {
        io->_printf("BROADCAST ");
    }
    if (flags & IFF_LOOPBACK) {
        io->_printf("LOOPBACK ");
    }
    if (flags & IFF_RUNNING) {
        io->_printf("RUNNING ");
    }
    if (flags & IFF_MULTICAST) {
        io->_printf("MULTICAST ");
    }
    if (netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) {
        if (flags & IFF_NOARP) {
            io->_printf("NOARP ");
        }
    }
    io->_printf(" MTU:%d  Metric:%d\n", netif->mtu, netif->metric);

    if (!netif_is_mipif(netif)) {
        io->_printf("%9s noproto:%u\n", "",
                (unsigned)MIB2_NETIF(netif)->ifinunknownprotos);

        io->_printf("%9s RX ucast packets:%u nucast packets:%u dropped:%u\n", "",
                (unsigned)MIB2_NETIF(netif)->ifinucastpkts, (unsigned)MIB2_NETIF(netif)->ifinnucastpkts, (unsigned)MIB2_NETIF(netif)->ifindiscards);
        io->_printf("%9s TX ucast packets:%u nucast packets:%u dropped:%u\n", "",
                (unsigned)MIB2_NETIF(netif)->ifoutucastpkts, (unsigned)MIB2_NETIF(netif)->ifoutnucastpkts, (unsigned)MIB2_NETIF(netif)->ifoutdiscards);
        io->_printf("%9s RX bytes:%qu (%s)  TX bytes:%qu (%s)\n", "",
               MIB2_NETIF(netif)->ifinoctets,
               __ms_lwip_octets(MIB2_NETIF(netif)->ifinoctets, buffer1, sizeof(buffer1)),
               MIB2_NETIF(netif)->ifoutoctets,
               __ms_lwip_octets(MIB2_NETIF(netif)->ifoutoctets, buffer2, sizeof(buffer2)));
    }
    io->_printf("\n");
}

/**
 * @brief lwIP netifs command.
 *
 * @param[in] argc Arguments count
 * @param[in] argv Arguments array
 * @param[in] io Pointer to shell io driver
 *
 * @return N/A
 */
static void __ms_shell_lwip_netifs(int argc, char *argv[], const ms_shell_io_t *io)
{
    if (ms_lwip_inited) {
        struct netif *netif;

        NETIF_FOREACH(netif) {
            __ms_lwip_netif_show(netif, io);
        }
    } else {
        io->_printf("lwIP no init!\n");
    }
}

MS_SHELL_CMD(netifs,   __ms_shell_lwip_netifs, "Show all lwIP netif info", __ms_shell_cmd_lwip_netifs);

#endif
