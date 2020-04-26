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
#include "lwip/netifapi.h"

typedef int   INT;
typedef void  VOID;
typedef void *PVOID;

#define PX_ERROR                        -1
#define ERROR_NONE                      0
#define LW_NULL                         MS_NULL

#define _ErrorHandle(err)               ms_thread_set_errno(err)
#define LWIP_IF_LIST_LOCK(write)        LOCK_TCPIP_CORE()
#define LWIP_IF_LIST_UNLOCK()           UNLOCK_TCPIP_CORE()
#define __ifIoctlInet                   __ms_lwip_if_ioctl_inet

/**
* @ingroup netif
* Get netif name by struct netif
*
* @param netif
* @param netif name buffer
*/
static char *
netif_get_name(struct netif *netif, char *name) /* SylixOS Add this function */
{
  if (netif != NULL) {
    name[0] = netif->name[0];
    name[1] = netif->name[1];
    lwip_itoa(&name[2], NETIF_NAMESIZE - 2, netif->num);
    return name;
  }
  return NULL;
}

/**
* @ingroup netif
* Get netif total num
*/
static unsigned int
netif_get_total(void)
{
  unsigned int total = 0;
  struct netif *netif;

  NETIF_FOREACH(netif) {
    total++;
  }

  return total;
}
/*********************************************************************************************************
** 函数名称: netif_get_flags
** 功能描述: 获得网络接口 flags
** 输　入  : 网络接口
** 输　出  : flags
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  netif_get_flags (struct netif *pnetif)
{
    INT  iFlags = 0;

    if (pnetif->flags & NETIF_FLAG_UP) {
        iFlags |= IFF_UP;
    }
    if (pnetif->flags & NETIF_FLAG_BROADCAST) {
        iFlags |= IFF_BROADCAST;
    } else {
        iFlags |= IFF_POINTOPOINT;
    }
    if (pnetif->flags & NETIF_FLAG_LINK_UP) {
        iFlags |= IFF_RUNNING;
    }
    if (pnetif->flags & NETIF_FLAG_IGMP) {
        iFlags |= IFF_MULTICAST;
    }
    if ((pnetif->flags & NETIF_FLAG_ETHARP) == 0) {
        iFlags |= IFF_NOARP;
    }
    if (pnetif->link_type == snmp_ifType_softwareLoopback) {
        iFlags |= IFF_LOOPBACK;
    }
    if ((pnetif->flags2 & NETIF_FLAG2_PROMISC)) {
        iFlags |= IFF_PROMISC;
    }
    if ((pnetif->flags2 & NETIF_FLAG2_ALLMULTI)) {
        iFlags |= IFF_ALLMULTI;
    }

    return  (iFlags);
}
/*********************************************************************************************************
** 函数名称: __ifConfSize
** 功能描述: 获得网络接口列表保存所需要的内存大小
** 输　入  : piSize    所需内存大小
** 输　出  : NONE
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static VOID __ifConfSize (INT  *piSize)
{
           INT       iNum = 0;
    struct netif    *pnetif;

    NETIF_FOREACH(pnetif) {
        iNum += sizeof(struct ifreq);
    }

    *piSize = iNum;
}
/*********************************************************************************************************
** 函数名称: __ifConf
** 功能描述: 获得网络接口列表操作
** 输　入  : pifconf   列表保存缓冲
** 输　出  : PX_ERROR or ERROR_NONE
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT __ifConf (struct ifconf  *pifconf)
{
           INT           iSize;
           INT           iNum = 0;
    struct netif        *pnetif;
    struct ifreq        *pifreq;
    struct sockaddr_in  *psockaddrin;

    if (!pifconf->ifc_req) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    iSize  = pifconf->ifc_len / sizeof(struct ifreq);                   /*  缓冲区个数                  */
    pifreq = pifconf->ifc_req;

    NETIF_FOREACH(pnetif) {
        if (iNum >= iSize) {
            break;
        }
        netif_get_name(pnetif, pifreq->ifr_name);
        psockaddrin = (struct sockaddr_in *)&(pifreq->ifr_addr);
        psockaddrin->sin_len    = sizeof(struct sockaddr_in);
        psockaddrin->sin_family = AF_INET;
        psockaddrin->sin_port   = 0;
        psockaddrin->sin_addr.s_addr = netif_ip4_addr(pnetif)->addr;

        iNum++;
        pifreq++;
    }

    pifconf->ifc_len = iNum * sizeof(struct ifreq);                     /*  读取个数                    */

    return  (ERROR_NONE);
}
/*********************************************************************************************************
** 函数名称: __ifReq6Size
** 功能描述: 获得网络接口 IPv6 地址数目
** 输　入  : ifreq6    ifreq6 请求控制块
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
#if LWIP_IPV6

static INT __ifReq6Size (struct in6_ifreq  *pifreq6)
{
    INT              i;
    INT              iNum   = 0;
    struct netif    *pnetif = netif_get_by_index(pifreq6->ifr6_ifindex);

    if (pnetif == LW_NULL) {
        _ErrorHandle(EADDRNOTAVAIL);                                    /*  未找到指定的网络接口        */
        return  (PX_ERROR);
    }

    for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(pnetif->ip6_addr_state[i])) {
            iNum++;
        }
    }

    pifreq6->ifr6_len = iNum * sizeof(struct in6_ifr_addr);             /*  回写实际大小                */

    return  (ERROR_NONE);
}

#endif                                                                  /*  LWIP_IPV6                   */
/*********************************************************************************************************
** 函数名称: __ifSubIoctlIf
** 功能描述: 网络接口 ioctl 操作 (针对网卡接口)
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __ifSubIoctlIf (INT  iCmd, PVOID  pvArg)
{
    INT              i, iIsUp, iFlags;
    INT              iRet   = PX_ERROR;
    struct ifreq    *pifreq = LW_NULL;
    struct netif    *pnetif;

    pifreq = (struct ifreq *)pvArg;

    pnetif = netif_find(pifreq->ifr_name);
    if (pnetif == LW_NULL) {
        _ErrorHandle(EADDRNOTAVAIL);                                    /*  未找到指定的网络接口        */
        return  (iRet);
    }

    switch (iCmd) {

    case SIOCGIFFLAGS:                                                  /*  获取网卡 flag               */
        pifreq->ifr_flags = netif_get_flags(pnetif);
        iRet = ERROR_NONE;
        break;

    case SIOCSIFFLAGS:                                                  /*  设置网卡 flag               */
        iFlags = netif_get_flags(pnetif);
        if (iFlags != pifreq->ifr_flags) {
            if (!pnetif->ioctl) {
                break;
            }
            iRet = pnetif->ioctl(pnetif, SIOCSIFFLAGS, pvArg);
            if (iRet < ERROR_NONE) {
                break;
            }
            if (pifreq->ifr_flags & IFF_PROMISC) {
                pnetif->flags2 |= NETIF_FLAG2_PROMISC;
            } else {
                pnetif->flags2 |= ~NETIF_FLAG2_PROMISC;
            }
            if (pifreq->ifr_flags & IFF_ALLMULTI) {
                pnetif->flags2 |= NETIF_FLAG2_ALLMULTI;
            } else {
                pnetif->flags2 |= ~NETIF_FLAG2_ALLMULTI;
            }
            if (pifreq->ifr_flags & IFF_UP) {
                netifapi_netif_set_up(pnetif);
            } else {
                netifapi_netif_set_down(pnetif);
            }
        }
        iRet = ERROR_NONE;
        break;

    case SIOCGIFTYPE:                                                   /*  获得网卡类型                */
        if ((pnetif->flags & NETIF_FLAG_BROADCAST) == 0) {
            pifreq->ifr_type = IFT_PPP;
        } else if (pnetif->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP)) {
            pifreq->ifr_type = IFT_ETHER;
        } else if (ip4_addr_isloopback(netif_ip4_addr(pnetif))) {
            pifreq->ifr_type = IFT_LOOP;
        } else {
            pifreq->ifr_type = IFT_OTHER;
        }
        iRet = ERROR_NONE;
        break;

    case SIOCGIFINDEX:                                                  /*  获得网卡 index              */
        pifreq->ifr_ifindex = netif_get_index(pnetif);
        iRet = ERROR_NONE;
        break;

    case SIOCGIFMTU:                                                    /*  获得网卡 mtu                */
        pifreq->ifr_mtu = pnetif->mtu;
        iRet = ERROR_NONE;
        break;

    case SIOCSIFMTU:                                                    /*  设置网卡 mtu                */
        if (pifreq->ifr_mtu != pnetif->mtu) {
            if (pnetif->ioctl) {
                if (pnetif->ioctl(pnetif, SIOCSIFMTU, pvArg) == 0) {
                    pnetif->mtu = pifreq->ifr_mtu;
                    iRet = ERROR_NONE;
                }
            } else {
                _ErrorHandle(ENOSYS);
            }
        } else {
            iRet = ERROR_NONE;
        }
        break;

    case SIOCGIFHWADDR:                                                 /*  获得物理地址                */
        if (pnetif->hwaddr_len && (pnetif->hwaddr_len <= IFHWADDR_MAXLEN)) {
            if (pnetif->ar_hrd != ARPHRD_VOID) {
                pifreq->ifr_hwaddr.sa_len    = pnetif->ar_hrd >> 8;
                pifreq->ifr_hwaddr.sa_family = pnetif->ar_hrd & 0xff;   /*  设置网卡地址类型            */
            } else {
                pifreq->ifr_hwaddr.sa_len    = 0;
                pifreq->ifr_hwaddr.sa_family = ARPHRD_ETHER;
            }
            for (i = 0; i < pnetif->hwaddr_len; i++) {
                pifreq->ifr_hwaddr.sa_data[i] = pnetif->hwaddr[i];
            }
            HALALEN_FROM_SA(&pifreq->ifr_hwaddr) = pnetif->hwaddr_len;
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCSIFHWADDR:                                                 /*  设置 mac 地址               */
        if (pnetif->hwaddr_len && (pnetif->hwaddr_len <= IFHWADDR_MAXLEN)) {
            iIsUp = netif_is_up(pnetif);
            if (pnetif->ioctl) {
                netifapi_netif_set_down(pnetif);                        /*  关闭网口                    */
                iRet = pnetif->ioctl(pnetif, SIOCSIFHWADDR, pvArg);
                if (iRet == ERROR_NONE) {
                    for (i = 0; i < pnetif->hwaddr_len; i++) {
                        pnetif->hwaddr[i] = pifreq->ifr_hwaddr.sa_data[i];
                    }
                }
                if (iIsUp) {
                    netifapi_netif_set_up(pnetif);                      /*  重启网口                    */
                }
            } else {
                _ErrorHandle(ENOTSUP);
            }
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCGIFMETRIC:                                                 /*  获得网卡测度                */
        pifreq->ifr_metric = pnetif->metric;
        iRet = ERROR_NONE;
        break;

    case SIOCSIFMETRIC:                                                 /*  设置网卡测度                */
        pnetif->metric = pifreq->ifr_metric;                            /*  目前不做处理                */
        iRet = ERROR_NONE;
        break;

    case SIOCADDMULTI:                                                  /*  设置组播滤波器              */
    case SIOCDELMULTI:
        if (pnetif->ioctl) {
            iRet = pnetif->ioctl(pnetif, iCmd, pvArg);
        }
        break;

#if 0 /* TODO: 暂未实现 */
    case SIOCGIFTCPAF:                                                  /*  获得 tcp ack freq           */
        pifreq->ifr_tcpaf = netif_get_tcp_ack_freq(pnetif);
        iRet = ERROR_NONE;
        break;

    case SIOCSIFTCPAF:                                                  /*  设置 tcp ack freq           */
        if ((pifreq->ifr_tcpaf >= LWIP_NETIF_TCP_ACK_FREQ_MIN) &&
            (pifreq->ifr_tcpaf <= LWIP_NETIF_TCP_ACK_FREQ_MAX)) {
            netif_set_tcp_ack_freq(pnetif, (u8_t)pifreq->ifr_tcpaf);
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCGIFTCPWND:                                                 /*  获得 tcp window             */
        pifreq->ifr_tcpwnd = netif_get_tcp_wnd(pnetif);
        iRet = ERROR_NONE;
        break;

    case SIOCSIFTCPWND:                                                 /*  设置 tcp window             */
        if ((pifreq->ifr_tcpwnd <= (0xffffu << TCP_RCV_SCALE)) &&
            (pifreq->ifr_tcpwnd >= (2 * TCP_MSS))) {
            netif_set_tcp_wnd(pnetif, (u32_t)pifreq->ifr_tcpaf);
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCGIFPFLAGS:                                                 /*  获取私有 flags              */
        pifreq->ifr_flags = netif_get_priv_flags(pnetif);
        iRet = ERROR_NONE;
        break;

    case SIOCSIFPFLAGS:                                                 /*  设置私有 flags              */
        _ErrorHandle(ENOSYS);
        break;
#endif
    }

    return  (iRet);
}
/*********************************************************************************************************
** 函数名称: __ifSubIoctl4
** 功能描述: 网络接口 ioctl 操作 (针对 ipv4)
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __ifSubIoctl4 (INT  iCmd, PVOID  pvArg)
{
           INT           iRet   = PX_ERROR;
    struct ifreq        *pifreq = LW_NULL;
    struct netif        *pnetif;
    struct sockaddr_in  *psockaddrin;

    pifreq = (struct ifreq *)pvArg;

    pnetif = netif_find(pifreq->ifr_name);
    if (pnetif == LW_NULL) {
        _ErrorHandle(EADDRNOTAVAIL);                                    /*  未找到指定的网络接口        */
        return  (iRet);
    }

    switch (iCmd) {                                                     /*  命令预处理                  */

    case SIOCGIFADDR:                                                   /*  获取地址操作                */
    case SIOCGIFNETMASK:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
        psockaddrin = (struct sockaddr_in *)&(pifreq->ifr_addr);
        psockaddrin->sin_len    = sizeof(struct sockaddr_in);
        psockaddrin->sin_family = AF_INET;
        psockaddrin->sin_port   = 0;
        break;

    case SIOCSIFADDR:                                                   /*  设置地址操作                */
    case SIOCSIFNETMASK:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
        psockaddrin = (struct sockaddr_in *)&(pifreq->ifr_addr);
        break;

    default:
        return  (iRet);
    }

    switch (iCmd) {                                                     /*  命令处理器                  */

    case SIOCGIFADDR:                                                   /*  获取网卡 IP                 */
        psockaddrin->sin_addr.s_addr = netif_ip4_addr(pnetif)->addr;
        iRet = ERROR_NONE;
        break;

    case SIOCGIFNETMASK:                                                /*  获取网卡 mask               */
        psockaddrin->sin_addr.s_addr = netif_ip4_netmask(pnetif)->addr;
        iRet = ERROR_NONE;
        break;

    case SIOCGIFDSTADDR:                                                /*  获取网卡目标地址            */
        if ((pnetif->flags & NETIF_FLAG_BROADCAST) == 0) {
            psockaddrin->sin_addr.s_addr = netif_ip4_gw(pnetif)->addr;
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCGIFBRDADDR:                                                /*  获取网卡广播地址            */
        if (pnetif->flags & NETIF_FLAG_BROADCAST) {
            psockaddrin->sin_addr.s_addr = (netif_ip4_addr(pnetif)->addr
                                         | (~(netif_ip4_netmask(pnetif)->addr)));
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCSIFADDR:                                                   /*  设置网卡地址                */
        if (psockaddrin->sin_family == AF_INET) {
            ip4_addr_t ipaddr;
            ipaddr.addr = psockaddrin->sin_addr.s_addr;
            LOCK_TCPIP_CORE();                                          /*  必须 lock 协议栈            */
            netif_set_ipaddr(pnetif, &ipaddr);
            UNLOCK_TCPIP_CORE();
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EAFNOSUPPORT);
        }
        break;

    case SIOCSIFNETMASK:                                                /*  设置网卡掩码                */
        if (psockaddrin->sin_family == AF_INET) {
            ip4_addr_t ipaddr;
            ipaddr.addr = psockaddrin->sin_addr.s_addr;
            LOCK_TCPIP_CORE();                                          /*  必须 lock 协议栈            */
            netif_set_netmask(pnetif, &ipaddr);
            UNLOCK_TCPIP_CORE();
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EAFNOSUPPORT);
        }
        break;

    case SIOCSIFDSTADDR:                                                /*  设置网卡目标地址            */
        if ((pnetif->flags & NETIF_FLAG_BROADCAST) == 0) {
            ip4_addr_t ipaddr;
            ipaddr.addr = psockaddrin->sin_addr.s_addr;
            LOCK_TCPIP_CORE();                                          /*  必须 lock 协议栈            */
            netif_set_gw(pnetif, &ipaddr);
            UNLOCK_TCPIP_CORE();
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;

    case SIOCSIFBRDADDR:                                                /*  设置网卡广播地址            */
        if (pnetif->flags & NETIF_FLAG_BROADCAST) {
            iRet = ERROR_NONE;
        } else {
            _ErrorHandle(EINVAL);
        }
        break;
    }

    return  (iRet);
}
/*********************************************************************************************************
** 函数名称: __ifSubIoctl6
** 功能描述: 网络接口 ioctl 操作 (针对 ipv6)
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
#if LWIP_IPV6

static INT  __ifSubIoctl6 (INT  iCmd, PVOID  pvArg)
{
           INT           i;
           INT           iSize;
           INT           iNum = 0;
           INT           iRet = PX_ERROR;
           ip6_addr_t    ip6addr;
    struct in6_ifreq    *pifreq6 = LW_NULL;
    struct in6_ifr_addr *pifr6addr;
    struct netif        *pnetif;
           s8_t          idx;
           err_t         err;

    pifreq6 = (struct in6_ifreq *)pvArg;

    pnetif = netif_get_by_index(pifreq6->ifr6_ifindex);
    if (pnetif == LW_NULL) {
        _ErrorHandle(EADDRNOTAVAIL);                                    /*  未找到指定的网络接口        */
        return  (iRet);
    }

#if 0 /* TODO: 暂未实现 */
    if (netif_is_mipif(pnetif)) {
        _ErrorHandle(ENOSYS);
        return  (iRet);
    }
#endif

    iSize = pifreq6->ifr6_len / sizeof(struct in6_ifr_addr);            /*  缓冲区个数                  */
    pifr6addr = pifreq6->ifr6_addr_array;

    switch (iCmd) {                                                     /*  命令处理器                  */

    case SIOCGIFADDR6:                                                  /*  获取网卡 IP                 */
        for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            if (iNum >= iSize) {
                break;
            }
            if (ip6_addr_isvalid(pnetif->ip6_addr_state[i])) {
                inet6_addr_from_ip6addr(&pifr6addr->ifr6a_addr, ip_2_ip6(&pnetif->ip6_addr[i]));
                if (ip6_addr_isloopback(ip_2_ip6(&pnetif->ip6_addr[i]))) {
                    pifr6addr->ifr6a_prefixlen = 128;
                } else if (ip6_addr_islinklocal(ip_2_ip6(&pnetif->ip6_addr[i]))) {
                    pifr6addr->ifr6a_prefixlen = 6;
                } else {
                    pifr6addr->ifr6a_prefixlen = 64;                    /*  TODO: 目前无法获取          */
                }
                iNum++;
                pifr6addr++;
            }
        }
        pifreq6->ifr6_len = iNum * sizeof(struct in6_ifr_addr);         /*  回写实际大小                */
        iRet = ERROR_NONE;
        break;

    case SIOCSIFADDR6:                                                  /*  添加一个 IPv6 地址          */
        if (iSize != 1) {                                               /*  每次只能设置一个 IP 地址    */
            _ErrorHandle(EOPNOTSUPP);
            break;
        }
        if (IN6_IS_ADDR_LOOPBACK(&pifr6addr->ifr6a_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&pifr6addr->ifr6a_addr)) {            /*  不能手动设置这两种类型的地址*/
            _ErrorHandle(EADDRNOTAVAIL);
            break;
        }
        inet6_addr_to_ip6addr(&ip6addr, &pifr6addr->ifr6a_addr);
        LOCK_TCPIP_CORE();                                              /*  必须 lock 协议栈            */
        err = netif_add_ip6_address(pnetif, &ip6addr, LW_NULL);
        UNLOCK_TCPIP_CORE();
        if (err) {
            _ErrorHandle(ENOSPC);
            break;
        }
        iRet = ERROR_NONE;
        break;

    case SIOCDIFADDR6:                                                  /*  删除一个 IPv6 地址          */
        if (iSize != 1) {                                               /*  每次只能设置一个 IP 地址    */
            _ErrorHandle(EOPNOTSUPP);
            break;
        }
        inet6_addr_to_ip6addr(&ip6addr, &pifr6addr->ifr6a_addr);
        LOCK_TCPIP_CORE();                                              /*  必须 lock 协议栈            */
        idx = netif_get_ip6_addr_match(pnetif, &ip6addr);
        if (idx >= 0) {
            netif_ip6_addr_set_state(pnetif, idx, IP6_ADDR_INVALID);
        }
        UNLOCK_TCPIP_CORE();
        if (idx < 0) {
            _ErrorHandle(EADDRNOTAVAIL);
            break;
        }
        iRet = ERROR_NONE;
        break;

    default:
        _ErrorHandle(ENOSYS);                                           /*  TODO: 其他命令暂未实现      */
        break;
    }

    return  (iRet);
}

#endif                                                                  /*  LWIP_IPV6                   */
/*********************************************************************************************************
** 函数名称: __ifSubIoctlStats
** 功能描述: INET 网络统计接口 ioctl 操作
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
INT  __ifSubIoctlStats (INT  iCmd, PVOID  pvArg)
{
#define MIB2_NETIF(netif)   (&((netif)->mib2_counters))

    INT                 iRet = PX_ERROR;
    struct ifstatreq   *pifstat;
    struct netif       *pnetif;

    pifstat = (struct ifstatreq *)pvArg;

    pnetif = netif_find(pifstat->ifrs_name);
    if (pnetif == LW_NULL) {
        _ErrorHandle(EADDRNOTAVAIL);                                    /*  未找到指定的网络接口        */
        return  (iRet);
    }

#if 0 /* TODO: 暂未实现 */
    if (netif_is_mipif(pnetif)) {
        pnetif = netif_get_masterif(pnetif);
        if (pnetif == LW_NULL) {
            _ErrorHandle(EADDRNOTAVAIL);                                /*  未找到指定的网络接口        */
            return  (iRet);
        }
    }
#endif

    switch (iCmd) {

    case SIOCGIFSTATS:
        pifstat->ifrs_mtu        = pnetif->mtu;
        pifstat->ifrs_collisions = 0;                                   /*  TODO: 暂未实现              */
        pifstat->ifrs_baudrate   = pnetif->link_speed;
        pifstat->ifrs_ipackets   = MIB2_NETIF(pnetif)->ifinucastpkts + MIB2_NETIF(pnetif)->ifinnucastpkts;
        pifstat->ifrs_ierrors    = MIB2_NETIF(pnetif)->ifinerrors;
        pifstat->ifrs_opackets   = MIB2_NETIF(pnetif)->ifoutucastpkts + MIB2_NETIF(pnetif)->ifoutnucastpkts;
        pifstat->ifrs_oerrors    = MIB2_NETIF(pnetif)->ifouterrors;
        pifstat->ifrs_ibytes     = MIB2_NETIF(pnetif)->ifinoctets;
        pifstat->ifrs_obytes     = MIB2_NETIF(pnetif)->ifoutoctets;
        pifstat->ifrs_imcasts    = MIB2_NETIF(pnetif)->ifinnucastpkts;
        pifstat->ifrs_omcasts    = MIB2_NETIF(pnetif)->ifoutnucastpkts;
        pifstat->ifrs_iqdrops    = MIB2_NETIF(pnetif)->ifindiscards;
        pifstat->ifrs_noproto    = MIB2_NETIF(pnetif)->ifinunknownprotos;
        pifstat->ifrs_baudrate   = pnetif->link_speed;
        iRet = ERROR_NONE;
        break;
    }

    return  (iRet);
}
/*********************************************************************************************************
** 函数名称: __ifSubIoctlCommon
** 功能描述: 通用网络接口 ioctl 操作
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __ifSubIoctlCommon (INT  iCmd, PVOID  pvArg)
{
    INT     iRet = PX_ERROR;

    switch (iCmd) {

    case SIOCGIFCONF: {                                                 /*  获得网卡列表                */
            struct ifconf *pifconf = (struct ifconf *)pvArg;
            iRet = __ifConf(pifconf);
            break;
        }

    case SIOCGIFNUM: {                                                  /*  获得网络接口数量            */
            if (pvArg) {
                *(INT *)pvArg = (INT)netif_get_total();
                iRet = ERROR_NONE;
            } else {
                _ErrorHandle(EINVAL);
            }
            break;
        }

    case SIOCGSIZIFCONF: {                                              /*  SIOCGIFCONF 所需缓冲大小    */
            INT  *piSize = (INT *)pvArg;
            __ifConfSize(piSize);
            iRet = ERROR_NONE;
            break;
        }

#if LWIP_IPV6
    case SIOCGSIZIFREQ6: {                                              /*  获得指定网口 ipv6 地址数量  */
            struct in6_ifreq *pifreq6 = (struct in6_ifreq *)pvArg;
            iRet = __ifReq6Size(pifreq6);
            break;
        }
#endif                                                                  /*  LWIP_IPV6                   */
    }

    return  (iRet);
}
/*********************************************************************************************************
** 函数名称: __ifIoctlInet
** 功能描述: INET 网络接口 ioctl 操作
** 输　入  : iCmd      命令
**           pvArg     参数
** 输　出  : 处理结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
INT  __ifIoctlInet (INT  iCmd, PVOID  pvArg)
{
    INT     iRet = PX_ERROR;

    if (pvArg == LW_NULL) {
        _ErrorHandle(EINVAL);
        return  (iRet);
    }

    if (iCmd == SIOCGIFNAME) {                                          /*  获得网卡名                  */
        struct ifreq *pifreq = (struct ifreq *)pvArg;
        if (if_indextoname(pifreq->ifr_ifindex, pifreq->ifr_name)) {
            iRet = ERROR_NONE;
        }
        return  (iRet);
    }

    switch (iCmd) {                                                     /*  命令预处理                  */

    case SIOCGIFCONF:                                                   /*  通用网络接口操作            */
    case SIOCGIFNUM:
    case SIOCGSIZIFCONF:
#if LWIP_IPV6
    case SIOCGSIZIFREQ6:
#endif
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctlCommon(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;

    case SIOCSIFFLAGS:                                                  /*  基本网络接口操作            */
    case SIOCGIFFLAGS:
    case SIOCGIFTYPE:
    case SIOCGIFINDEX:
    case SIOCGIFMTU:
    case SIOCSIFMTU:
    case SIOCGIFHWADDR:
    case SIOCSIFHWADDR:
    case SIOCGIFMETRIC:
    case SIOCSIFMETRIC:
    case SIOCADDMULTI:
    case SIOCDELMULTI:
    case SIOCGIFTCPAF:
    case SIOCSIFTCPAF:
    case SIOCGIFTCPWND:
    case SIOCSIFTCPWND:
    case SIOCGIFPFLAGS:
    case SIOCSIFPFLAGS:
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctlIf(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;

    case SIOCGIFADDR:                                                   /*  ipv4 操作                   */
    case SIOCGIFNETMASK:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
    case SIOCSIFADDR:
    case SIOCSIFNETMASK:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctl4(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;

#if 0 /* TODO: 暂未实现 */
    case SIOCDIFADDR:
        LWIP_IF_LIST_LOCK(LW_TRUE);                                     /*  进入临界区                  */
        iRet = __ifSubIoctlAlias4(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;

    case SIOCAIFADDR:
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctlAlias4(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;
#endif

#if LWIP_IPV6
    case SIOCGIFADDR6:                                                  /*  ipv6 操作                   */
    case SIOCGIFNETMASK6:
    case SIOCGIFDSTADDR6:
    case SIOCSIFADDR6:
    case SIOCSIFNETMASK6:
    case SIOCSIFDSTADDR6:
    case SIOCDIFADDR6:
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctl6(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;
#endif                                                                  /*  LWIP_IPV6                   */

    case SIOCGIFSTATS:                                                  /*  网络统计                    */
        LWIP_IF_LIST_LOCK(LW_FALSE);                                    /*  进入临界区                  */
        iRet = __ifSubIoctlStats(iCmd, pvArg);
        LWIP_IF_LIST_UNLOCK();                                          /*  退出临界区                  */
        break;

    default:
        _ErrorHandle(ENOSYS);
        break;
    }

    return  (iRet);
}
