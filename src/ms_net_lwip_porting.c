/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: ms_net_lwip_porting.h lwIP porting.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#define __MS_NET
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/stats.h"

/**
 * @brief lwIP porting.
 */

static ms_handle_t  ms_lwip_core_lockid;

#if LWIP_COMPAT_MUTEX == 0
/**
 * @ingroup sys_mutex
 * Create a new mutex.
 * Note that mutexes are expected to not be taken recursively by the lwIP code,
 * so both implementation types (recursive or non-recursive) should work.
 * The mutex is allocated to the memory that 'mutex'
 * points to (which can be both a pointer or the actual OS structure).
 * If the mutex has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 *
 * @param mutex pointer to the mutex to create
 * @return ERR_OK if successful, another err_t otherwise
 */
err_t sys_mutex_new(sys_mutex_t *mutex)
{
    err_t ret;

    if (ms_mutex_create("lwip_mutex", MS_WAIT_TYPE_PRIO, mutex) == MS_ERR_NONE) {

#if SYS_STATS
        ++lwip_stats.sys.mutex.used;
        if (lwip_stats.sys.mutex.max < lwip_stats.sys.mutex.used) {
            lwip_stats.sys.mutex.max = lwip_stats.sys.mutex.used;
        }
#endif /* SYS_STATS */

        ret = ERR_OK;

    } else {
        ms_printk(MS_PK_ERR, "Failed to create lwip mutex!\n");

#if SYS_STATS
        ++lwip_stats.sys.mutex.err;
#endif /* SYS_STATS */

        ret = ERR_MEM;
    }

    return ret;
}

/**
 * @ingroup sys_mutex
 * Blocks the thread until the mutex can be grabbed.
 * @param mutex the mutex to lock
 */
void sys_mutex_lock(sys_mutex_t *mutex)
{
    while (ms_mutex_lock(*mutex, MS_TIMEOUT_FOREVER) != MS_ERR_NONE) {
    }
}

/**
 * @ingroup sys_mutex
 * Releases the mutex previously locked through 'sys_mutex_lock()'.
 * @param mutex the mutex to unlock
 */
void sys_mutex_unlock(sys_mutex_t *mutex)
{
    (void)ms_mutex_unlock(*mutex);
}

/**
 * @ingroup sys_mutex
 * Deallocates a mutex.
 * @param mutex the mutex to delete
 */
void sys_mutex_free(sys_mutex_t *mutex)
{
    (void)ms_mutex_destroy(*mutex);

#if SYS_STATS
    --lwip_stats.sys.mutex.used;
#endif /* SYS_STATS */
}

/**
 * @ingroup sys_mutex
 * Returns 1 if the mutes is valid, 0 if it is not valid.
 * When using pointers, a simple way is to check the pointer for != NULL.
 * When directly using OS structures, implementing this may be more complex.
 * This may also be a define, in which case the function is not prototyped.
 */
int sys_mutex_valid(sys_mutex_t *mutex)
{
    int ret;

    if (*mutex == SYS_MUTEX_NULL) {
        ret = 0;
    } else {
        ret = 1;
    }

    return ret;
}

/**
 * @ingroup sys_mutex
 * Invalidate a mutex so that sys_mutex_valid() returns 0.
 * ATTENTION: This does NOT mean that the mutex shall be deallocated:
 * sys_mutex_free() is always called before calling this function!
 * This may also be a define, in which case the function is not prototyped.
 */
void sys_mutex_set_invalid(sys_mutex_t *mutex)
{
    *mutex = SYS_MUTEX_NULL;
}

#endif /*LWIP_COMPAT_MUTEX*/

/**
 * @ingroup sys_sem
 * Create a new semaphore
 * Creates a new semaphore. The semaphore is allocated to the memory that 'sem'
 * points to (which can be both a pointer or the actual OS structure).
 * The "count" argument specifies the initial state of the semaphore (which is
 * either 0 or 1).
 * If the semaphore has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 *
 * @param sem pointer to the semaphore to create
 * @param count initial count of the semaphore
 * @return ERR_OK if successful, another err_t otherwise
 */
err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
    err_t ret;

    if (ms_semc_create("lwip_semc", count, UINT16_MAX,
                       MS_WAIT_TYPE_PRIO, sem) == MS_ERR_NONE) {
#if SYS_STATS
        ++lwip_stats.sys.sem.used;
        if (lwip_stats.sys.sem.max < lwip_stats.sys.sem.used) {
            lwip_stats.sys.sem.max = lwip_stats.sys.sem.used;
        }
#endif /* SYS_STATS */

        ret = ERR_OK;

    } else {
        ms_printk(MS_PK_ERR, "Failed to create lwip sem!\n");

#if SYS_STATS
        ++lwip_stats.sys.sem.err;
#endif /* SYS_STATS */

        ret = ERR_MEM;
    }

    return ret;
}

/**
 * @ingroup sys_sem
 * Signals a semaphore
 * @param sem the semaphore to signal
 */
void sys_sem_signal(sys_sem_t *sem)
{
    (void)ms_semc_post(*sem);
}

/**
 * @ingroup sys_sem
 *  Blocks the thread while waiting for the semaphore to be signaled. If the
 * "timeout" argument is non-zero, the thread should only be blocked for the
 * specified time (measured in milliseconds). If the "timeout" argument is zero,
 * the thread should be blocked until the semaphore is signalled.
 *
 * The return value is SYS_ARCH_TIMEOUT if the semaphore wasn't signaled within
 * the specified time or any other value if it was signaled (with or without
 * waiting).
 * Notice that lwIP implements a function with a similar name,
 * sys_sem_wait(), that uses the sys_arch_sem_wait() function.
 *
 * @param sem the semaphore to wait for
 * @param timeout timeout in milliseconds to wait (0 = wait forever)
 * @return SYS_ARCH_TIMEOUT on timeout, any other value on success
 */
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
    ms_uint64_t start_time = ms_time_get_ms();
    u32_t ret;

    if (timeout != 0) {
        if (ms_semc_wait(*sem, ms_time_ms_to_tick(timeout)) == MS_ERR_NONE) {
            ret = (ms_time_get_ms() - start_time);
        } else {
            ret = SYS_ARCH_TIMEOUT;
        }

    } else {
        while (ms_semc_wait(*sem, MS_TIMEOUT_FOREVER) != MS_ERR_NONE) {
        }
        ret = (ms_time_get_ms() - start_time);
    }

    return ret;
}


/**
 * @ingroup sys_sem
 * Deallocates a semaphore.
 * @param sem semaphore to delete
 */
void sys_sem_free(sys_sem_t *sem)
{
    (void)ms_semc_destroy(*sem);

#if SYS_STATS
    --lwip_stats.sys.sem.used;
#endif /* SYS_STATS */
}

/**
 * @ingroup sys_sem
 * Returns 1 if the semaphore is valid, 0 if it is not valid.
 * When using pointers, a simple way is to check the pointer for != NULL.
 * When directly using OS structures, implementing this may be more complex.
 * This may also be a define, in which case the function is not prototyped.
 */
int sys_sem_valid(sys_sem_t *sem)
{
    int ret;

    if (*sem == SYS_SEM_NULL) {
        ret = 0;
    } else {
        ret = 1;
    }

    return ret;
}

/**
 * @ingroup sys_sem
 * Invalidate a semaphore so that sys_sem_valid() returns 0.
 * ATTENTION: This does NOT mean that the semaphore shall be deallocated:
 * sys_sem_free() is always called before calling this function!
 * This may also be a define, in which case the function is not prototyped.
 */
void sys_sem_set_invalid(sys_sem_t *sem)
{
    *sem = SYS_SEM_NULL;
}

/**
 * @ingroup sys_mbox
 * Creates an empty mailbox for maximum "size" elements. Elements stored
 * in mailboxes are pointers. You have to define macros "_MBOX_SIZE"
 * in your lwipopts.h, or ignore this parameter in your implementation
 * and use a default size.
 * If the mailbox has been created, ERR_OK should be returned. Returning any
 * other error will provide a hint what went wrong, but except for assertions,
 * no real error handling is implemented.
 *
 * @param mbox pointer to the mbox to create
 * @param size (minimum) number of messages in this mbox
 * @return ERR_OK if successful, another err_t otherwise
 */
err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
    void *msg_buf = ms_kmalloc(size * sizeof(void *));
    err_t ret = ERR_MEM;

    if (msg_buf != MS_NULL) {
        if (ms_mqueue_create("lwip_mbox", msg_buf, size, sizeof(void *),
                             MS_WAIT_TYPE_PRIO, mbox) == MS_ERR_NONE) {

#if SYS_STATS
            ++lwip_stats.sys.mbox.used;
            if (lwip_stats.sys.mbox.max < lwip_stats.sys.mbox.used) {
                lwip_stats.sys.mbox.max = lwip_stats.sys.mbox.used;
            }
#endif /* SYS_STATS */

            ret = ERR_OK;

        } else {
            (void)ms_kfree(msg_buf);
        }
    }

    if (ret != ERR_OK) {
        ms_printk(MS_PK_ERR, "Failed to create lwip mbox!\n");
    }

    return ret;
}


/**
 * @ingroup sys_mbox
 * Post a message to an mbox - may not fail
 * -> blocks if full, only to be used from tasks NOT from ISR!
 *
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
void sys_mbox_post(sys_mbox_t *mbox, void *data)
{
    while (ms_mqueue_post(*mbox, &data, MS_TIMEOUT_FOREVER) != MS_ERR_NONE) {
    }
}

/**
 * @ingroup sys_mbox
 * Try to post a message to an mbox - may fail if full.
 * Can be used from ISR (if the sys arch layer allows this).
 * Returns ERR_MEM if it is full, else, ERR_OK if the "msg" is posted.
 *
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
    err_t ret;

    if (ms_mqueue_post(*mbox, &msg, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE) {
        ret = ERR_OK;
    } else {
        ret = ERR_MEM;

#if SYS_STATS
        lwip_stats.sys.mbox.err++;
#endif /* SYS_STATS */
    }

    return ret;
}

/**
 * @ingroup sys_mbox
 * Try to post a message to an mbox - may fail if full.
 * To be be used from ISR.
 * Returns ERR_MEM if it is full, else, ERR_OK if the "msg" is posted.
 *
 * @param mbox mbox to posts the message
 * @param msg message to post (ATTENTION: can be NULL)
 */
err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg)
{
    return sys_mbox_trypost(mbox, msg);
}

/**
 * @ingroup sys_mbox
 * Blocks the thread until a message arrives in the mailbox, but does
 * not block the thread longer than "timeout" milliseconds (similar to
 * the sys_arch_sem_wait() function). If "timeout" is 0, the thread should
 * be blocked until a message arrives. The "msg" argument is a result
 * parameter that is set by the function (i.e., by doing "*msg =
 * ptr"). The "msg" parameter maybe NULL to indicate that the message
 * should be dropped.
 * The return values are the same as for the sys_arch_sem_wait() function:
 * SYS_ARCH_TIMEOUT if there was a timeout, any other value if a messages
 * is received.
 *
 * Note that a function with a similar name, sys_mbox_fetch(), is
 * implemented by lwIP.
 *
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @param timeout maximum time (in milliseconds) to wait for a message (0 = wait forever)
 * @return SYS_ARCH_TIMEOUT on timeout, any other value if a message has been received
 */
u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout)
{
    ms_uint64_t start_time = ms_time_get_ms();
    u32_t ret;

    if (timeout != 0) {
        if (ms_mqueue_wait(*mbox, msg, ms_time_ms_to_tick(timeout)) == MS_ERR_NONE) {
            ret = (ms_time_get_ms() - start_time);
        } else {
            ret = SYS_ARCH_TIMEOUT;
        }

    } else {
        while (ms_mqueue_wait(*mbox, msg, MS_TIMEOUT_FOREVER) != MS_ERR_NONE) {
        }
        ret = (ms_time_get_ms() - start_time);
    }

    return ret;
}

/**
 * @ingroup sys_mbox
 * This is similar to sys_arch_mbox_fetch, however if a message is not
 * present in the mailbox, it immediately returns with the code
 * SYS_MBOX_EMPTY. On success 0 is returned.
 * To allow for efficient implementations, this can be defined as a
 * function-like macro in sys_arch.h instead of a normal function. For
 * example, a naive implementation could be:
 * \#define sys_arch_mbox_tryfetch(mbox,msg) sys_arch_mbox_fetch(mbox,msg,1)
 * although this would introduce unnecessary delays.
 *
 * @param mbox mbox to get a message from
 * @param msg pointer where the message is stored
 * @return 0 (milliseconds) if a message has been received
 *         or SYS_MBOX_EMPTY if the mailbox is empty
 */
u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
    u32_t ret;

    if (ms_mqueue_wait(*mbox, msg, MS_TIMEOUT_NO_WAIT) == MS_ERR_NONE) {
        ret = ERR_OK;
    } else {
        ret = SYS_MBOX_EMPTY;
    }

    return ret;
}

/**
 * @ingroup sys_mbox
 * Deallocates a mailbox. If there are messages still present in the
 * mailbox when the mailbox is deallocated, it is an indication of a
 * programming error in lwIP and the developer should be notified.
 *
 * @param mbox mbox to delete
 */
void sys_mbox_free(sys_mbox_t *mbox)
{
    ms_mqueue_stat_t stat;

    if (ms_mqueue_stat(*mbox, &stat) == MS_ERR_NONE) {
        (void)ms_mqueue_destroy(*mbox);

        if (stat.msg_buf != MS_NULL) {
            (void)ms_kfree(stat.msg_buf);
        }

#if SYS_STATS
        --lwip_stats.sys.mbox.used;
#endif /* SYS_STATS */
    }
}

/**
 * @ingroup sys_mbox
 * Returns 1 if the mailbox is valid, 0 if it is not valid.
 * When using pointers, a simple way is to check the pointer for != NULL.
 * When directly using OS structures, implementing this may be more complex.
 * This may also be a define, in which case the function is not prototyped.
 */
int sys_mbox_valid(sys_mbox_t *mbox)
{
    int ret;

    if (*mbox == SYS_MBOX_NULL) {
        ret = 0;
    } else {
        ret = 1;
    }

    return ret;
}

/**
 * @ingroup sys_mbox
 * Invalidate a mailbox so that sys_mbox_valid() returns 0.
 * ATTENTION: This does NOT mean that the mailbox shall be deallocated:
 * sys_mbox_free() is always called before calling this function!
 * This may also be a define, in which case the function is not prototyped.
 */
void sys_mbox_set_invalid(sys_mbox_t *mbox)
{
    *mbox = SYS_MBOX_NULL;
}

/**
 * @ingroup sys_misc
 * The only thread function:
 * Starts a new thread named "name" with priority "prio" that will begin its
 * execution in the function "thread()". The "arg" argument will be passed as an
 * argument to the thread() function. The stack size to used for this thread is
 * the "stacksize" parameter. The id of the new thread is returned. Both the id
 * and the priority are system dependent.
 * ATTENTION: although this function returns a value, it MUST NOT FAIL (ports have to assert this!)
 *
 * @param name human-readable name for the thread (used for debugging purposes)
 * @param thread thread-function
 * @param arg parameter passed to 'thread'
 * @param stacksize stack size in bytes for the new thread (may be ignored by ports)
 * @param prio priority of the new thread (may be ignored by ports)
 */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg, int stacksize, int prio)
{
    ms_handle_t tid;

    if (ms_thread_create(name, thread, arg, stacksize, prio, TCPIP_THREAD_TIME_SLICE,
                         TCPIP_THREAD_OPT | MS_THREAD_OPT_SUPER, &tid) != MS_ERR_NONE) {
        tid = MS_HANDLE_INVALID;
        ms_printk(MS_PK_ERR, "Failed to create lwip thread!\n");
    }

    return (sys_thread_t)tid;
}

/**
 * @ingroup sys_misc
 * sys_init() must be called before anything else.
 * Initialize the sys_arch layer.
 */
void sys_init(void)
{
    if (ms_mutex_create("lwip_lock", MS_WAIT_TYPE_PRIO, &ms_lwip_core_lockid) != MS_ERR_NONE) {
        ms_printk(MS_PK_ERR, "Failed to create lwip lock!\n");
    }
}

/**
 * Ticks/jiffies since power up.
 */
u32_t sys_jiffies(void)
{
    return (u32_t)ms_time_get();
}

/**
 * @ingroup sys_time
 * Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it.
 * Don't care for wraparound, this is only used for time diffs.
 * Not implementing this function means you cannot use some modules (e.g. TCP
 * timestamps, internal timeouts for NO_SYS==1).
 */
u32_t sys_now(void)
{
    return (u32_t)ms_time_get_ms();
}

/**
 * @ingroup sys_misc
 * Sleep for specified number of ms
 */
void sys_msleep(u32_t ms)
{
    (void)ms_thread_sleep_ms(ms);
}

/**
 * @ingroup sys_prot
 * SYS_ARCH_PROTECT
 * Perform a "fast" protect. This could be implemented by
 * disabling interrupts for an embedded system or by using a semaphore or
 * mutex. The implementation should allow calling SYS_ARCH_PROTECT when
 * already protected. The old protection level is returned in the variable
 * "lev". This macro will default to calling the sys_arch_protect() function
 * which should be implemented in sys_arch.c. If a particular port needs a
 * different implementation, then this macro may be defined in sys_arch.h
 */
sys_prot_t sys_arch_protect(void)
{
    while (ms_mutex_lock(ms_lwip_core_lockid, MS_TIMEOUT_FOREVER) != MS_ERR_NONE) {
    }

    return (sys_prot_t)1;
}

/**
 * @ingroup sys_prot
 * SYS_ARCH_UNPROTECT
 * Perform a "fast" set of the protection level to "lev". This could be
 * implemented by setting the interrupt level to "lev" within the MACRO or by
 * using a semaphore or mutex.  This macro will default to calling the
 * sys_arch_unprotect() function which should be implemented in
 * sys_arch.c. If a particular port needs a different implementation, then
 * this macro may be defined in sys_arch.h
 */
void sys_arch_unprotect(sys_prot_t pval)
{
    (void)pval;

    (void)ms_mutex_unlock(ms_lwip_core_lockid);
}
