/*
 * libqtsan - Guest-side library for QTSan
 * Hooks pthread functions and notifies QEMU plugin about synchronization
 *
 * Copyright (C) 2026, Zaneham
 * License: GNU GPL, version 2 or later.
 *
 * Usage: LD_PRELOAD=./libqtsan.so ./your_program
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "qtsan_common.h"

/*
 * Original pthread function pointers
 */
static int (*real_pthread_mutex_lock)(pthread_mutex_t *) = NULL;
static int (*real_pthread_mutex_unlock)(pthread_mutex_t *) = NULL;
static int (*real_pthread_create)(pthread_t *, const pthread_attr_t *,
                                   void *(*)(void *), void *) = NULL;
static int (*real_pthread_join)(pthread_t, void **) = NULL;

/*
 * Notify QTSan plugin via fake syscall
 */
static void qtsan_notify(enum qtsan_action action, uintptr_t arg1, uintptr_t arg2)
{
    syscall(QTSAN_FAKESYS_NR, action, arg1, arg2);
}

/*
 * Initialize original function pointers
 */
static void init_real_functions(void)
{
    if (real_pthread_mutex_lock != NULL) {
        return;
    }

    real_pthread_mutex_lock = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    real_pthread_mutex_unlock = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
    real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
    real_pthread_join = dlsym(RTLD_NEXT, "pthread_join");
}

/*
 * Hooked pthread_mutex_lock
 */
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int result;

    init_real_functions();

    result = real_pthread_mutex_lock(mutex);

    if (result == 0) {
        qtsan_notify(QTSAN_ACTION_MUTEX_LOCK, (uintptr_t)mutex, 0);
    }

    return result;
}

/*
 * Hooked pthread_mutex_unlock
 */
int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    int result;

    init_real_functions();

    qtsan_notify(QTSAN_ACTION_MUTEX_UNLOCK, (uintptr_t)mutex, 0);

    result = real_pthread_mutex_unlock(mutex);

    return result;
}

/*
 * Wrapper data for thread creation
 */
struct thread_wrapper_data {
    void *(*real_start)(void *);
    void *real_arg;
    pthread_t parent_tid;
};

/*
 * Thread wrapper to notify on thread start
 */
static void *thread_wrapper(void *arg)
{
    struct thread_wrapper_data *data = arg;
    void *(*start)(void *) = data->real_start;
    void *real_arg = data->real_arg;

    /* Notify: child thread started */
    qtsan_notify(QTSAN_ACTION_THREAD_CREATE, (uintptr_t)data->parent_tid, 0);

    /* Free wrapper data - allocated by pthread_create hook */
    free(data);

    return start(real_arg);
}

/*
 * Hooked pthread_create
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg)
{
    struct thread_wrapper_data *data;
    int result;

    init_real_functions();

    data = malloc(sizeof(*data));
    if (data == NULL) {
        return real_pthread_create(thread, attr, start_routine, arg);
    }

    data->real_start = start_routine;
    data->real_arg = arg;
    data->parent_tid = pthread_self();

    result = real_pthread_create(thread, attr, thread_wrapper, data);

    if (result != 0) {
        free(data);
    }

    return result;
}

/*
 * Hooked pthread_join
 */
int pthread_join(pthread_t thread, void **retval)
{
    int result;

    init_real_functions();

    result = real_pthread_join(thread, retval);

    if (result == 0) {
        qtsan_notify(QTSAN_ACTION_THREAD_JOIN, (uintptr_t)thread, 0);
    }

    return result;
}

/*
 * Library constructor
 */
__attribute__((constructor))
static void libqtsan_init(void)
{
    (void)fprintf(stderr, "libqtsan: loaded\n");
    init_real_functions();
}
