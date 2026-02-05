/*
 * QTSan - Common definitions shared between plugin and guest library
 *
 * Copyright (C) 2026, Zaneham
 * License: GNU GPL, version 2 or later.
 */

#ifndef QTSAN_COMMON_H
#define QTSAN_COMMON_H

#define QTSAN_FAKESYS_NR    0xa2a5

enum qtsan_action {
    QTSAN_ACTION_MUTEX_LOCK     = 1,
    QTSAN_ACTION_MUTEX_UNLOCK   = 2,
    QTSAN_ACTION_THREAD_CREATE  = 3,
    QTSAN_ACTION_THREAD_JOIN    = 4,
    QTSAN_ACTION_ACQUIRE        = 5,
    QTSAN_ACTION_RELEASE        = 6,
    QTSAN_ACTION_MALLOC         = 7,
    QTSAN_ACTION_FREE           = 8
};

#endif /* QTSAN_COMMON_H */
