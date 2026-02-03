/*
 * QTSan - QEMU ThreadSanitizer Plugin
 * Binary-only data race detection for QEMU user-mode emulation
 *
 * Copyright (C) 2026, Zaneham
 * License: GNU GPL, version 2 or later.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/*
 * Fake syscall number for libqtsan communication
 */
#define QTSAN_FAKESYS_NR        0xa2a5

/*
 * Actions from libqtsan
 */
#define QTSAN_ACTION_MUTEX_LOCK     1U
#define QTSAN_ACTION_MUTEX_UNLOCK   2U
#define QTSAN_ACTION_THREAD_CREATE  3U
#define QTSAN_ACTION_THREAD_JOIN    4U

/*
 * Configuration - all sizes fixed at compile time
 */
#define QTSAN_MAX_THREADS       64U
#define QTSAN_SHADOW_CELLS      4U
#define QTSAN_SHADOW_BUCKETS    65536U
#define QTSAN_BUCKET_ENTRIES    16U
#define QTSAN_MAX_MUTEXES       1024U

/*
 * Shadow cell: tracks one memory access
 */
typedef struct {
    uint32_t epoch;
    uint16_t tid;
    uint8_t  size_log;
    uint8_t  flags;
} ShadowCell;

#define FLAG_VALID      0x02U
#define FLAG_IS_WRITE   0x01U

/*
 * Shadow bucket: fixed array of cells for one hash bucket
 */
typedef struct {
    uint64_t    addr[QTSAN_BUCKET_ENTRIES];
    ShadowCell  cells[QTSAN_BUCKET_ENTRIES][QTSAN_SHADOW_CELLS];
    uint32_t    count;
} ShadowBucket;

/*
 * Vector clock
 */
typedef struct {
    uint32_t clocks[QTSAN_MAX_THREADS];
} VectorClock;

/*
 * Thread state
 */
typedef struct {
    VectorClock vc;
    uint64_t    access_count;
    uint32_t    epoch;
    uint32_t    tid;
    bool        active;
} ThreadState;

/*
 * Mutex state: tracks the vector clock at last unlock
 */
typedef struct {
    uint64_t    addr;
    VectorClock vc;
    bool        valid;
} MutexState;

/*
 * Global state - all statically allocated
 */
static ShadowBucket g_shadow[QTSAN_SHADOW_BUCKETS];
static ThreadState  g_threads[QTSAN_MAX_THREADS];
static MutexState   g_mutexes[QTSAN_MAX_MUTEXES];
static uint64_t     g_total_accesses;
static uint64_t     g_total_races;
static uint64_t     g_sync_ops;
static bool         g_verbose;

/*
 * Hash function for shadow memory lookup
 */
static uint32_t shadow_hash(uint64_t addr)
{
    uint64_t aligned;
    uint64_t hash;

    aligned = addr >> 3U;
    hash = aligned ^ (aligned >> 16U);

    return (uint32_t)(hash % QTSAN_SHADOW_BUCKETS);
}

/*
 * Initialize a vector clock to zero
 */
static void vc_init(VectorClock *vc)
{
    uint32_t i;

    assert(vc != NULL);

    for (i = 0U; i < QTSAN_MAX_THREADS; i++) {
        vc->clocks[i] = 0U;
    }
}

/*
 * Copy vector clock
 */
static void vc_copy(VectorClock *dst, const VectorClock *src)
{
    uint32_t i;

    assert(dst != NULL);
    assert(src != NULL);

    for (i = 0U; i < QTSAN_MAX_THREADS; i++) {
        dst->clocks[i] = src->clocks[i];
    }
}

/*
 * Join vector clocks: dst = max(dst, src)
 */
static void vc_join(VectorClock *dst, const VectorClock *src)
{
    uint32_t i;

    assert(dst != NULL);
    assert(src != NULL);

    for (i = 0U; i < QTSAN_MAX_THREADS; i++) {
        if (src->clocks[i] > dst->clocks[i]) {
            dst->clocks[i] = src->clocks[i];
        }
    }
}

/*
 * Check if access A happens-before access B
 */
static bool vc_happens_before(uint32_t a_tid, uint32_t a_epoch,
                               const VectorClock *b_vc)
{
    assert(b_vc != NULL);
    assert(a_tid < QTSAN_MAX_THREADS);

    return a_epoch <= b_vc->clocks[a_tid];
}

/*
 * Find mutex state by address
 */
static MutexState *mutex_find(uint64_t addr)
{
    uint32_t i;
    uint32_t free_slot;
    bool found_free;

    found_free = false;
    free_slot = 0U;

    for (i = 0U; i < QTSAN_MAX_MUTEXES; i++) {
        if (g_mutexes[i].valid && g_mutexes[i].addr == addr) {
            return &g_mutexes[i];
        }
        if (!g_mutexes[i].valid && !found_free) {
            free_slot = i;
            found_free = true;
        }
    }

    /* Create new mutex entry */
    if (found_free) {
        g_mutexes[free_slot].addr = addr;
        g_mutexes[free_slot].valid = true;
        vc_init(&g_mutexes[free_slot].vc);
        return &g_mutexes[free_slot];
    }

    return NULL;
}

/*
 * Handle mutex lock: thread acquires mutex's vector clock
 */
static void handle_mutex_lock(uint32_t vcpu_idx, uint64_t mutex_addr)
{
    ThreadState *ts;
    MutexState *ms;

    if (vcpu_idx >= QTSAN_MAX_THREADS) {
        return;
    }

    ts = &g_threads[vcpu_idx];
    if (!ts->active) {
        return;
    }

    ms = mutex_find(mutex_addr);
    if (ms == NULL) {
        return;
    }

    /* Acquire: join mutex's VC into thread's VC */
    vc_join(&ts->vc, &ms->vc);
    g_sync_ops++;

    if (g_verbose) {
        (void)fprintf(stderr, "QTSan: thread %u lock mutex 0x%" PRIx64 "\n",
                      vcpu_idx, mutex_addr);
    }
}

/*
 * Handle mutex unlock: mutex gets thread's vector clock
 */
static void handle_mutex_unlock(uint32_t vcpu_idx, uint64_t mutex_addr)
{
    ThreadState *ts;
    MutexState *ms;

    if (vcpu_idx >= QTSAN_MAX_THREADS) {
        return;
    }

    ts = &g_threads[vcpu_idx];
    if (!ts->active) {
        return;
    }

    ms = mutex_find(mutex_addr);
    if (ms == NULL) {
        return;
    }

    /* Release: copy thread's VC to mutex */
    vc_copy(&ms->vc, &ts->vc);

    /* Increment thread's epoch */
    ts->epoch++;
    ts->vc.clocks[ts->tid] = ts->epoch;
    g_sync_ops++;

    if (g_verbose) {
        (void)fprintf(stderr, "QTSan: thread %u unlock mutex 0x%" PRIx64 "\n",
                      vcpu_idx, mutex_addr);
    }
}

/*
 * Handle thread create: child inherits parent's VC
 */
static void handle_thread_create(uint32_t parent_idx, uint32_t child_idx)
{
    ThreadState *parent;
    ThreadState *child;

    if (parent_idx >= QTSAN_MAX_THREADS || child_idx >= QTSAN_MAX_THREADS) {
        return;
    }

    parent = &g_threads[parent_idx];
    child = &g_threads[child_idx];

    if (parent->active && child->active) {
        /* Child inherits parent's vector clock */
        vc_join(&child->vc, &parent->vc);

        /* Parent increments its epoch */
        parent->epoch++;
        parent->vc.clocks[parent->tid] = parent->epoch;
        g_sync_ops++;

        if (g_verbose) {
            (void)fprintf(stderr, "QTSan: thread %u created thread %u\n",
                          parent_idx, child_idx);
        }
    }
}

/*
 * Handle thread join: parent syncs with child's final VC
 */
static void handle_thread_join(uint32_t parent_idx, uint32_t child_idx)
{
    ThreadState *parent;
    ThreadState *child;

    if (parent_idx >= QTSAN_MAX_THREADS || child_idx >= QTSAN_MAX_THREADS) {
        return;
    }

    parent = &g_threads[parent_idx];
    child = &g_threads[child_idx];

    if (parent->active) {
        /* Parent joins child's vector clock */
        vc_join(&parent->vc, &child->vc);
        g_sync_ops++;

        if (g_verbose) {
            (void)fprintf(stderr, "QTSan: thread %u joined thread %u\n",
                          parent_idx, child_idx);
        }
    }
}

/*
 * Report a detected data race
 */
static void report_race(uint32_t tid1, uint32_t tid2,
                        uint64_t addr, bool write1, bool write2)
{
    g_total_races++;

    (void)fprintf(stderr, "\n");
    (void)fprintf(stderr, "==========================================\n");
    (void)fprintf(stderr, "QTSan: DATA RACE DETECTED\n");
    (void)fprintf(stderr, "==========================================\n");
    (void)fprintf(stderr, "  Address: 0x%016" PRIx64 "\n", addr);
    (void)fprintf(stderr, "  Thread %u: %s\n", tid1, write1 ? "write" : "read");
    (void)fprintf(stderr, "  Thread %u: %s\n", tid2, write2 ? "write" : "read");
    (void)fprintf(stderr, "==========================================\n");
}

/*
 * Find or create shadow entry for an address
 */
static ShadowCell *shadow_find(uint64_t addr)
{
    uint32_t bucket_idx;
    ShadowBucket *bucket;
    uint64_t aligned;
    uint32_t i;

    aligned = addr & ~7ULL;
    bucket_idx = shadow_hash(aligned);
    bucket = &g_shadow[bucket_idx];

    assert(bucket != NULL);

    for (i = 0U; i < bucket->count; i++) {
        if (bucket->addr[i] == aligned) {
            return bucket->cells[i];
        }
    }

    if (bucket->count < QTSAN_BUCKET_ENTRIES) {
        uint32_t idx = bucket->count;
        bucket->addr[idx] = aligned;
        (void)memset(bucket->cells[idx], 0, sizeof(bucket->cells[idx]));
        bucket->count++;
        return bucket->cells[idx];
    }

    bucket->addr[0] = aligned;
    (void)memset(bucket->cells[0], 0, sizeof(bucket->cells[0]));
    return bucket->cells[0];
}

/*
 * Check shadow cells for potential races
 */
static void check_cells_for_race(const ShadowCell *cells, uint32_t self_tid,
                                  const VectorClock *self_vc, uint64_t addr,
                                  bool is_write)
{
    uint32_t i;

    assert(cells != NULL);
    assert(self_vc != NULL);
    assert(self_tid < QTSAN_MAX_THREADS);

    for (i = 0U; i < QTSAN_SHADOW_CELLS; i++) {
        const ShadowCell *cell = &cells[i];
        bool cell_valid;
        bool cell_write;

        cell_valid = (cell->flags & FLAG_VALID) != 0U;
        if (!cell_valid) {
            continue;
        }

        if (cell->tid == self_tid) {
            continue;
        }

        cell_write = (cell->flags & FLAG_IS_WRITE) != 0U;
        if ((!is_write) && (!cell_write)) {
            continue;
        }

        if (!vc_happens_before(cell->tid, cell->epoch, self_vc)) {
            report_race(cell->tid, self_tid, addr, cell_write, is_write);
        }
    }
}

/*
 * Update shadow with current access
 */
static void shadow_update(ShadowCell *cells, uint32_t tid,
                          uint32_t epoch, uint8_t size_log, bool is_write)
{
    uint32_t slot;
    uint32_t oldest_epoch;
    uint32_t i;

    assert(cells != NULL);
    assert(tid < QTSAN_MAX_THREADS);

    slot = 0U;
    oldest_epoch = UINT32_MAX;

    for (i = 0U; i < QTSAN_SHADOW_CELLS; i++) {
        bool valid = (cells[i].flags & FLAG_VALID) != 0U;

        if (!valid) {
            slot = i;
            break;
        }
        if (cells[i].epoch < oldest_epoch) {
            oldest_epoch = cells[i].epoch;
            slot = i;
        }
    }

    cells[slot].epoch = epoch;
    cells[slot].tid = (uint16_t)tid;
    cells[slot].size_log = size_log;
    cells[slot].flags = FLAG_VALID;
    if (is_write) {
        cells[slot].flags |= FLAG_IS_WRITE;
    }
}

/*
 * Process a memory access
 */
static void process_access(uint32_t vcpu_idx, uint64_t addr,
                           uint8_t size_log, bool is_write)
{
    ThreadState *self;
    ShadowCell *cells;

    if (vcpu_idx >= QTSAN_MAX_THREADS) {
        return;
    }

    self = &g_threads[vcpu_idx];
    if (!self->active) {
        return;
    }

    cells = shadow_find(addr);
    if (cells == NULL) {
        return;
    }

    self->access_count++;
    g_total_accesses++;

    check_cells_for_race(cells, self->tid, &self->vc, addr, is_write);
    shadow_update(cells, self->tid, self->epoch, size_log, is_write);

    self->epoch++;
    self->vc.clocks[self->tid] = self->epoch;
}

/*
 * QEMU callback: memory access
 */
static void cb_mem_access(unsigned int vcpu_index,
                          qemu_plugin_meminfo_t info,
                          uint64_t vaddr, void *udata)
{
    bool is_store;
    unsigned int size_shift;

    (void)udata;

    is_store = qemu_plugin_mem_is_store(info);
    size_shift = qemu_plugin_mem_size_shift(info);

    process_access(vcpu_index, vaddr, (uint8_t)size_shift, is_store);
}

/*
 * QEMU callback: syscall filter - intercept our fake syscall
 */
static bool cb_syscall_filter(qemu_plugin_id_t id, unsigned int vcpu_index,
                               int64_t num, uint64_t a1, uint64_t a2,
                               uint64_t a3, uint64_t a4, uint64_t a5,
                               uint64_t a6, uint64_t a7, uint64_t a8,
                               uint64_t *sysret)
{
    (void)id;
    (void)a3;
    (void)a4;
    (void)a5;
    (void)a6;
    (void)a7;
    (void)a8;

    if (num != QTSAN_FAKESYS_NR) {
        return false;
    }

    switch ((uint32_t)a1) {
    case QTSAN_ACTION_MUTEX_LOCK:
        handle_mutex_lock(vcpu_index, a2);
        break;
    case QTSAN_ACTION_MUTEX_UNLOCK:
        handle_mutex_unlock(vcpu_index, a2);
        break;
    case QTSAN_ACTION_THREAD_CREATE:
        handle_thread_create(vcpu_index, (uint32_t)a2);
        break;
    case QTSAN_ACTION_THREAD_JOIN:
        handle_thread_join(vcpu_index, (uint32_t)a2);
        break;
    default:
        break;
    }

    *sysret = 0;
    return true;
}

/*
 * QEMU callback: translation block
 */
static void cb_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns;
    size_t i;

    (void)id;

    n_insns = qemu_plugin_tb_n_insns(tb);

    for (i = 0U; i < n_insns; i++) {
        struct qemu_plugin_insn *insn;

        insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_register_vcpu_mem_cb(insn, cb_mem_access,
                                          QEMU_PLUGIN_CB_NO_REGS,
                                          QEMU_PLUGIN_MEM_RW, NULL);
    }
}

/*
 * QEMU callback: vCPU initialized
 */
static void cb_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    ThreadState *ts;

    (void)id;

    if (vcpu_index >= QTSAN_MAX_THREADS) {
        (void)fprintf(stderr, "QTSan: thread limit exceeded\n");
        return;
    }

    ts = &g_threads[vcpu_index];
    ts->tid = vcpu_index;
    ts->epoch = 1U;
    ts->access_count = 0U;
    ts->active = true;
    vc_init(&ts->vc);
    ts->vc.clocks[vcpu_index] = 1U;

    if (g_verbose) {
        (void)fprintf(stderr, "QTSan: thread %u started\n", vcpu_index);
    }
}

/*
 * QEMU callback: vCPU exit
 */
static void cb_vcpu_exit(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;

    if (vcpu_index >= QTSAN_MAX_THREADS) {
        return;
    }

    g_threads[vcpu_index].active = false;

    if (g_verbose) {
        (void)fprintf(stderr, "QTSan: thread %u exited\n", vcpu_index);
    }
}

/*
 * QEMU callback: plugin exit
 */
static void cb_plugin_exit(qemu_plugin_id_t id, void *udata)
{
    (void)id;
    (void)udata;

    (void)fprintf(stderr, "\n");
    (void)fprintf(stderr, "==========================================\n");
    (void)fprintf(stderr, "QTSan Summary\n");
    (void)fprintf(stderr, "==========================================\n");
    (void)fprintf(stderr, "Memory accesses:  %" PRIu64 "\n", g_total_accesses);
    (void)fprintf(stderr, "Sync operations:  %" PRIu64 "\n", g_sync_ops);
    (void)fprintf(stderr, "Races detected:   %" PRIu64 "\n", g_total_races);
    (void)fprintf(stderr, "==========================================\n");
}

/*
 * Plugin entry point
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    assert(info != NULL);

    (void)fprintf(stderr, "QTSan: plugin loaded\n");
    (void)fprintf(stderr, "QTSan: target %s\n", info->target_name);

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "verbose=true") == 0) {
            g_verbose = true;
        }
    }

    (void)memset(g_shadow, 0, sizeof(g_shadow));
    (void)memset(g_threads, 0, sizeof(g_threads));
    (void)memset(g_mutexes, 0, sizeof(g_mutexes));
    g_total_accesses = 0U;
    g_total_races = 0U;
    g_sync_ops = 0U;

    qemu_plugin_register_vcpu_init_cb(id, cb_vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, cb_vcpu_exit);
    qemu_plugin_register_vcpu_tb_trans_cb(id, cb_tb_trans);
    qemu_plugin_register_vcpu_syscall_filter_cb(id, cb_syscall_filter);
    qemu_plugin_register_atexit_cb(id, cb_plugin_exit, NULL);

    return 0;
}
