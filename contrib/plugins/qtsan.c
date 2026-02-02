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
 * Configuration - all sizes fixed at compile time
 */
#define QTSAN_MAX_THREADS       64U
#define QTSAN_SHADOW_CELLS      4U
#define QTSAN_SHADOW_BUCKETS    65536U
#define QTSAN_BUCKET_ENTRIES    16U

/*
 * Shadow cell: tracks one memory access
 */
typedef struct {
    uint32_t epoch;
    uint16_t tid;
    uint8_t  size_log;
    uint8_t  flags;         /* bit 0: is_write, bit 1: valid */
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
 * Global state - all statically allocated
 */
static ShadowBucket g_shadow[QTSAN_SHADOW_BUCKETS];
static ThreadState  g_threads[QTSAN_MAX_THREADS];
static uint64_t     g_total_accesses;
static uint64_t     g_total_races;
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
 * Check if access A happens-before access B
 * Returns true if A's epoch is covered by B's vector clock
 */
static bool vc_happens_before(uint32_t a_tid, uint32_t a_epoch,
                               const VectorClock *b_vc)
{
    assert(b_vc != NULL);
    assert(a_tid < QTSAN_MAX_THREADS);

    return a_epoch <= b_vc->clocks[a_tid];
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
 * Returns pointer to shadow cells, or NULL if bucket is full
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

    /* Search existing entries */
    for (i = 0U; i < bucket->count; i++) {
        if (bucket->addr[i] == aligned) {
            return bucket->cells[i];
        }
    }

    /* Add new entry if space available */
    if (bucket->count < QTSAN_BUCKET_ENTRIES) {
        uint32_t idx = bucket->count;
        bucket->addr[idx] = aligned;
        (void)memset(bucket->cells[idx], 0, sizeof(bucket->cells[idx]));
        bucket->count++;
        return bucket->cells[idx];
    }

    /* Bucket full - reuse slot 0 */
    bucket->addr[0] = aligned;
    (void)memset(bucket->cells[0], 0, sizeof(bucket->cells[0]));
    return bucket->cells[0];
}

/*
 * Check shadow cells for potential races with current access
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
        bool same_thread;
        bool both_reads;
        bool ordered;

        cell_valid = (cell->flags & FLAG_VALID) != 0U;
        if (!cell_valid) {
            continue;
        }

        same_thread = (cell->tid == self_tid);
        if (same_thread) {
            continue;
        }

        cell_write = (cell->flags & FLAG_IS_WRITE) != 0U;
        both_reads = (!is_write) && (!cell_write);
        if (both_reads) {
            continue;
        }

        ordered = vc_happens_before(cell->tid, cell->epoch, self_vc);
        if (!ordered) {
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

    /* Find empty or oldest slot */
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

    /* Update the slot */
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

    /* Increment epoch */
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

    /* Parse arguments */
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "verbose=true") == 0) {
            g_verbose = true;
        }
    }

    /* Initialize state */
    (void)memset(g_shadow, 0, sizeof(g_shadow));
    (void)memset(g_threads, 0, sizeof(g_threads));
    g_total_accesses = 0U;
    g_total_races = 0U;

    /* Register callbacks */
    qemu_plugin_register_vcpu_init_cb(id, cb_vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, cb_vcpu_exit);
    qemu_plugin_register_vcpu_tb_trans_cb(id, cb_tb_trans);
    qemu_plugin_register_atexit_cb(id, cb_plugin_exit, NULL);

    return 0;
}
