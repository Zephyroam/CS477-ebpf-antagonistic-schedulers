/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include "include/scx/common.bpf.h"
// #include <linux/perf_event.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>


char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could
 * just use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct task_ctx {
	bool isLimited;
	u64 last_cache_miss_rate;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} cache_misses_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} cache_loads_map SEC(".maps");


SEC("perf_event")
int count_cache_misses(struct bpf_perf_event_value *ctx) {
    u64 *counter;
    u32 key = 0;

    // Access the map and increment the counter
    counter = bpf_map_lookup_elem(&cache_misses_map, &key);
    if (counter) {
        (*counter)++;
    }
    return 0;
}

SEC("perf_event")
int count_cache_loads(struct bpf_perf_event_value *ctx) {
    u64 *counter;
    u32 key = 0;

    // Access the map and increment the counter
    counter = bpf_map_lookup_elem(&cache_loads_map, &key);
    if (counter) {
        (*counter)++;
    }
    return 0;
}



static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}



static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

SEC("perf_event")
int monitor_execve(struct trace_event_raw_sys_enter *ctx) {
    char filename[128];
    u32 idx = 0; // Use a fixed index for tracking execve calls

    // Read the filename of the executed program
    if (bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[0]) > 0) {
        bpf_printk("Execve called with filename: %s\n", filename);
    }


    return 0;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	// record current cache miss rate(misses/loades) for the current CPU
	u64 *cache_misses;
	u64 *cache_loads;
	u32 key = 0;

	cache_misses = bpf_map_lookup_elem(&cache_misses_map, &key);
	cache_loads = bpf_map_lookup_elem(&cache_loads_map, &key);

	if (cache_misses && cache_loads) {
		struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (tctx) {
			tctx->last_cache_miss_rate = *cache_misses / *cache_loads;
		}
	}
	

}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */


	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

	// Re record current cache miss rate(misses/loades) for the current CPU, compare it with the last cache miss rate
	// compute the change rate, if it is greater than 5%, set the task as limited
	u64 *cache_misses;
	u64 *cache_loads;
	u32 key = 0;

	cache_misses = bpf_map_lookup_elem(&cache_misses_map, &key);
	cache_loads = bpf_map_lookup_elem(&cache_loads_map, &key);

	if (cache_misses && cache_loads) {
		struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (tctx) {
			u64 current_cache_miss_rate = *cache_misses / *cache_loads;
			u64 change_rate = (current_cache_miss_rate - tctx->last_cache_miss_rate) / tctx->last_cache_miss_rate;
			if (change_rate > 0.05) {
				tctx->isLimited = true;
			}
		}
	}

}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;

}

/* Scheduler init*/
s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
    int ret;

    
    ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
    if (ret) {
        bpf_printk("Failed to create dispatch queue: %d\n", ret);
        return ret;
    }



    bpf_printk("Simple scheduler initialized successfully.\n");
    return 0;
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .name			= "simple");