
#include "include/scx/common.bpf.h"


char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;//for test

static u64 vtime_now;
UEI_DEFINE(uei);

#define MSEC_PER_SEC 1000ULL
#define USEC_PER_MSEC 1000ULL
#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_MSEC (USEC_PER_MSEC * NSEC_PER_USEC)
#define SHARED_DSQ 0
#define P_REMOVE_NS (2 * NSEC_PER_MSEC)
#define R_MAX 3
#define TASK_DEAD                       0x00000080

struct bpf_cpumask __kptr *primary_cpumask;
struct bpf_cpumask __kptr *buffer_cpumask;
static s32 nr_buffer;

//task context
struct task_ctx {
	bool isLimited;
	u64 last_cache_miss_rate;
	
    s32 prefer_core;
    s32 prev_cpu;
};

//per cpu context
struct pcpu_ctx {
    struct bpf_timer timer;
    bool scheduled_degrade;
    u64 last_cache_miss_rate; 
};


struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, struct pcpu_ctx);
} pcpu_ctxs SEC(".maps");


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



static void try_make_core_buffer(s32 cpu, struct bpf_cpumask *buffer, bool promotion) 
{
    s32 tmp_nr_buffer = nr_buffer;
    if (tmp_nr_buffer < R_MAX) {
        __sync_fetch_and_add(&nr_buffer, 1);
        bpf_cpumask_set_cpu(cpu, buffer);
    }
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

// automatically called by the kernel when the timer expires
static int degrade_primary_core(void *map, int *key, struct bpf_timer *timer)
{
    s32 cpu = *key;
    struct pcpu_ctx *pcpu_ctx;
    struct bpf_cpumask *primary, *buffer;

    bpf_rcu_read_lock();
    primary = primary_cpumask;
    buffer = buffer_cpumask;
    if (!primary || !buffer) {
        bpf_rcu_read_unlock();
        return 0;
    }

    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (!pcpu_ctx) {
        bpf_rcu_read_unlock();
        return 0;
    }

    // Demote CPU from primary to buffer set
    bpf_cpumask_clear_cpu(cpu, primary);
    try_make_core_buffer(cpu, buffer, false);

    // Reset the scheduled_degrade flag
    pcpu_ctx->scheduled_degrade = false;

    bpf_rcu_read_unlock();
    return 0;
}


s32 BPF_STRUCT_OPS(kun_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    struct task_ctx *tctx;
    struct bpf_cpumask *primary, *buffer;
    s32 cpu;
    bool is_idle = false;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return -ENOENT;

    bpf_rcu_read_lock();
    primary = primary_cpumask;
    buffer = buffer_cpumask;

    if (!primary || !buffer) {
        bpf_rcu_read_unlock();
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    }


    // Try attached core in primary first, the highest priority, do not care the type of the task
    if (tctx->prefer_core >= 0) {
        if (bpf_cpumask_test_cpu(tctx->prefer_core, cast_mask(primary)) &&
            scx_bpf_test_and_clear_cpu_idle(tctx->prefer_core)) {
            cpu = tctx->prefer_core;
            goto out_primary;
        }
    }

    // Limited tasks can only use buffer or default CPUs, can not set cpu in buffer to primary
    if (tctx->isLimited) {

        // Try fully idle CPU in buffer first
        cpu = scx_bpf_pick_idle_cpu(cast_mask(buffer), SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            bpf_rcu_read_unlock();
            return cpu;
        }

        // Try buffer set first
        cpu = scx_bpf_pick_idle_cpu(cast_mask(buffer), 0);
        if (cpu >= 0) {
            bpf_rcu_read_unlock();
            return cpu;
        }
        
        // Fallback to any idle CPU
        cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
        if (cpu >= 0) {
            bpf_rcu_read_unlock();
            return cpu;
        }

        // Last resort - default selection
        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        bpf_rcu_read_unlock();
        return cpu;
    }

    // Try fully idle CPU in primary
    cpu = scx_bpf_pick_idle_cpu(cast_mask(primary), SCX_PICK_IDLE_CORE);
    if (cpu >= 0)
        goto out_primary;

    // Try any idle CPU in primary
    cpu = scx_bpf_pick_idle_cpu(cast_mask(primary), 0);
    if (cpu >= 0)
        goto out_primary;

    // Try fully idle CPU in buffer
    cpu = scx_bpf_pick_idle_cpu(cast_mask(buffer), SCX_PICK_IDLE_CORE);
    if (cpu >= 0) {
        bpf_cpumask_set_cpu(cpu, primary);
        if (bpf_cpumask_test_cpu(cpu, cast_mask(buffer))) {
            __sync_fetch_and_add(&nr_buffer, -1);
            bpf_cpumask_clear_cpu(cpu, buffer);
        }
        goto out_primary;
    }

    // Try any idle CPU in buffer
    cpu = scx_bpf_pick_idle_cpu(cast_mask(buffer), 0);
    if (cpu >= 0) {
        bpf_cpumask_set_cpu(cpu, primary);
        if (bpf_cpumask_test_cpu(cpu, cast_mask(buffer))) {
            __sync_fetch_and_add(&nr_buffer, -1);
            bpf_cpumask_clear_cpu(cpu, buffer);
        }
        goto out_primary;
    }

    // Fallback to default selection
    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

out_primary:
    
    struct pcpu_ctx *pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (pcpu_ctx && pcpu_ctx->scheduled_degrade) {
        // Get current cache miss rate
        u64 *cache_misses, *cache_loads;
        u32 key = 0;
        cache_misses = bpf_map_lookup_percpu_elem(&cache_misses_map, &key, cpu);
        cache_loads = bpf_map_lookup_percpu_elem(&cache_loads_map, &key, cpu);
        u64 current_cache_miss_rate = *cache_misses / *cache_loads;
        u64 last_cache_miss_rate = pcpu_ctx->last_cache_miss_rate;
        if(current_cache_miss_rate- last_cache_miss_rate < 0.08) {
            // Cancel the degrade timer
            int err = bpf_timer_cancel(&pcpu_ctx->timer);
            if (err < 0) {
                scx_bpf_error("Failed to cancel pcpu timer");
            }
            pcpu_ctx->scheduled_degrade = false;
        }

    }


    if (tctx->prev_cpu == cpu)
    {
        tctx->prefer_core = cpu;
        // Set the prefer core to primary set
        if (!bpf_cpumask_test_cpu(cpu, cast_mask(primary))&&!bpf_cpumask_test_cpu(cpu, cast_mask(buffer))) {
            bpf_cpumask_set_cpu(cpu, primary);

        }
    }

    tctx->prev_cpu = prev_cpu;

    bpf_rcu_read_unlock();

    if (is_idle) {
        stat_inc(0);
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}
void BPF_STRUCT_OPS(kun_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

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



s32 BPF_STRUCT_OPS(kun_dispatch, s32 cpu, struct task_struct *prev)
{
    struct pcpu_ctx *pcpu_ctx;
    struct bpf_cpumask *primary, *buffer;
    bool in_primary;
    s32 ret = 0;

    // Try to consume next task
    if (scx_bpf_consume(SHARED_DSQ))
        return 0;

    bpf_rcu_read_lock();
    primary = primary_cpumask;
    buffer = buffer_cpumask;

    if (!primary || !buffer) {
        bpf_rcu_read_unlock();
        return -EINVAL;
    }

    pcpu_ctx = bpf_map_lookup_elem(&pcpu_ctxs, &cpu);
    if (!pcpu_ctx) {
        bpf_rcu_read_unlock();
        return -ENOENT;
    }

    in_primary = bpf_cpumask_test_cpu(cpu, cast_mask(primary));

    // Keep task local if still runnable
    if (prev && (prev->scx.flags & SCX_TASK_QUEUED) && in_primary) {
        scx_bpf_dispatch(prev, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        bpf_rcu_read_unlock();
        return 0;
    }

    // Handle CPU degrade
    if (in_primary) {
        if (prev && prev->__state == TASK_DEAD) {
            // Immediate degrade if task died
            bpf_cpumask_clear_cpu(cpu, primary);
            try_make_core_buffer(cpu, buffer, false);
        } else {
            // Record initial cache miss rate
            u64 *cache_misses, *cache_loads;
            u32 key = 0;
            cache_misses = bpf_map_lookup_percpu_elem(&cache_misses_map, &key, cpu);
            cache_loads = bpf_map_lookup_percpu_elem(&cache_loads_map, &key, cpu);
            
            if (cache_misses && cache_loads) {
                pcpu_ctx->last_cache_miss_rate = *cache_misses / *cache_loads;
            }

            // Schedule degrade timer
            pcpu_ctx->scheduled_degrade = true;
            bpf_timer_start(&pcpu_ctx->timer, P_REMOVE_NS, BPF_F_TIMER_CPU_PIN);
            bpf_timer_set_callback(&pcpu_ctx->timer, degrade_primary_core);

        }
    }

    bpf_rcu_read_unlock();
    return ret;
}

void BPF_STRUCT_OPS(kun_running, struct task_struct *p)
{

	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	// record current cache miss rate(misses/loades) for the current CPU
	u64 *cache_misses;
	u64 *cache_loads;
    s32 cpu = bpf_get_smp_processor_id();
	u32 key = 0;

	cache_misses = bpf_map_lookup_percpu_elem(&cache_misses_map, &key, cpu);
	cache_loads = bpf_map_lookup_percpu_elem(&cache_loads_map, &key, cpu);

	if (cache_misses && cache_loads) {
		struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (tctx) {
			tctx->last_cache_miss_rate = *cache_misses / *cache_loads;
		}
	}
	

}

void BPF_STRUCT_OPS(kun_stopping, struct task_struct *p, bool runnable)
{

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

	// Re record current cache miss rate(misses/loades) for the current CPU, compare it with the last cache miss rate
	// compute the change rate, if it is greater than 5%, set the task as limited
	u64 *cache_misses;
	u64 *cache_loads;
    s32 cpu = bpf_get_smp_processor_id();
	u32 key = 0;

	cache_misses = bpf_map_lookup_percpu_elem(&cache_misses_map, &key, cpu);
	cache_loads = bpf_map_lookup_percpu_elem(&cache_loads_map, &key, cpu);

	if (cache_misses && cache_loads) {
		struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (tctx) {
			u64 current_cache_miss_rate = *cache_misses / *cache_loads;
			u64 change_rate = (current_cache_miss_rate - tctx->last_cache_miss_rate) / tctx->last_cache_miss_rate;
			if (change_rate > 0.08) {
				tctx->isLimited = true;
			}
		}
	}

}

void BPF_STRUCT_OPS(kun_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;

}



s32 BPF_STRUCT_OPS_SLEEPABLE(kun_init)
{
    struct bpf_cpumask *cpumask;
    int ret;
    s32 cpu;
	int err;
	struct bpf_timer *timer;
	u32 key = 0;

    ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
    if (ret)
        return ret;

    // Initialize primary set
    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;
    bpf_cpumask_clear(cpumask);
    cpumask = bpf_kptr_xchg(&primary_cpumask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);

    // Initialize buffer set
    cpumask = bpf_cpumask_create();
    if (!cpumask)
        return -ENOMEM;
    bpf_cpumask_clear(cpumask);
    cpumask = bpf_kptr_xchg(&buffer_cpumask, cpumask);
    if (cpumask)
        bpf_cpumask_release(cpumask);
    return 0;
}

SCX_OPS_DEFINE(kun_ops,
	       .select_cpu		= (void *)kun_select_cpu,
	       .enqueue			= (void *)kun_enqueue,
	       .dispatch		= (void *)kun_dispatch,
	       .running			= (void *)kun_running,
	       .stopping		= (void *)kun_stopping,
	       .enable			= (void *)kun_enable,
	       .init			= (void *)kun_init,
	       .name			= "kun");