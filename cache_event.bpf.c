
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>  
#include <stdint.h>        

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 128);
} cache_miss_stats SEC(".maps");

SEC("perf_event")
int handle_cache_miss(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    u64 *count = bpf_map_lookup_elem(&cache_miss_stats, &cpu);

    if (!count) {
        return 0;
    }

    u64 misses = bpf_perf_event_read(ctx, 0);
    if ((s64)misses < 0) {
        return 0;
    }

    *count += misses;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
