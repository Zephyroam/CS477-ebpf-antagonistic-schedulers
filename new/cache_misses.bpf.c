#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} cache_misses_map SEC(".maps");


SEC("perf_event")
int count_cache_misses(struct bpf_perf_event_value *ctx) {
    u64 *counter;
    u32 key = 0;

    // Access the map and increment the counter
    counter = bpf_map_lookup_elem(&cache_misses_map, &key);
    if (counter) {
        (*counter)++;
    }
    bpf_printk("GOT QQQQ");
    return 0;
}

char _license[] SEC("license") = "GPL";
