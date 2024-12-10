#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared_maps.h"



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