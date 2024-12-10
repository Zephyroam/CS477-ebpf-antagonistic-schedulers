#ifndef _SHARED_MAPS_H_
#define _SHARED_MAPS_H_

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // Change to per-CPU array
    __uint(max_entries, 12);                   // One entry per CPU
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);      // Enable map sharing
    __uint(map_flags, BPF_F_PRESERVE_ELEMS);  // Preserve values
} cache_misses_map SEC(".maps") __weak;       // __weak allows sharing

#endif