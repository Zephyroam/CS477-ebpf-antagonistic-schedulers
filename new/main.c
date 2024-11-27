#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdint.h>
#include "cache_misses.bpf.skel.h"

#define CHECK(condition, message) \
    if (condition) {              \
        perror(message);          \
        exit(EXIT_FAILURE);       \
    }

int main() {
    struct cache_misses_bpf *skel;
    int err;
    int map_fd;

    skel = cache_misses_bpf__open();
    CHECK(!skel, "cache_misses_bpf__open");

    err = cache_misses_bpf__load(skel);
    CHECK(err, "cache_misses_bpf__load");

    err = cache_misses_bpf__attach(skel);
    CHECK(err, "cache_misses_bpf__attach");

    printf("eBPF program successfully attached. Monitoring CACHE_MISSES...\n");

    map_fd = bpf_map__fd(skel->maps.cache_misses_map);
    CHECK(map_fd < 0, "bpf_map__fd");

    while (1) {
        uint64_t count = 0;
        int key = 0;

        err = bpf_map_lookup_elem(map_fd, &key, &count);
        CHECK(err, "bpf_map_lookup_elem");

        printf("CACHE_MISSES: %llu\n", count);
        sleep(1);
    }

    cache_misses_bpf__destroy(skel);
    return 0;
}
