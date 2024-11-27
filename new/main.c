#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <stdint.h>


#define CHECK(condition, message) \
    if (condition) {              \
        perror(message);          \
        exit(EXIT_FAILURE);       \
    }

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int map_fd, prog_fd, perf_fd;
    struct perf_event_attr attr = {};

    // Load eBPF program
    obj = bpf_object__open_file("cache_misses.bpf.o", NULL);
    CHECK(!obj, "bpf_object__open_file");

    CHECK(bpf_object__load(obj), "bpf_object__load");

    // Get the program and map
    prog = bpf_object__find_program_by_name(obj, "count_cache_misses");
    CHECK(!prog, "bpf_object__find_program_by_name");

    map = bpf_object__find_map_by_name(obj, "cache_misses_map");
    CHECK(!map, "bpf_object__find_map_by_name");

    map_fd = bpf_map__fd(map);

    // Attach the program to the PERF_EVENT
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CACHE_MISSES;
    attr.size = sizeof(attr);
    attr.sample_period = 0;
    attr.sample_type = 0;

    perf_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    CHECK(perf_fd < 0, "perf_event_open");

    prog_fd = bpf_program__fd(prog);
    CHECK(ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd), "PERF_EVENT_IOC_SET_BPF");

    // Enable the PERF_EVENT
    CHECK(ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0), "PERF_EVENT_IOC_ENABLE");

    printf("eBPF program successfully attached. Monitoring CACHE_MISSES...\n");

    // Monitor results
    while (1) {
        uint64_t count = 0;
        CHECK(bpf_map_lookup_elem(map_fd, &(uint32_t){0}, &count), "bpf_map_lookup_elem");
        printf("CACHE_MISSES: %llu\n", count);
        sleep(1);
    }

    close(perf_fd);
    bpf_object__close(obj);
    return 0;
}
