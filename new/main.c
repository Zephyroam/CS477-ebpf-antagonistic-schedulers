#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include "cache_misses.bpf.skel.h"

#define CHECK(condition, message) \
    if (condition) {              \
        perror(message);          \
        exit(EXIT_FAILURE);       \
    }

struct perf_event_attr *create_perf_event_attr_for_cache_misses() {
    struct perf_event_attr *attr = malloc(sizeof(struct perf_event_attr));
    if (!attr) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    attr->type = PERF_TYPE_HW_CACHE;
    attr->size = sizeof(struct perf_event_attr);
    attr->config = (PERF_COUNT_HW_CACHE_L1D |
                    PERF_COUNT_HW_CACHE_OP_READ << 8 |
                    PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    attr->disabled = 0;
    attr->sample_type = PERF_SAMPLE_IP;
    attr->exclude_kernel = 1;
    attr->exclude_hv = 1;
    attr->freq = 0;
    attr->sample_period = 1000;

    return attr;
}

struct perf_event_attr *create_perf_event_attr_for_cache_loads() {
    struct perf_event_attr *attr = malloc(sizeof(struct perf_event_attr));
    if (!attr) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    attr->type = PERF_TYPE_HW_CACHE;
    attr->size = sizeof(struct perf_event_attr);
    attr->config = (PERF_COUNT_HW_CACHE_L1D |
                    PERF_COUNT_HW_CACHE_OP_READ << 8 |
                    PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    attr->disabled = 0;
    attr->sample_type = PERF_SAMPLE_IP;
    attr->exclude_kernel = 1;
    attr->exclude_hv = 1;
    attr->freq = 0;
    attr->sample_period = 1000;

    return attr;
}

int open_and_load_bpf_program(struct bpf_program *prog, struct perf_event_attr *attr, int cpu) {
    int prog_fd;
    int perf_fd;
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        perror("bpf_program__fd");
        return -1;
    }

    perf_fd = syscall(SYS_perf_event_open, attr, -1, cpu, -1, 0);
    if (perf_fd < 0) {
        perror("perf_event_open");
        return -1;
    }

    int err = ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    if (err) {
        perror("PERF_EVENT_IOC_SET_BPF");
        close(perf_fd);
        perf_fd = -1;
        return -1;
    }

    err = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (err) {
        perror("PERF_EVENT_IOC_SET_BPF");
        close(perf_fd);
        perf_fd = -1;
        return -1;
    }

    err = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (err) {
        perror("PERF_EVENT_IOC_ENABLE");
        close(perf_fd);
        perf_fd = -1;
        return -1;
    }

    return perf_fd;
}

int main() {
    struct cache_misses_bpf *skel;
    struct bpf_program *count_cache_misses_prog;
    struct bpf_program *count_cache_loads_prog;
    int cache_misses_map_fd, cache_loads_map_fd;
    struct perf_event_attr *attr_cache_misses;
    struct perf_event_attr *attr_cache_loads;
    int err;

    // load eBPF program
    skel = cache_misses_bpf__open();
    CHECK(!skel, "cache_misses_bpf__open");

    err = cache_misses_bpf__load(skel);
    CHECK(err, "cache_misses_bpf__load");

    // get eBPF program and map
    count_cache_misses_prog = skel->progs.count_cache_misses;
    CHECK(!count_cache_misses_prog, "skel->progs.count_cache_misses");

    count_cache_loads_prog = skel->progs.count_cache_loads;
    CHECK(!count_cache_loads_prog, "skel->progs.count_cache_loads");

    cache_misses_map_fd = bpf_map__fd(skel->maps.cache_misses_map);
    CHECK(cache_misses_map_fd < 0, "bpf_map__fd");

    cache_loads_map_fd = bpf_map__fd(skel->maps.cache_loads_map);
    CHECK(cache_loads_map_fd < 0, "bpf_map__fd");
    
    // create perf_event_attr for cache misses
    attr_cache_misses = create_perf_event_attr_for_cache_misses();

    // create perf_event_attr for cache loads
    attr_cache_loads = create_perf_event_attr_for_cache_loads();

    int num_cpus = get_nprocs();

    int *perf_fds_cache_misses = calloc(num_cpus, sizeof(int));
    int *perf_fds_cache_loads = calloc(num_cpus, sizeof(int));
    CHECK(!perf_fds_cache_misses || !perf_fds_cache_loads, "Failed to allocate memory for perf_fds");

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        perf_fds_cache_misses[cpu] = open_and_load_bpf_program(count_cache_misses_prog, attr_cache_misses, cpu);
        CHECK(perf_fds_cache_misses[cpu] < 0, "open_and_load_bpf_program for cache misses");

        perf_fds_cache_loads[cpu] = open_and_load_bpf_program(count_cache_loads_prog, attr_cache_loads, cpu);
        CHECK(perf_fds_cache_loads[cpu] < 0, "open_and_load_bpf_program for cache loads");
    }

    printf("eBPF program successfully attached. Monitoring L1-dcache-load-misses and L1-dcache-loads...\n");

    uint64_t *cpu_counts = calloc(num_cpus, sizeof(uint64_t));
    if (!cpu_counts) {
        perror("Failed to allocate memory for CPU counts");
        return EXIT_FAILURE;
    }

    while (1) {
        uint32_t key = 0;

        memset(cpu_counts, 0, num_cpus * sizeof(uint64_t));
        err = bpf_map_lookup_elem(cache_misses_map_fd, &key, cpu_counts);
        CHECK(err, "Failed to read from BPF map");

        uint64_t total_count = 0;
        printf("Per-CPU L1-dcache-load-misses:\n");
        for (int i = 0; i < num_cpus; i++) {
            printf("  CPU %d: %llu\n", i, cpu_counts[i]);
            total_count += cpu_counts[i];
        }
        printf("Total L1-dcache-load-misses: %llu\n", total_count);


        memset(cpu_counts, 0, num_cpus * sizeof(uint64_t));
        err = bpf_map_lookup_elem(cache_loads_map_fd, &key, cpu_counts);
        CHECK(err, "Failed to read from BPF map");

        total_count = 0;
        printf("Per-CPU L1-dcache-loads:\n");
        for (int i = 0; i < num_cpus; i++) {
            printf("  CPU %d: %llu\n", i, cpu_counts[i]);
            total_count += cpu_counts[i];
        }
        printf("Total L1-dcache-loads: %llu\n", total_count);

        sleep(1);
    }

    free(cpu_counts);
    cache_misses_bpf__destroy(skel);
    // Free resources at the end
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        close(perf_fds_cache_misses[cpu]);
        close(perf_fds_cache_loads[cpu]);
    }
    free(perf_fds_cache_misses);
    free(perf_fds_cache_loads);
    return 0;
}
