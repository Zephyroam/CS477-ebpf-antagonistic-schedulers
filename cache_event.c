#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PERF_EVENT_TYPE PERF_TYPE_HW_CACHE
#define PERF_EVENT_CONFIG PERF_COUNT_HW_CACHE_MISSES
#define MAP_PATH "/sys/fs/bpf/sched_ext/cache_miss_even"  /*where is this BPF map path?*/
#define MAX_CPUS 12                              

int open_perf_event(int type, int config, int cpu) {
    struct perf_event_attr attr = {
        .type = type,
        .config = config,
        .size = sizeof(struct perf_event_attr),
        .disabled = 0,
        .exclude_kernel = 0,
        .exclude_hv = 0,
    };

    int fd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed to open perf event for CPU %d: %s\n", cpu, strerror(errno));
    }
    return fd;
}

int main() {
    int map_fd, cpu, fd;
    int key;

    /* Open map*/
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open BPF map at %s: %s\n", MAP_PATH, strerror(errno));
        return 1;
    }

   
    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        fd = open_perf_event(PERF_EVENT_TYPE, PERF_EVENT_CONFIG, cpu);
        if (fd < 0) {
            fprintf(stderr, "Skipping CPU %d due to error\n", cpu);
            continue; 
        }

        key = cpu;
        if (bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to update BPF map for CPU %d: %s\n", cpu, strerror(errno));
            close(fd); 
            printf("Successfully added perf event for CPU %d\n", cpu);
        }
    }

    close(map_fd);
    return 0;
}
