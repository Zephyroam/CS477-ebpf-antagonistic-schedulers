#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include "cache_misses.bpf.skel.h"

#define CHECK(condition, message) \
    if (condition) {              \
        perror(message);          \
        exit(EXIT_FAILURE);       \
    }

int main() {
    struct cache_misses_bpf *skel;
    struct bpf_program *prog;
    struct bpf_map *map;
    int map_fd, prog_fd;
    int num_cpus;
    int *perf_fds;
    struct perf_event_attr attr = {};
    int err;

    // 加载 eBPF 程序
    skel = cache_misses_bpf__open();
    CHECK(!skel, "cache_misses_bpf__open");

    err = cache_misses_bpf__load(skel);
    CHECK(err, "cache_misses_bpf__load");

    // 获取 eBPF 程序和映射
    prog = skel->progs.count_cache_misses;
    CHECK(!prog, "bpf_object__find_program_by_name");

    map = skel->maps.cache_misses_map;
    CHECK(!map, "bpf_object__find_map_by_name");

    map_fd = bpf_map__fd(map);

    // 设置性能事件属性以监控 L1-dcache-load-misses
    attr.type = PERF_TYPE_HW_CACHE;
    attr.size = sizeof(struct perf_event_attr);
    attr.config = PERF_COUNT_HW_CACHE_L1D |
                  (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                  (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    attr.sample_period = 0;
    attr.sample_type = 0;
    attr.disabled = 0;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 0;

    // 获取 CPU 数量
    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    CHECK(num_cpus < 1, "sysconf");

    perf_fds = calloc(num_cpus, sizeof(int));
    CHECK(!perf_fds, "calloc");

    prog_fd = bpf_program__fd(prog);

    // 为每个 CPU 打开性能事件并附加 eBPF 程序
    for (int i = 0; i < num_cpus; i++) {
        perf_fds[i] = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
        if (perf_fds[i] < 0) {
            perror("perf_event_open");
            continue;
        }

        err = ioctl(perf_fds[i], PERF_EVENT_IOC_SET_BPF, prog_fd);
        if (err) {
            perror("PERF_EVENT_IOC_SET_BPF");
            close(perf_fds[i]);
            perf_fds[i] = -1;
            continue;
        }

        err = ioctl(perf_fds[i], PERF_EVENT_IOC_ENABLE, 0);
        if (err) {
            perror("PERF_EVENT_IOC_ENABLE");
            close(perf_fds[i]);
            perf_fds[i] = -1;
            continue;
        }
    }

    printf("eBPF program successfully attached. Monitoring L1-dcache-load-misses...\n");

    // 监控结果
    while (1) {
        uint64_t total_count = 0;
        uint32_t key = 0;
        uint64_t *counts;
        int cpu_count;

        // 为每个 CPU 读取计数
        cpu_count = bpf_num_possible_cpus();
        counts = calloc(cpu_count, sizeof(uint64_t));
        CHECK(!counts, "calloc");

        err = bpf_map_lookup_elem(map_fd, &key, counts);
        CHECK(err, "bpf_map_lookup_elem");

        for (int i = 0; i < cpu_count; i++) {
            total_count += counts[i];
        }

        printf("L1-dcache-load-misses: %llu\n", total_count);

        free(counts);
        sleep(1);
    }

    // 清理资源
    for (int i = 0; i < num_cpus; i++) {
        if (perf_fds[i] >= 0) {
            close(perf_fds[i]);
        }
    }
    free(perf_fds);
    cache_misses_bpf__destroy(skel);
    return 0;
}
