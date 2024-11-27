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
    attr.disabled = 0;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 0;

    // 获取 CPU 数量
    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    CHECK(num_cpus < 1, "sysconf");

    int perf_fd;

    prog_fd = bpf_program__fd(prog);

    printf("%d", num_cpus);

    perf_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (perf_fd < 0) {
        perror("perf_event_open");
        return 0;
    }

    err = ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    if (err) {
        perror("PERF_EVENT_IOC_SET_BPF");
        close(perf_fd);
        perf_fd = -1;
        return 0;
    }
    err = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    if (err) {
        perror("PERF_EVENT_IOC_SET_BPF");
        close(perf_fd);
        perf_fd = -1;
        return 0;
    }

    err = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    if (err) {
        perror("PERF_EVENT_IOC_ENABLE");
        close(perf_fd);
        perf_fd = -1;
        return 0;
    }

    printf("eBPF program successfully attached. Monitoring L1-dcache-load-misses...\n");

    printf("%d", libbpf_num_possible_cpus());
    // 监控结果
    while (1) {
        uint64_t total_count = 0;
        uint32_t key = 0;


        err = bpf_map_lookup_elem(map_fd, &key, &total_count);
        CHECK(err, "bpf_map_lookup_elem");

        printf("L1-dcache-load-misses: %llu\n", total_count);
        long long count;
        if (read(perf_fd, &count, sizeof(long long)) == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        printf("%d\n", count);

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
