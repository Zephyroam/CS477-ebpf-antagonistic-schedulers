/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include "include/scx/common.h"
#include "scx_kun.bpf.skel.h"

const char help_fmt[] =
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n";


static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int kun)
{
	exit_req = 1;
}

static void read_stats(struct scx_kun_bpf *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}



/*******************/

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
    memset(attr, 0, sizeof(struct perf_event_attr));

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
    memset(attr, 0, sizeof(struct perf_event_attr));

    attr->type = PERF_TYPE_HW_CACHE;
    attr->size = sizeof(struct perf_event_attr);
    attr->config = (PERF_COUNT_HW_CACHE_L1D |
                    PERF_COUNT_HW_CACHE_OP_READ << 8 |
                    PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16);
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

/*******************/



int main(int argc, char **argv)
{
	struct scx_kun_bpf *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(kun_ops, scx_kun_bpf);

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, kun_ops, scx_kun_bpf, uei);
	link = SCX_OPS_ATTACH(skel, kun_ops, scx_kun_bpf);


	/*******************/
	// get eBPF program and map
    struct bpf_program *count_cache_misses_prog;
    struct bpf_program *count_cache_loads_prog;
    int cache_misses_map_fd, cache_loads_map_fd;
    struct perf_event_attr *attr_cache_misses;
    struct perf_event_attr *attr_cache_loads;
	int err;
	
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
        printf("Attaching eBPF program to CPU %d\n", cpu);
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

	/*******************/

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];


		read_stats(skel, stats);

		printf("local=%llu global=%llu\n", stats[0], stats[1]);

		fflush(stdout);


		/*******************/
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
		/*******************/


		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_kun_bpf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}