#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <vector>
#include <gflags/gflags.h>
#include <stdint.h>
#include <bits/types.h>
#include <utils/time_utils.h>


DEFINE_int32(run_time, 5, "Running time (s) of the experiment.");
DEFINE_double(period, 100, "For each period (ms), the worker uses a fixed share of CPU time.");
DEFINE_int32(num_workers, 1, "The number of workers.");
DEFINE_double(work_share, 1.0,
              "Each thread tries to target this share of the cycles on a CPU. "
              "For example, if 'work_share' is 0.5, each thread tries to target 50% of cycles on a CPU. "
              "Note that 'work_share' must be >=0.0 and <=1.0.");
DEFINE_string(output_path, "/tmp/skyloft_synthetic", "The path to the experiment results.");

#define USED_CPUS 64


struct worker_t {
    __nsec start;
    __nsec usage;
    int nth;
    int cpu_id; // If you want to bind each thread to a specific CPU
};

static struct worker_t workers[USED_CPUS];

void* synthetic_worker(void *arg) {
    struct worker_t *worker = (struct worker_t *)arg;
    __nsec period = (__nsec)(FLAGS_period * NSEC_PER_MSEC);
    __nsec share = (__nsec)(FLAGS_work_share * period);

    if (!worker->start) {
        worker->start = now_ns();
    }

    __nsec end_time = worker->start + FLAGS_run_time * NSEC_PER_SEC;

    while (1) {
        __nsec current_time = now_ns();
        if (current_time > end_time) {
            break;
        }

        // Determine which period we are in
        int n = (int)((current_time - worker->start + period - 1) / period);
        if (n <= worker->nth) {
            // Not reached the next period yet, yield CPU
            sched_yield();
            continue;
        }
        worker->nth = n;

        __nsec finish = worker->start + n * period;
        __nsec usage = 0;
        __nsec usage_start = now_ns();

        // Busy-wait to achieve the desired CPU usage share
        while ((now_ns() < finish) && ((usage = now_ns() - usage_start) < share)) {
            // busy loop
        }

        worker->usage += usage;
        sched_yield();
    }

    return NULL;
}

static void write_results() {
    __nsec usage_total = 0;
    printf("Antagonist CPU share:\n");
    for (int i = 0; i < FLAGS_num_workers; i++) {
        usage_total += workers[i].usage;
        double worker_share = (double)workers[i].usage / (FLAGS_run_time * (double)NSEC_PER_SEC);
        printf("\tWorker %d: %.3lf\n", i+1, worker_share);
    }
    double avg_share = (double)usage_total / (FLAGS_run_time * (double)NSEC_PER_SEC * FLAGS_num_workers);
    printf("\tTotal: %.3lf\n", avg_share);

    FILE *file = fopen(FLAGS_output_path.c_str(), "a");
    if (file) {
        fprintf(file, "%.3lf\n", avg_share);
        fclose(file);
    }
}

int main(int argc, char **argv) {
    gflags::SetUsageMessage("antagonist [options]");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_num_workers > USED_CPUS) {
        fprintf(stderr, "Too many workers\n");
        exit(EXIT_FAILURE);
    }

    gflags::ShutDownCommandLineFlags();

    printf("Antagonist with %d thread(s)\n", FLAGS_num_workers);

    // Initialize worker structures
    for (int i = 0; i < FLAGS_num_workers; i++) {
        workers[i].start = 0;
        workers[i].usage = 0;
        workers[i].nth = -1;
        workers[i].cpu_id = i; // Potential CPU assignment, if needed
    }

    std::vector<pthread_t> threads(FLAGS_num_workers);

    // Create worker threads
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        // Optional: set CPU affinity
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(workers[i].cpu_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset) != 0) {
            perror("pthread_attr_setaffinity_np");
        }

        if (pthread_create(&threads[i], &attr, synthetic_worker, (void*)&workers[i]) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }

        pthread_attr_destroy(&attr);
    }

    // Wait for all threads to finish
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    // Write out the results
    write_results();

    return 0;
}
