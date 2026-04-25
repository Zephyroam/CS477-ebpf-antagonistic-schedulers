#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <vector>
#include <gflags/gflags.h>
#include <stdint.h>

typedef uint64_t __nsec;

DEFINE_int32(run_time, 5, "Running time (s) of the experiment.");
DEFINE_int32(num_workers, 1, "The number of worker threads.");
DEFINE_string(output_path, "/tmp/membw_result", "The path to write the experiment results.");
DEFINE_uint64(buffer_size_mb, 512, "Size of the buffer in MB to be used for memory bandwidth test."); 

#define NSEC_PER_SEC 1000000000ULL
#define USED_CPUS 64

static inline __nsec now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__nsec)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

struct worker_t {
    __nsec start;
    uint64_t bytes_processed; // The number of bytes processed by the worker
    int cpu_id;               // CPU ID to which the worker is bound
};

// global workers array
static struct worker_t workers[USED_CPUS];

// global buffer
static char *global_buffer = NULL;
static uint64_t global_buffer_size = 0; // global buffer size in bytes

void* memory_bandwidth_worker(void *arg) {
    struct worker_t *worker = (struct worker_t *)arg;
    worker->bytes_processed = 0;

    worker->start = now_ns();
    __nsec end_time = worker->start + ((__nsec)FLAGS_run_time * NSEC_PER_SEC);

    // simple memory access pattern: repeatedly traverse the global_buffer
    // simulate: read operations on the buffer (can add simple write operations)
    uint64_t offset = 0;
    uint64_t processed = 0;

    // to prevent the optimizer from eliminating the loop
    uint64_t sum = 0;

    while (now_ns() < end_time) {
        // read a cache line or a fixed size of data from global_buffer for processing
        // e.g., read 64 bytes (a cache line) at a time
        // here, simply accumulate byte by byte
        for (int i = 0; i < 64; i++) {
            sum += (uint8_t)global_buffer[offset + i];
        }

        offset += 64;
        processed += 64;

        // reset the offset if it reaches the end of the buffer
        if (offset + 64 >= global_buffer_size) {
            offset = 0;
        }
    }

    worker->bytes_processed = processed;
    return NULL;
}

static void write_results() {
    uint64_t total_bytes = 0;
    for (int i = 0; i < FLAGS_num_workers; i++) {
        total_bytes += workers[i].bytes_processed;
    }

    double total_time = (double)FLAGS_run_time; // total time in seconds
    double avg_bandwidth = (double)total_bytes / total_time / (double)FLAGS_num_workers; 
    // avg_bandwidth is in bytes per second

    printf("Memory Bandwidth Intensive Workload Results:\n");
    for (int i = 0; i < FLAGS_num_workers; i++) {
        double bw = (double)workers[i].bytes_processed / total_time;
        double bw_mb_s = bw / (1024.0 * 1024.0);
        printf("\tWorker %d: %.3f MB/s\n", i+1, bw_mb_s);
    }

    double total_bw = (double)total_bytes / total_time; // total bandwidth in bytes per second
    double total_bw_mb_s = total_bw / (1024.0 * 1024.0);
    double avg_bw_mb_s = total_bw_mb_s / FLAGS_num_workers; 
    printf("\tAverage: %.3f MB/s per worker\n", avg_bw_mb_s);
    printf("\tTotal  : %.3f MB/s\n", total_bw_mb_s);

    FILE *file = fopen(FLAGS_output_path.c_str(), "a");
    if (file) {
        fprintf(file, "%.3f\n", total_bw_mb_s);
        fclose(file);
    }
}

int main(int argc, char **argv) {
    gflags::SetUsageMessage("memory_bandwidth_test [options]");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    if (FLAGS_num_workers > USED_CPUS) {
        fprintf(stderr, "Too many workers\n");
        exit(EXIT_FAILURE);
    }

    // allocate memory based on the buffer size specified by the user
    // convert MB to bytes
    global_buffer_size = FLAGS_buffer_size_mb * 1024ULL * 1024ULL;
    global_buffer = (char*)malloc(global_buffer_size);
    if (!global_buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        exit(EXIT_FAILURE);
    }

    // initialize the buffer with some data
    for (uint64_t i = 0; i < global_buffer_size; i++) {
        global_buffer[i] = (char)(i & 0xFF);
    }

    gflags::ShutDownCommandLineFlags();

    printf("Starting memory bandwidth intensive workload with %d thread(s)\n", FLAGS_num_workers);
    printf("Buffer size: %lu MB\n", (unsigned long)FLAGS_buffer_size_mb);

    // initialize workers
    for (int i = 0; i < FLAGS_num_workers; i++) {
        workers[i].cpu_id = i;
    }

    std::vector<pthread_t> threads(FLAGS_num_workers);

    // create worker threads
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        // optional: set the CPU affinity of the thread
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(workers[i].cpu_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset) != 0) {
            perror("pthread_attr_setaffinity_np");
        }

        if (pthread_create(&threads[i], &attr, memory_bandwidth_worker, (void*)&workers[i]) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }

        pthread_attr_destroy(&attr);
    }

    // wait for all worker threads to finish
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    // write the results to the output file
    write_results();

    free(global_buffer);

    return 0;
}
