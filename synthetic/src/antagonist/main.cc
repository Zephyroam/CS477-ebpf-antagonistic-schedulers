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
// 可根据情况调整buffer大小，如512MB，1GB等

#define NSEC_PER_SEC 1000000000ULL
#define USED_CPUS 64

static inline __nsec now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__nsec)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

struct worker_t {
    __nsec start;
    uint64_t bytes_processed; // 本线程处理的字节数
    int cpu_id;               // CPU亲和度ID
};

// 全局workers数组
static struct worker_t workers[USED_CPUS];

// 全局缓冲区指针
static char *global_buffer = NULL;
static uint64_t global_buffer_size = 0; // 字节数

void* memory_bandwidth_worker(void *arg) {
    struct worker_t *worker = (struct worker_t *)arg;
    worker->bytes_processed = 0;

    worker->start = now_ns();
    __nsec end_time = worker->start + ((__nsec)FLAGS_run_time * NSEC_PER_SEC);

    // 简单的内存访问模式：重复地遍历global_buffer
    // 模拟：对缓冲区进行读操作（可再加上简单的写操作）
    uint64_t offset = 0;
    uint64_t processed = 0;

    // 为了避免编译器优化，可以引入一个累加变量
    uint64_t sum = 0;

    while (now_ns() < end_time) {
        // 从global_buffer读取一个缓存行或一定大小的数据进行处理
        // 比如一次读取64字节(一个cache line)
        // 这里简单地逐字节累加
        for (int i = 0; i < 64; i++) {
            sum += (uint8_t)global_buffer[offset + i];
        }

        offset += 64;
        processed += 64;

        // 若到达缓冲区末尾，从头开始
        if (offset + 64 >= global_buffer_size) {
            offset = 0;
        }
    }

    worker->bytes_processed = processed;
    // sum的值不会真正影响工作负载性能，但可以防止优化器将读取消除
    // 最终不使用sum的结果，只是确保实际有访问内存
    return NULL;
}

static void write_results() {
    uint64_t total_bytes = 0;
    for (int i = 0; i < FLAGS_num_workers; i++) {
        total_bytes += workers[i].bytes_processed;
    }

    double total_time = (double)FLAGS_run_time; // 运行时间(秒)
    double avg_bandwidth = (double)total_bytes / total_time / (double)FLAGS_num_workers; 
    // avg_bandwidth为每个worker平均带宽(字节/秒)

    printf("Memory Bandwidth Intensive Workload Results:\n");
    for (int i = 0; i < FLAGS_num_workers; i++) {
        double bw = (double)workers[i].bytes_processed / total_time;
        // 转换为MB/s显示 (1MB = 1024*1024字节)
        double bw_mb_s = bw / (1024.0 * 1024.0);
        printf("\tWorker %d: %.3f MB/s\n", i+1, bw_mb_s);
    }

    double total_bw = (double)total_bytes / total_time; // 总带宽（字节/秒）
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

    // 根据用户指定的buffer大小分配内存
    // 将MB转换为字节
    global_buffer_size = FLAGS_buffer_size_mb * 1024ULL * 1024ULL;
    global_buffer = (char*)malloc(global_buffer_size);
    if (!global_buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        exit(EXIT_FAILURE);
    }

    // 初始化缓冲区（可选）- 这里简单赋值
    for (uint64_t i = 0; i < global_buffer_size; i++) {
        global_buffer[i] = (char)(i & 0xFF);
    }

    gflags::ShutDownCommandLineFlags();

    printf("Starting memory bandwidth intensive workload with %d thread(s)\n", FLAGS_num_workers);
    printf("Buffer size: %lu MB\n", (unsigned long)FLAGS_buffer_size_mb);

    // 初始化workers
    for (int i = 0; i < FLAGS_num_workers; i++) {
        workers[i].cpu_id = i;
    }

    std::vector<pthread_t> threads(FLAGS_num_workers);

    // 创建线程
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        // 可选：将线程绑定到指定CPU
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

    // 等待所有线程结束
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    // 输出结果
    write_results();

    free(global_buffer);

    return 0;
}
