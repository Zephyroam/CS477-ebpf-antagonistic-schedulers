#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <gflags/gflags.h>
#include <rocksdb/c.h>
#include "utils/time_utils.h"
#include "common.h"
#include "random.h"

#define MAX_QUEUE_SIZE 1024

typedef struct {
    request_t *requests;
    int issued;
    int processed;
    request_t *queue[MAX_QUEUE_SIZE];
    int queue_start;
    int queue_end;
} dispatcher_t;

static dispatcher_t *g_dispatcher;
static rocksdb_t *g_db;

dispatcher_t *dispatcher_create(void);
void do_dispatching(dispatcher_t *dispatcher);
void *worker_thread_func(void *arg);

// Initialize dispatcher
dispatcher_t *dispatcher_create(void)
{
    int i;
    dispatcher_t *dispatcher;

    int target_tput = target_throughput();
    int num_reqs = target_tput * FLAGS_run_time * 2;

    printf("Target throughput: %d req/s\n", target_tput);
    printf("Number of requests: %d\n", num_reqs);

    dispatcher = (dispatcher_t *)malloc(sizeof(dispatcher_t));
    dispatcher->requests = (request_t *)malloc(sizeof(request_t) * num_reqs);
    dispatcher->issued = 0;
    dispatcher->processed = 0;
    dispatcher->queue_start = 0;
    dispatcher->queue_end = 0;

    double timestamp = 0;
    for (i = 0; i < num_reqs; i++) {
        timestamp += random_exponential_distribution();
        init_request_bimodal(&dispatcher->requests[i], FLAGS_range_query_ratio,
                             FLAGS_range_query_size);
        dispatcher->requests[i].gen_time = timestamp * NSEC_PER_USEC;
    }

    return dispatcher;
}

static inline request_t *poll_synthetic_network(dispatcher_t *dispatcher, __nsec start_time)
{
    request_t *req = &dispatcher->requests[dispatcher->issued];

    if (now_ns() < start_time + req->gen_time)
        return NULL;

    req->gen_time += start_time;
    req->recv_time = now_ns();
    dispatcher->issued++;
    return req;
}

// Worker thread function
void *worker_thread_func(void *arg)
{
    dispatcher_t *dispatcher = (dispatcher_t *)arg;
    while (1) {
        request_t *req = NULL;

        // Check for requests in the queue
        while (dispatcher->queue_start == dispatcher->queue_end) {
            usleep(100); // Busy wait
        }

        req = dispatcher->queue[dispatcher->queue_start];
        dispatcher->queue_start = (dispatcher->queue_start + 1) % MAX_QUEUE_SIZE;

        if (!req) {
            break; // Exit signal received
        }

        req->start_time = now_ns();
        if (FLAGS_fake_work) {
            if (req->type == ROCKSDB_GET) {
                fake_work(FLAGS_get_service_time);
            } else if (req->type == ROCKSDB_RANGE) {
                fake_work(FLAGS_range_query_service_time);
            }
        } else {
            if (req->type == ROCKSDB_GET) {
                rocksdb_handle_get(g_db, req);
            } else if (req->type == ROCKSDB_RANGE) {
                rocksdb_handle_range_query(g_db, req);
            }
        }
        req->end_time = now_ns();

        dispatcher->processed++;
    }
    return NULL;
}

// Dispatching requests
void do_dispatching(dispatcher_t *dispatcher)
{
    request_t *req;
    __nsec start, end;
    start = now_ns();
    end = now_ns() + FLAGS_run_time * NSEC_PER_SEC;

    pthread_t workers[FLAGS_num_workers];
    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_create(&workers[i], NULL, worker_thread_func, dispatcher);
    }

    while (now_ns() < end) {
        req = poll_synthetic_network(dispatcher, start);
        if (req) {
            dispatcher->queue[dispatcher->queue_end] = req;
            dispatcher->queue_end = (dispatcher->queue_end + 1) % MAX_QUEUE_SIZE;
        }
    }

    // Signal workers to exit
    for (int i = 0; i < FLAGS_num_workers; i++) {
        dispatcher->queue[dispatcher->queue_end] = NULL;
        dispatcher->queue_end = (dispatcher->queue_end + 1) % MAX_QUEUE_SIZE;
    }

    for (int i = 0; i < FLAGS_num_workers; i++) {
        pthread_join(workers[i], NULL);
    }

    printf("Number of requests issued: %d\n", dispatcher->issued);
    printf("Number of requests processed: %d\n", dispatcher->processed);
}
int main(int argc, char **argv)
{
    gflags::SetUsageMessage("test_rocksdb [options]");
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    gflags::ShutDownCommandLineFlags();
    
    if (FLAGS_load < 0) {
        printf("Invalid load: %f\n", FLAGS_load);
        exit(EXIT_FAILURE);
    }
    if (FLAGS_get_service_time < 0 || (double)FLAGS_get_service_time > 1000 * NSEC_PER_USEC) {
        printf("Invalid get_service_time: %f\n", (double)FLAGS_get_service_time / NSEC_PER_USEC);
        exit(EXIT_FAILURE);
    }

    if (!FLAGS_fake_work) {
        printf("RocksDB path: %s\n", FLAGS_rocksdb_path.c_str());
        printf("Initializing RocksDB...\n");
        g_db = rocksdb_init(FLAGS_rocksdb_path.c_str(), FLAGS_rocksdb_cache_size);
    }
    if (FLAGS_bench_request)
        benchmark_request(g_db);

    random_init();
    double mean_arrive_time_us = 1e6 / target_throughput();
    random_exponential_distribution_init(1.0 / mean_arrive_time_us);

    printf("Initializing load dispatcher...\n");
    g_dispatcher = dispatcher_create();

    printf("Generating requests...\n");
    do_dispatching(g_dispatcher);

    if (FLAGS_detailed_print)
        write_lat_results_detailed(g_dispatcher->issued, g_dispatcher->requests);
    else if (FLAGS_slowdown_print)
        write_slo_results(g_dispatcher->issued, g_dispatcher->requests);
    else
        write_lat_results(g_dispatcher->issued, g_dispatcher->requests);

    // cleanup
    free(g_dispatcher->requests);
    free(g_dispatcher);
    if (!FLAGS_fake_work)
        rocksdb_close(g_db);

    printf("Experiment exits gracefully.\n");

    return 0;
}
