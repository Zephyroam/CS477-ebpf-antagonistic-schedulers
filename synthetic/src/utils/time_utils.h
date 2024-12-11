#ifndef _TIME_H_
#define _TIME_H_

#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <chrono>

typedef uint64_t __sec;
typedef uint64_t __nsec;
typedef uint64_t __usec;

#define NSEC_PER_SEC  (1000000000UL)
#define NSEC_PER_MSEC (1000000UL)
#define NSEC_PER_USEC (1000UL)
#define USEC_PER_SEC  (1000000UL)
#define USEC_PER_MSEC (1000UL)
#define MSEC_PER_SEC  (1000UL)

#define time_nsec_to_sec(ns)  ((ns) / NSEC_PER_SEC)
#define time_nsec_to_msec(ns) ((ns) / NSEC_PER_MSEC)
#define time_nsec_to_usec(ns) ((ns) / NSEC_PER_USEC)

#define time_sec_to_nsec(sec)   ((sec) * NSEC_PER_SEC)
#define time_msec_to_nsec(msec) ((msec) * NSEC_PER_MSEC)
#define time_usec_to_nsec(usec) ((usec) * NSEC_PER_USEC)

extern __usec g_boot_time_us;

static inline __nsec now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__nsec)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static inline __usec now_us() {
    using namespace std::chrono;
    auto now = high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return duration_cast<microseconds>(duration).count();
}

/// Return monotonic time in microseconds since system boot.
static inline __usec monotonic_us()
{
    return now_us() - g_boot_time_us;
}

static inline void spin_until(__nsec deadline)
{
    while (now_ns() < deadline);
}

static inline void spin(__nsec duration)
{
    spin_until(now_ns() + duration);
}

#endif // _TIME_H_
