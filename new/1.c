#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>

int main() {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        exit(EXIT_FAILURE);
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // 执行一些工作
    for (volatile int i = 0; i < 100000000; ++i);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    long long count;
    if (read(fd, &count, sizeof(long long)) == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    printf("CPU cycles: %lld\n", count);

    close(fd);
    return 0;
}
