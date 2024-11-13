#!/bin/sh

# Get the name of the scheduler from arguments
SCHEDULER=$1

# Register the scheduler
bpftool struct_ops register $SCHEDULER.bpf.o /sys/fs/bpf/sched_ext || (echo "Error attaching scheduler, consider calling stop.sh before" || exit 1)

# Print scheduler name, fails if it isn't registered properly
cat /sys/kernel/sched_ext/root/ops || (echo "No sched-ext scheduler installed" && exit 1)
