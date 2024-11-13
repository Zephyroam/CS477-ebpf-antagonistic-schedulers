#!/bin/sh

# Compile the scheduler
clang -target bpf -g -O2 -c sched_ext.bpf.c -o sched_ext.bpf.o -I.
