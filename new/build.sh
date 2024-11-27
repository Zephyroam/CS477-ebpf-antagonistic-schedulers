bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -target bpf -c cache_misses.bpf.c -o cache_misses.bpf.o -I.
bpftool gen skeleton cache_misses.bpf.o > cache_misses.bpf.skel.h
gcc -o cache_misses main.c -lbpf -I.
