#!/bin/sh

cd ./synthetic

# run the batch workload (rocksdb)
./build/bin/shinjuku --detailed_print --discard_time 2 --get_service_time=1400 --range_query_service_time=222445 --range_query_ratio=0.005 --num_workers 8 --run_time 5 &

# sleep to allow the workload to start
sleep 10

# run the antagonist workload
./build/bin/antagonist --num_workers 8 &