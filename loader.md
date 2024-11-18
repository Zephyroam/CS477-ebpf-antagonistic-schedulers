python workload_generator.py latency --port 8080 --max_clients 5 --computation_size 1000 &

python workload_generator.py batch --num_processes 4 --iterations 10 --matrix_size 1000
