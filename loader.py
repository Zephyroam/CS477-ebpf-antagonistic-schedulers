import argparse
import multiprocessing
import numpy as np
import socket
import threading
import time


def latency_server(port, max_clients, computation_size, shutdown_event):
    """
    simulates a latency-critical workload.
    """
    def handle_client(conn, addr):
        print(f"Connected by {addr}")
        data = conn.recv(1024)
        if data:
            # simple computation
            result = np.sum(np.random.rand(computation_size))
            conn.sendall(f"Processed: {result:.4f}".encode())  # respond to client
        conn.close()

    # create a simple server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", port))
    server.listen(max_clients)
    print(f"Latency server listening on port {port}...")

    while not shutdown_event.is_set():
        server.settimeout(1.0)
        try:
            conn, addr = server.accept()
            # Check if shutdown signal has been set before handling the client
            if shutdown_event.is_set():
                conn.close()
                break
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error occurred: {e}")
            break

    server.close()
    print("Latency server stopped.")


def batch_workload(task_id, iterations, matrix_size):
    """
    simulates a batch workload :matrix computations.
    """
    print(f"Batch Task {task_id} started.")
    for i in range(iterations):
        matrix_a = np.random.rand(matrix_size, matrix_size)
        matrix_b = np.random.rand(matrix_size, matrix_size)
        # perform matrix multiplication
        result = np.dot(matrix_a, matrix_b)
        if i % 10 == 0:
            print(f"Batch Task {task_id}: Iteration {i} completed.")
    print(f"Batch Task {task_id} completed.")


def run_latency_server(port, max_clients, computation_size):
    """
    run the latency-critical server.
    """
    shutdown_event = threading.Event()
    server_thread = threading.Thread(target=latency_server, args=(port, max_clients, computation_size, shutdown_event))
    server_thread.daemon = True
    server_thread.start()
    return server_thread, shutdown_event


def run_batch_tasks(num_processes, iterations, matrix_size):
    """
    runs multiple batch workloads in parallel.
    """
    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=batch_workload, args=(i, iterations, matrix_size))
        processes.append(p)
        p.start()
    for p in processes:
        p.join()


def main():
    parser = argparse.ArgumentParser(description="Simulate latency-critical and batch workloads.")
    parser.add_argument("task_type", choices=["latency", "batch"], help="Type of workload to run.")
    parser.add_argument("--port", type=int, default=8080, help="Port for the latency-critical server (default: 8080).")
    parser.add_argument("--max_clients", type=int, default=5, help="Max clients for the latency server (default: 5).")
    parser.add_argument("--computation_size", type=int, default=1000,
                        help="Size of the computation for latency-critical workload (default: 1000).")
    parser.add_argument("--num_processes", type=int, default=multiprocessing.cpu_count(),
                        help="Number of processes for batch workload (default: number of CPU cores).")
    parser.add_argument("--iterations", type=int, default=10,
                        help="Number of iterations for batch workload (default: 10).")
    parser.add_argument("--matrix_size", type=int, default=1000,
                        help="Size of the matrices for batch workload (default: 1000x1000).")

    args = parser.parse_args()

    if args.task_type == "latency":
        print("Starting latency-critical server...")
        server_thread, shutdown_event = run_latency_server(args.port, args.max_clients, args.computation_size)
        print("Press Ctrl+C to stop the server.")
        try:
            while True:
                time.sleep(1)  # keep server running
        except KeyboardInterrupt:
            print("\nStopping server...")
            shutdown_event.set()
            server_thread.join()  
            print("Server stopped.")
    elif args.task_type == "batch":
        print(f"Starting batch workload with {args.num_processes} processes.")
        start_time = time.time()
        run_batch_tasks(args.num_processes, args.iterations, args.matrix_size)
        elapsed_time = time.time() - start_time
        print(f"Batch workload completed in {elapsed_time:.2f} seconds.")


if __name__ == "__main__":
    main()
