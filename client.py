import threading
import socket
import time

def latency_client(server_ip, port, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, port))
            s.sendall(message.encode())
            data = s.recv(1024)
            print(f"Received: {data.decode()}")
    except Exception as e:
        print(f"Error: {e}")

def stress_test(server_ip, port, num_clients):
    threads = []
    for i in range(num_clients):
        t = threading.Thread(target=latency_client, args=(server_ip, port, f"Message {i}"))
        threads.append(t)
        t.start()
        time.sleep(0.1)

    for t in threads:
        t.join()

if __name__ == "__main__":
    stress_test("localhost", 8080, 1000)