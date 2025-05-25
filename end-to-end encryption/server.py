# Import the socket library for network communication
import socket
import threading

# Server configuration
HOST = '127.0.0.1'
PORT = 65432

# Dictionary to store client connections
clients = {}
# Lock for thread-safe operations
lock = threading.Lock()

# Function to relay messages between clients
def relay(conn, peer):
    while True:
        try:
            # Receive data from the client
            data = conn.recv(4096)
            if not data:
                break
            # Send the data to the peer client
            with lock:
                if peer in clients:
                    clients[peer].sendall(data)
        except:
            break

# Main server loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Bind the server to the specified host and port
    s.bind((HOST, PORT))
    # Listen for incoming connections
    s.listen(2)
    print("[SERVER] Listening for connections...")

    # Accept two connections (for Alice and Bob)
    for _ in range(2):
        conn, addr = s.accept()
        # Receive the client's name
        name = conn.recv(1024).decode()
        print(f"[SERVER] {name} connected from {addr}")
        # Store the client connection
        with lock:
            clients[name] = conn

    # Start relay threads for each client pair
    threading.Thread(target=relay, args=(clients["Alice"], "Bob")).start()
    threading.Thread(target=relay, args=(clients["Bob"], "Alice")).start()