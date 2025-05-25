import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

alice_conn = None
bob_conn = None
shared_key_exchanged = False
lock = threading.Lock()

def handle_connection(conn, name):
    global shared_key_exchanged
    while True:
        if not shared_key_exchanged:
            # Initial Message expected to be public keys
            if name == "Alice":
                alice_public_key = conn.recv(1024).decode()
                with lock:
                    if bob_conn:
                        bob_conn.sendall(alice_public_key.encode())
            else:  # Bob
                bob_public_key = conn.recv(1024).decode()
                with lock:
                    if alice_conn:
                        alice_conn.sendall(bob_public_key.encode())
            shared_key_exchanged = True  # Simplistic, assumes immediate exchange
            continue
        
        message = conn.recv(1024)
        if message:
            if name == "Alice":
                if bob_conn:
                    bob_conn.sendall(message)
            else:
                if alice_conn:
                    alice_conn.sendall(message)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(2)
    print("[SERVER] Listening for connections...")
    
    alice_conn, addr = s.accept()
    print(f"[SERVER] Alice connected from {addr}")
    threading.Thread(target=handle_connection, args=(alice_conn, "Alice")).start()
    
    bob_conn, addr = s.accept()
    print(f"[SERVER] Bob connected from {addr}")
    threading.Thread(target=handle_connection, args=(bob_conn, "Bob")).start()