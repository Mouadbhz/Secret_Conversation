# Import necessary libraries
import socket
import threading
from key_utils import *

# Server configuration
HOST = '127.0.0.1'
PORT = 65432

# Generate Alice's identity and ephemeral key pairs
ik_priv_alice, ik_pub_alice = generate_key_pair()
ek_priv_alice, ek_pub_alice = generate_key_pair()

# Establish a connection to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # Send Alice's name
    s.sendall(b"Alice")

    # Send Alice's identity and ephemeral public keys
    s.sendall(ik_pub_alice.encode() + b"\n")
    s.sendall(ek_pub_alice.encode() + b"\n")

    # Receive Bob's identity and ephemeral public keys
    ik_pub_bob = s.recv(1024).decode()
    ek_pub_bob = s.recv(1024).decode()

    # Perform 3DH to establish a shared secret
    shared_secret = triple_dh(ik_priv_alice, ek_priv_alice, 
                              PublicKey(ik_pub_bob, encoder=RawEncoder), 
                              PublicKey(ek_pub_bob, encoder=RawEncoder))

    # Initialize the Double Ratchet with the shared secret
    ratchet = DoubleRatchet(shared_secret, ek_priv_alice, 
                            PublicKey(ek_pub_bob, encoder=RawEncoder))

    # Function to listen for incoming messages
    def listen():
        while True:
            # Receive a message from Bob
            ciphertext = s.recv(4096)
            if ciphertext:
                # Decrypt the message using the Double Ratchet
                plaintext = ratchet.ratchet_receive(ciphertext)
                print("[Bob]:", plaintext)

    # Start the listening thread
    threading.Thread(target=listen, daemon=True).start()

    # Main loop to send messages
    while True:
        # Input a message to send
        message = input("You: ")
        # Encrypt the message using the Double Ratchet
        ciphertext = ratchet.ratchet_send(message)
        # Send the encrypted message
        s.sendall(ciphertext)