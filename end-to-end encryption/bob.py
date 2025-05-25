# Import necessary libraries
import socket
import threading
from key_utils import *

# Server configuration
HOST = '127.0.0.1'
PORT = 65432

# Generate Bob's identity and ephemeral key pairs
ik_priv_bob, ik_pub_bob = generate_key_pair()
ek_priv_bob, ek_pub_bob = generate_key_pair()

# Establish a connection to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # Send Bob's name
    s.sendall(b"Bob")

    # Receive Alice's identity and ephemeral public keys
    ik_pub_alice = s.recv(1024).decode()
    ek_pub_alice = s.recv(1024).decode()

    # Send Bob's identity and ephemeral public keys
    s.sendall(ik_pub_bob.encode() + b"\n")
    s.sendall(ek_pub_bob.encode() + b"\n")

    # Perform 3DH to establish a shared secret
    shared_secret = triple_dh(ik_priv_bob, ek_priv_bob, 
                              PublicKey(ik_pub_alice, encoder=RawEncoder), 
                              PublicKey(ek_pub_alice, encoder=RawEncoder))

    # Initialize the Double Ratchet with the shared secret
    ratchet = DoubleRatchet(shared_secret, ek_priv_bob, 
                            PublicKey(ek_pub_alice, encoder=RawEncoder))

    # Function to listen for incoming messages
    def listen():
        while True:
            # Receive a message from Alice
            ciphertext = s.recv(4096)
            if ciphertext:
                # Decrypt the message using the Double Ratchet
                plaintext = ratchet.ratchet_receive(ciphertext)
                print("[Alice]:", plaintext)

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