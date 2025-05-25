import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from RC4 import rc4
import os

# Generate Alice's Curve25519 key pair
private_key = x25519.X25519PrivateKey.generate()
alice_public_key = private_key.public_key()

# Serialize Alice's public key for sending
alice_public_key_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)

s = socket.socket()
s.connect(("localhost", 65432))

# Send Alice's public key
s.send(alice_public_key_bytes)

# Receive Bob's public key
bob_public_key_bytes = s.recv(1024)
bob_public_key = serialization.load_ssh_public_key(
    bob_public_key_bytes,
    backend=default_backend()
)

# Compute shared secret
shared_secret = private_key.exchange(bob_public_key)
shared_key = shared_secret.hex()  # Use hex representation as key

print(f"[Alice] Shared Key: {shared_key}")

while True:
    message = input("[Alice] Enter your message (or 'quit' to exit): ")
    if message.lower() == 'quit':
        break
    ciphertext = rc4(shared_key, message.encode())
    s.send(ciphertext)
    print("[Alice] Encrypted message sent.")
    
    # Receive and decrypt Bob's response
    ciphertext = s.recv(1024)
    if ciphertext:
        decrypted = rc4(shared_key, ciphertext)
        print(f"[Bob] Decrypted message: {decrypted.decode()}")

s.close()