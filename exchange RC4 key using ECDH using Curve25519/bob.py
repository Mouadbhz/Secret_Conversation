import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend

from RC4 import rc4
import os

# Generate Bob's Curve25519 key pair
private_key = x25519.X25519PrivateKey.generate()
bob_public_key = private_key.public_key()

# Serialize Bob's public key for sending
bob_public_key_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)

s = socket.socket()
s.connect(("localhost", 65432))

# Send Bob’s public key
s.send(bob_public_key_bytes)

# Receive Alice's public key
alice_public_key_bytes = s.recv(1024)
alice_public_key = serialization.load_ssh_public_key(
    alice_public_key_bytes,
    backend=default_backend()
)

# Compute shared secret
shared_secret = private_key.exchange(alice_public_key)
shared_key = shared_secret.hex()  # Use hex representation as key

print(f"[Bob] Shared Key: {shared_key}")

while True:
    # Receive and decrypt Alice's message
    ciphertext = s.recv(1024)
    if ciphertext:
        decrypted = rc4(shared_key, ciphertext)
        print(f"[Alice] Decrypted message: {decrypted.decode()}")
        
    message = input("[Bob] Enter your message (or 'quit' to exit): ")
    if message.lower() == 'quit':
        break
    ciphertext = rc4(shared_key, message.encode())
    s.send(ciphertext)
    print("[Bob] Encrypted message sent.")

s.close()