import socket
import random
from RC4 import rc4

# Elliptic Curve Parameters (same as Alice's)
p = 97
a = 2
b = 3
G = (3, 6)

# EC math
def inverse_mod(k, p):
    return pow(k, -1, p)

def add_points(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == Q:
        m = (3 * P[0]**2 + a) * inverse_mod(2 * P[1], p) % p
    else:
        m = (Q[1] - P[1]) * inverse_mod(Q[0] - P[0], p) % p

    x = (m**2 - P[0] - Q[0]) % p
    y = (m * (P[0] - x) - P[1]) % p
    return (x, y)

def scalar_mult(k, P):
    result = None
    for bit in bin(k)[2:]:
        result = add_points(result, result)
        if bit == '1':
            result = add_points(result, P)
    return result

# Bob's ECDH key generation
private_key = random.randint(1, p-1)
public_key = scalar_mult(private_key, G)

s = socket.socket()
s.connect(("localhost", 65432))

# Send Bob’s public key
s.send(f"{public_key[0]},{public_key[1]}".encode())

# Receive Alice's public key
data = s.recv(1024).decode()
ax, ay = map(int, data.split(","))
alice_public_key = (ax, ay)

# Compute shared ECDH key
shared_point = scalar_mult(private_key, alice_public_key)
shared_key = str(shared_point[0])  # Use x-coordinate as key
print(f"[Bob] Shared ECDH key: {shared_key}")

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