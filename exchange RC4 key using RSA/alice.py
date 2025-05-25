import socket
from sympy import mod_inverse
import random

# Fonctions RC4
def ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, length):
    i = 0
    j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream

def rc4(key, plaintext):
    key = [ord(c) for c in key]
    S = ksa(key)
    i = 0
    j = 0
    ciphertext=b""
    #plaintext=plaintext.encode()
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        ciphertext_octet = bytes([ char ^ K])
        ciphertext=ciphertext+ciphertext_octet
        #keystream.append(K)
    return ciphertext


# Fonctions RSA
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    if p % 2 == 0:
        p += 1
    return p

def generate_prime_number(length=10):
    p = 0
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_keys():
    p = generate_prime_number(8)
    q = generate_prime_number(8)
    while q == p:
        q = generate_prime_number(8)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randrange(1, phi_n)
    g = gcd(e, phi_n)
    while g != 1:
        e = random.randrange(1, phi_n)
        g = gcd(e, phi_n)
    d = mod_inverse(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt_rsa(public_key, plaintext):
    e, n = public_key
    cipher_nums = [pow(byte, e, n) for byte in plaintext]
    ciphertext = ' '.join(map(str, cipher_nums))
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key
    cipher_nums = list(map(int, ciphertext.split()))
    plaintext = bytes([pow(char, d, n) for char in cipher_nums])
    return plaintext

# Génération des clés pour Alice
public_key, private_key = generate_keys()
print("Clé publique d'Alice:", public_key)
print("Clé privée d'Alice:", private_key)

# Génération de la clé RC4 pour Alice
rc4_key = "alice_secret_key"

# Adresse IP et port de Bob
bob_ip = '127.0.0.1'
bob_port = 12345

# Connexion à Bob
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((bob_ip, bob_port))
    
    # Envoyer la clé publique d'Alice à Bob
    s.sendall(f"{public_key[0]} {public_key[1]}".encode())
    
    # Recevoir la clé publique de Bob
    bob_public_key = s.recv(1024).decode()
    e, n = map(int, bob_public_key.split())
    bob_public_key = (e, n)
    print("Clé publique de Bob reçue:", bob_public_key)
    
    # Chiffrer et envoyer la clé RC4 d'Alice à Bob
    encrypted_rc4_key = encrypt_rsa(bob_public_key, rc4_key.encode())
    s.sendall(encrypted_rc4_key.encode())
    
    # Recevoir et déchiffrer la clé RC4 de Bob
    encrypted_bob_rc4_key = s.recv(1024).decode()
    bob_rc4_key = decrypt_rsa(private_key, encrypted_bob_rc4_key).decode()
    print("Clé RC4 de Bob reçue et déchiffrée:", bob_rc4_key)
    
    while True:
        # Saisir un message à chiffrer et envoyer à Bob
        message = input("Saisissez le message à envoyer à Bob (ou tapez 'exit' pour quitter): ")
        if message.lower() == 'exit':
            print("Fermeture de la connexion.")
            break
        encrypted_message = rc4(bob_rc4_key, message.encode())
        print("############################ send to bob")
        print(encrypted_message)
        print(bob_rc4_key)
        print("############################")
        s.sendall(encrypted_message)
        print("Message chiffré envoyé à Bob:", encrypted_message.hex())
        
        # Recevoir la réponse de Bob
        encrypted_response = s.recv(1024)
        print("############################")
        print(encrypted_response)
        print("############################")
        decrypted_response = rc4(bob_rc4_key, encrypted_response)
        print("Message reçu de Bob:", decrypted_response.decode())