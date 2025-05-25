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

# Génération des clés pour Bob
public_key, private_key = generate_keys()
print("Clé publique de Bob:", public_key)
print("Clé privée de Bob:", private_key)

# Génération de la clé RC4 pour Bob
rc4_key = "bob_secret_key"

# Adresse IP et port de Bob
bob_ip = '127.0.0.1'
bob_port = 12345

# Connexion à Bob
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((bob_ip, bob_port))
    s.listen()
    print("En attente de la connexion d'Alice...")
    
    conn, addr = s.accept()
    with conn:
        print("Connecté par", addr)
        
        # Recevoir la clé publique d'Alice
        alice_public_key = conn.recv(1024).decode()
        e, n = map(int, alice_public_key.split())
        alice_public_key = (e, n)
        print("Clé publique d'Alice reçue:", alice_public_key)
        
        # Envoyer la clé publique de Bob à Alice
        conn.sendall(f"{public_key[0]} {public_key[1]}".encode())
        
        # Recevoir et déchiffrer la clé RC4 d'Alice
        encrypted_alice_rc4_key = conn.recv(1024).decode()
        alice_rc4_key = decrypt_rsa(private_key, encrypted_alice_rc4_key).decode()
        print("Clé RC4 d'Alice reçue et déchiffrée:", alice_rc4_key)
        bob_rc4_key = "bob_secret_key"
        
        # Chiffrer et envoyer la clé RC4 de Bob à Alice
        encrypted_rc4_key = encrypt_rsa(alice_public_key, rc4_key.encode())
        conn.sendall(encrypted_rc4_key.encode())
        
        while True:
            # Recevoir le message chiffré d'Alice
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break
            print("############################")
            print(encrypted_message)
            print("############################")
            decrypted_message = rc4(bob_rc4_key, encrypted_message)
            print("############################")
            print(decrypted_message)
            print(alice_rc4_key)
            print("############################")
            print("Message reçu d'Alice:", decrypted_message.decode())
            
            # Saisir une réponse à chiffrer et envoyer à Alice
            response = input("Saisissez la réponse à envoyer à Alice (ou tapez 'exit' pour quitter): ")
            if response.lower() == 'exit':
                print("Fermeture de la connexion.")
                break
            encrypted_response = rc4(rc4_key, response.encode()) # encrypted with bob_rc4_key
            conn.sendall(encrypted_response)
            print("Réponse chiffrée envoyée à Alice:", encrypted_response.hex())