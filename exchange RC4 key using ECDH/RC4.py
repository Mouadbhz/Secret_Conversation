def ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    
    return S

def prga(S,m):
    i = 0
    j = 0
    keystream= list(range(len(m)))
    for char in m:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
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

def main():
    key = "alice_secret_key"
    plaintext = "hello"

    # Encrypt
    ciphertext = rc4(key, plaintext.encode())
    print('Ciphertext:', ciphertext)
    
    # Decrypt
    decrypted = rc4(key, ciphertext)
    print(decrypted)
    print('Decrypted:', decrypted.decode())

    # plaintext222 = rc4(key, ciphertext)
    # print('plaintext222:', plaintext222.decode())

if __name__ == "__main__":
    main()