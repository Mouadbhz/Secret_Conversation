# Import necessary libraries
import os
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import hmac
import hashlib

# Function to generate a new key pair
def generate_key_pair():
    # Generate a new private key
    private_key = PrivateKey.generate()
    # Derive the public key from the private key
    public_key = private_key.public_key
    return private_key, public_key

# Function to perform Triple Diffie-Hellman (3DH) key exchange
def triple_dh(ik_priv_alice, ek_priv_alice, ik_pub_bob, ek_pub_bob):
    # Compute the shared secrets
    dh1 = Box(ik_priv_alice, ek_pub_bob).shared_key()
    dh2 = Box(ek_priv_alice, ik_pub_bob).shared_key()
    dh3 = Box(ek_priv_alice, ek_pub_bob).shared_key()
    # Hash the shared secrets to get the final shared key
    return blake2b(dh1 + dh2 + dh3, encoder=RawEncoder)[:32]

# Class implementing the Double Ratchet Algorithm
class DoubleRatchet:
    def __init__(self, root_key, alice_ephemeral_priv, bob_public_key):
        # Initialize with the root key (from 3DH), Alice's ephemeral private key, and Bob's public key
        self.root_key = root_key
        self.alice_ephemeral_priv = alice_ephemeral_priv
        self.bob_public_key = bob_public_key
        # Initialize sending chain key
        self.send_chain_key = self.root_key
        # Initialize receiving chain key (updated upon first message receipt)
        self.recv_chain_key = None

    # Method to send an encrypted message
    def ratchet_send(self, message):
        # Update the sending chain key
        self.send_chain_key = self.kdf_ck(self.send_chain_key)
        # Derive the message key from the updated sending chain key
        message_key = self.kdf_mk(self.send_chain_key)
        # Encrypt the message using the message key
        ciphertext = bytes(a ^ b for a, b in zip(message.encode(), message_key[:len(message)]))
        return ciphertext

    # Method to receive and decrypt a message
    def ratchet_receive(self, ciphertext):
        if not self.recv_chain_key:
            # If this is the first message, derive the receiving chain key from the root key
            self.recv_chain_key = self.kdf_ck(self.root_key)
        # Derive the message key from the current receiving chain key
        message_key = self.kdf_mk(self.recv_chain_key)
        # Update the receiving chain key for the next message
        self.recv_chain_key = self.kdf_ck(self.recv_chain_key)
        # Decrypt the message using the message key
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, message_key[:len(ciphertext)]))
        return plaintext.decode()

    # Key derivation function for chain keys
    def kdf_ck(self, ck):
        return hmac.new(ck, b"chain", hashlib.sha256).digest()

    # Key derivation function for message keys
    def kdf_mk(self, ck):
        return hmac.new(ck, b"message", hashlib.sha256).digest()