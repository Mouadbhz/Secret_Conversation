# Secret_Conversation
Overview
The Python scripts alice.py and bob.py demonstrate secure communication between Alice (client) and Bob (server) using RSA for key exchange and RC4 for encrypting/decrypting messages.

Alice's Script (alice.py)
Generates RSA keys and shares her public key with Bob.
Exchanges RC4 keys securely using RSA encryption.
Sends and receives messages encrypted with RC4.
Bob's Script (bob.py)
Generates RSA keys and shares his public key with Alice.
Receives and decrypts Alice's RC4 key, then sends back his own encrypted RC4 key.
Sends and receives messages encrypted with RC4.
Interaction 
Alice and Bob exchange RSA public keys.
RC4 keys are exchanged securely using RSA encryption.
Messages are sent and received using RC4 encryption.
