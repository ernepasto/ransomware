import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = '127.0.0.1'
PORT = 65432

# Load the private key
with open('../../keys/pub_priv_pair.key', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(), password=None
    )

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((HOST, PORT))
    sock.listen()
    conn, addr = sock.accept()

    with conn:
        # Receive the size of the encrypted key (8 bytes, unsigned long long)
        raw_size = conn.recv(8)
        if len(raw_size) < 8:
            raise ValueError('Errore nella ricezione della dimensione della chiave')
        key_size = struct.unpack('!Q', raw_size)[0]

        # Receive the encrypted key
        encrypted_key = b''
        while len(encrypted_key) < key_size:
            chunk = conn.recv(1024)
            if not chunk:
                break
            encrypted_key += chunk

        print(f'Encrypted key received ({len(encrypted_key)} bytes) from {addr}')
        
        # Decrypt and save the symmetric key
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        # Send back the decrypted key: first the size, then the content
        conn.sendall(struct.pack('!Q', len(symmetric_key)))
        conn.sendall(symmetric_key)

        print('Symmetric key sent back to client.')
