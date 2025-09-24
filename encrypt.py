import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt):
    """Derive AES key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file):
    # Ask for password
    password = getpass("Enter password for encryption: ")

    # Generate random salt and derive key
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    # Read plaintext
    with open(input_file, "rb") as f:
        plaintext = f.read()

    # Padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # AES-CBC Encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save: salt + IV + ciphertext
    with open(output_file, "wb") as f:
        f.write(salt + iv + ciphertext)

    print(f"[+] File encrypted and saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt.py <input_file> <output_file>")
        sys.exit(1)

    encrypt_file(sys.argv[1], sys.argv[2])
