import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_key(key_file):
    """Generate a random AES key and save to file if not exists"""
    if not os.path.exists(key_file):
        key = os.urandom(32)  # AES-256
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"[+] New AES key generated and saved to {key_file}")
    else:
        with open(key_file, "rb") as f:
            key = f.read()
        print(f"[+] Using existing key from {key_file}")
    return key

def encrypt_file(input_file, output_file, key_file):
    key = generate_key(key_file)
    iv = os.urandom(16)  # 16 bytes for AES block size

    # Read plaintext
    with open(input_file, "rb") as f:
        plaintext = f.read()

    # Padding (PKCS7)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # AES-CBC Encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save IV + ciphertext
    with open(output_file, "wb") as f:
        f.write(iv + ciphertext)

    print(f"[+] File encrypted and saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python encrypt.py <input_file> <output_file> <key_file>")
        sys.exit(1)

    encrypt_file(sys.argv[1], sys.argv[2], sys.argv[3])
