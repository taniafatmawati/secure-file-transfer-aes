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
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_file(input_file, output_file):
    # Ask for password
    password = getpass("Enter password for decryption: ")

    # Load file (salt + IV + ciphertext)
    with open(input_file, "rb") as f:
        data = f.read()

    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)

    # AES-CBC Decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decrypt.py <input_file> <output_file>")
        sys.exit(1)

    decrypt_file(sys.argv[1], sys.argv[2])
