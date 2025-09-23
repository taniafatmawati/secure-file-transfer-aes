import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(input_file, output_file, key_file):
    # Load key
    with open(key_file, "rb") as f:
        key = f.read()

    # Load IV + ciphertext
    with open(input_file, "rb") as f:
        data = f.read()
    iv, ciphertext = data[:16], data[16:]

    # AES-CBC Decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save decrypted file
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decrypt.py <input_file> <output_file> <key_file>")
        sys.exit(1)

    decrypt_file(sys.argv[1], sys.argv[2], sys.argv[3])
