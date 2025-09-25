# 🔐 Secure File Transfer with AES-256 Encryption (CBC Mode) + PBKDF2

## 📌 Project Overview
This project implements a simple file encryption and decryption system using the **AES-256 (CBC mode)** algorithm combined with **PBKDF2 password-based key derivation**.
The purpose is to demonstrate fundamental concepts of **applied cryptography**, **secure communication**, and **key management** in Python.

The tool allows:
- Encrypting a file with AES before sending it.
- Decrypting the file back to its original content on the receiver side.
- Deriving keys securely from a password instead of storing raw keys.

⚠️ **Disclaimer**: This project is for **educational purposes only**.  
Do not use it in production environments.

---

## ✨ Key Features
- AES-256 encryption (32-byte / 256-bit key length) with CBC mode
- PKCS7 padding
- Random IV (Initialization Vector) and **salt** generated for each encryption
- **PBKDF2-HMAC-SHA256** for password-based key derivation
- Secure file format: `salt + IV + ciphertext`
- Command-line interface (CLI)
- Separate scripts for encryption (`encrypt.py`) and decryption (`decrypt.py`)

---

## 🛠 Skills Demonstrated
- Applied cryptography using Python
- Understanding of AES block cipher, CBC mode, and PKCS7 padding
- Secure password-based key derivation with PBKDF2
- Secure key/IV/salt management
- File handling in Python

---

## 📦 Requirements
- Python 3.x
- `cryptography` library

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Example Usage

We will use a sample file `message.txt`.

### Content of `message.txt`
```
This is a confidential message for testing AES encryption.
Bright minds work hard, pray sincerely, and live with gratitude.
End of message.
```

### Encrypt a file
```bash
python encrypt.py message.txt message.enc
```

Output:
```
Enter password for encryption: ********
[+] File encrypted and saved to message.enc
```

### Decrypt a file
```bash
python decrypt.py message.enc message_dec.txt
```

Output:
```
Enter password for decryption: ********
[+] File decrypted and saved to message_dec.txt
```

Now, open `message_dec.txt` and you will see the original content:
```
This is a confidential message for testing AES encryption.
Bright minds work hard, pray sincerely, and live with gratitude.
End of message.
```

---

## 📂 Workflow

**Encryption Flow:**
1. User enters password
2. Salt generated → PBKDF2 → derive AES key
3. AES-CBC encryption → Output = salt + IV + ciphertext

**Decryption Flow:**
1. User enters the same password
2. Salt loaded → PBKDF2 → derive same AES key
3. AES-CBC decryption → Original file restored


📸 **Example Demo Screenshot** (terminal + output file):

**1. Terminal Output**  
![Terminal Output](screenshots/output-terminal.png)

**2. File Content Comparison**  
![File Output](screenshots/output-file.png)

---

## 🔮 Future Improvements
- Implement secure key exchange mechanism  
- Build GUI version for easier interaction  

---
