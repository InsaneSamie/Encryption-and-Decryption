# Encryption-and-Decryption

## AES File Encryption and Decryption
This project demonstrates file encryption and decryption using AES (Advanced Encryption Standard) 256 in Python.

https://github.com/InsaneSamie/Encryption-and-Decryption/assets/101932418/9fd6cb09-18d4-4957-91c5-907198eeea82

## Overview
This Python script allows you to encrypt and decrypt files using AES-256 CBC mode encryption. AES is a symmetric encryption algorithm widely used to secure data.

## Features
Encryption: Encrypts a specified input file and stores the encrypted data along with the initialization vector (IV) in an output file.<br>
Decryption: Decrypts the encrypted file back to its original form using the provided encryption key.
# Requirements
- Python 3.x
- pycryptodome library (install via pip install pycryptodome)

# Usage
# Encryption:
Run the script and provide the name of the input file (e.g., input.txt).
The encrypted file (encrypted_file.bin) will be generated in the current directory.

# Decryption:
After encryption, run the script again.
It will decrypt encrypted_file.bin and produce decrypted_file.txt in the current directory.
Security Note
Ensure to keep your encryption key (key) secure and private.
This script uses AES-256 CBC mode encryption, which is suitable for secure data transmission and storage.

## Example

$ python 1.py<br>
Enter the name of the input .txt file: s.txt<br>
Encrypting...<br>
Encryption complete.<br>
Decrypting...<br>
Decryption complete.<br>
Verification successful: The original and decrypted files match.<br>

