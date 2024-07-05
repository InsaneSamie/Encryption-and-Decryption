from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    """Pad the data to be a multiple of AES block size (16 bytes)."""
    pad_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_length] * pad_length)

def unpad(data):
    """Remove the padding from the data."""
    pad_length = data[-1]
    return data[:-pad_length]

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext))
    with open(output_file, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # AES block size is 16 bytes
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def main():
    key = get_random_bytes(32)  # AES-256 requires a 32-byte key
    input_file = input("Enter the name of the input .txt file: ")
    encrypted_file = 'encrypted_file.bin'
    decrypted_file = 'decrypted_file.txt'

    if not os.path.exists(input_file):
        print(f"File '{input_file}' does not exist.")
        return

    print("Encrypting...")
    encrypt_file(input_file, encrypted_file, key)
    print("Encryption complete.")

    print("Decrypting...")
    decrypt_file(encrypted_file, decrypted_file, key)
    print("Decryption complete.")

    # Verify that the decrypted file is the same as the original file
    with open(input_file, 'rb') as original, open(decrypted_file, 'rb') as decrypted:
        assert original.read() == decrypted.read(), "Mismatch between original and decrypted files!"

    print("Verification successful: The original and decrypted files match.")

if __name__ == '__main__':
    main()
