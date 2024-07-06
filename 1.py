import os
import argparse
import logging
import configparser
from tqdm import tqdm
from getpass import getpass
from threading import Thread
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256

# Constants
SALT_SIZE = 16
HMAC_SIZE = 32
BLOCK_SIZE = AES.block_size

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def pad(data):
    """Pad the data to at a multiple of BLOCK_SIZE (16 bytes)."""
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove padding from the data."""
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password, salt, key_length=32):
    """Derive a key from password and salt using PBKDF2."""
    return PBKDF2(password, salt, dkLen=key_length, count=1000000, hmac_hash_module=SHA256)

def create_output_dir(output_file):
    """Create the output directory if it doesn't exist."""
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

def encrypt_file(input_file, output_file, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    hmac = HMAC.new(key, digestmod=SHA256)
    
    file_size = os.path.getsize(input_file)
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.iv)
        
        hmac.update(cipher.iv)
        
        pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc='Encrypting')
        while chunk := f_in.read(BLOCK_SIZE * 1024):
            chunk = pad(chunk)
            ciphertext = cipher.encrypt(chunk)
            hmac.update(ciphertext)
            f_out.write(ciphertext)
            pbar.update(len(chunk))
        pbar.close()
        f_out.write(hmac.digest())
    
    logging.info(f"File '{input_file}' encrypted to '{output_file}' successfully.")

def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(SALT_SIZE)
            iv = f.read(BLOCK_SIZE)
            ciphertext = f.read(-HMAC_SIZE)
            hmac_digest = f.read(HMAC_SIZE)
    except FileNotFoundError:
        logging.error(f"File '{input_file}' not found.")
        return

    key = derive_key(password, salt)
    hmac = HMAC.new(key, digestmod=SHA256)
    
    hmac.update(iv + ciphertext)
    try:
        hmac.verify(hmac_digest)
    except ValueError:
        logging.error("HMAC verification failed. The file may have been tampered with or the password is incorrect.")
        return

    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(output_file, 'wb') as of:
        pbar = tqdm(total=len(ciphertext), unit='B', unit_scale=True, desc='Decrypting')
        while chunk := ciphertext[:BLOCK_SIZE * 1024]:
            ciphertext = ciphertext[BLOCK_SIZE * 1024:]
            plaintext_chunk = unpad(cipher.decrypt(chunk))
            of.write(plaintext_chunk)
            pbar.update(len(chunk))
        pbar.close()
    
    logging.info(f"File '{input_file}' decrypted to '{output_file}' successfully.")

def process_file(input_file, action, output_file, password, config):
    if action == "encrypt":
        encrypt_file(input_file, output_file, password)
    elif action == "decrypt":
        decrypt_file(input_file, output_file, password)

def read_config(config_path):
    """Read and parse configuration file."""
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def main():
    parser = argparse.ArgumentParser(description="Encrypt and decrypt files using AES-256.")
    parser.add_argument("input_file", help="The file to be encrypted/decrypted.")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Whether to encrypt or decrypt the file.")
    parser.add_argument("output_file", help="The output file for the encrypted/decrypted data.")
    parser.add_argument("--password", help="The password for key derivation.")
    parser.add_argument("--config", help="Path to configuration file with settings.")
    parser.add_argument("--log", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log.upper())

    # Get password if not provided as argument
    if not args.password:
        args.password = getpass(prompt='Enter password: ')

    # Read configuration file if provided
    if args.config:
        config = read_config(args.config)
    else:
        config = None

    # Create output directory if it doesn't exist
    create_output_dir(args.output_file)
    
    # Start processing file with multithreading
    thread = Thread(target=process_file, args=(args.input_file, args.action, args.output_file, args.password, config))
    thread.start()
    thread.join()

if __name__ == '__main__':
    main()
