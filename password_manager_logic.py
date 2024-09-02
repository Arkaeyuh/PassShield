# password_manager_logic.py

import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Constants for encryption settings
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
AES_MODE = AES.MODE_GCM

# Function to generate a random password of specified length
def generate_password(length=16):
    return get_random_bytes(length).hex()

# Function to encrypt a password using a master key
def encrypt_password(password, master_key):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(master_key, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES_MODE)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return {
        'salt': salt.hex(),
        'nonce': cipher.nonce.hex(),
        'tag': tag.hex(),
        'ciphertext': ciphertext.hex()
    }

# Function to decrypt a password using a master key
def decrypt_password(encrypted_data, master_key):
    salt = bytes.fromhex(encrypted_data['salt'])
    nonce = bytes.fromhex(encrypted_data['nonce'])
    tag = bytes.fromhex(encrypted_data['tag'])
    ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    key = PBKDF2(master_key, salt, dkLen=KEY_SIZE, count=ITERATIONS)
    cipher = AES.new(key, AES_MODE, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode('utf-8')

# Function to store multiple encrypted passwords in a JSON file
def store_passwords(file_path, encrypted_passwords):
    with open(file_path, 'w') as file:
        json.dump(encrypted_passwords, file)

# Function to retrieve multiple encrypted passwords from a JSON file
def retrieve_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
