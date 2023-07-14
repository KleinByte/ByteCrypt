from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import os
import shutil
import json
import getpass
import subprocess
import platform
import datetime
import time


def read_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def read_password(password_file):
    try:
        with open(password_file, 'r') as f:
            password_data = json.load(f)
        return password_data.get('password')
    except FileNotFoundError:
        return None

def get_7z_path():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if platform.system() == 'Windows':
        return os.path.join(script_dir, './7z/windows/7z.exe')
    elif platform.system() == 'Linux':
        return os.path.join(script_dir, './7z/linux/7zz')
    else:
        raise Exception('Unsupported platform')

def get_key(password: str, salt=None):
    password = password.encode()
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return salt, key

def custom_encrypt(password: str, input_file: str):
    salt, key = get_key(password)
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(input_file, 'wb') as file:
        file.write(salt + encrypted_data)

def custom_decrypt(password: str, input_file: str):
    with open(input_file, 'rb') as file:
        file_data = file.read()
    salt = file_data[:16]  # The first 16 bytes is the salt
    file_data = file_data[16:]  # The rest is the encrypted data
    _, key = get_key(password, salt)
    cipher_suite = Fernet(key)
    unencrypted_data = cipher_suite.decrypt(file_data)
    with open(input_file, 'wb') as file:
        file.write(unencrypted_data)

def create_encrypted_7z(unencrypted_directory, encrypted_directory, password, custom_encryption_password):
    subprocess.run([get_7z_path(), 'a', '-p{}'.format(password), '-mhe', encrypted_directory, unencrypted_directory], check=True)
    custom_encrypt(custom_encryption_password, encrypted_directory)


def extract_encrypted_7z(encrypted_directory, unencrypted_directory, password, custom_encryption_password):
    custom_decrypt(custom_encryption_password, encrypted_directory)
    result = subprocess.run([get_7z_path(), 'x', '-p{}'.format(password), '-o{}'.format(unencrypted_directory), encrypted_directory], check=True, capture_output=True, text=True)
    if result.returncode == 2:
        print("Incorrect password.")
        password = getpassword("decrypt")
        extract_encrypted_7z(encrypted_directory, unencrypted_directory, password)
    else:
        print("Decrypt Successful.")
        os.remove(encrypted_directory)

def set_permissions_recursive(path):
    for root, dirs, files in os.walk(path):
        for dir in dirs:
            os.chmod(os.path.join(root, dir), 0o700)
        for file in files:
            os.chmod(os.path.join(root, file), 0o700)

def getpassword(encryptOrDecrypt):
    if encryptOrDecrypt == "encrypt":
        password1 = getpass.getpass("Enter the password to encrypt: ")
        password2 = getpass.getpass("Enter the password again: ")
        if password1 != password2:
            print("Passwords do not match. Try again.")
            getpassword("encrypt")
        return password1
    elif encryptOrDecrypt == "decrypt":
        password1 = getpass.getpass("Enter the password to decrypt: ")
        return password1

if __name__ == '__main__':
    print("ByteCrypt v1.0 Initialized...")
    # Get the root directory (where you ran this script from)
    root_dir = os.path.dirname(os.path.abspath(__file__))

    # Use os.path.join to construct the path to your config file
    config_path = os.path.join(root_dir, 'config.json')
    config = read_config(config_path)

    # Check for the password file
    password_file_path = os.path.join(root_dir, 'password.json')
    password = read_password(password_file_path)

    #TODO :Have this configured by config
    custom_encryption_password = getpass.getpass("Enter custom encryption password: ")

    unencrypted_directory = os.path.join(root_dir, config.get('unencrypted_directory'))
    encrypted_directory = os.path.join(root_dir, config.get('encrypted_directory'))
    encrypted_directoryStr = config.get('encrypted_directory')[2:]
    backup_dir = config.get('backup_dir')

    # Check if password was loaded from the file
    if not password:
        if os.path.exists(encrypted_directory):
            password = getpassword("decrypt")
        else:
            password = getpassword("encrypt")

    if os.path.exists(encrypted_directory):
        print(f"Encrypted Directory {encrypted_directory} exists.")
        extract_encrypted_7z(encrypted_directory, "./", password, custom_encryption_password)
    else:
        print(f"Archive {encrypted_directory} does not exist.")
        create_encrypted_7z(unencrypted_directory, encrypted_directory, password, custom_encryption_password)
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M.%S")
        archive_name_with_datetime = f"{encrypted_directoryStr}_{current_datetime + '.7z'}"
        dest = os.path.join(root_dir,backup_dir)
        shutil.copy(encrypted_directory,dest+archive_name_with_datetime)
        set_permissions_recursive(unencrypted_directory)
        time.sleep(2)
        shutil.rmtree(unencrypted_directory)
