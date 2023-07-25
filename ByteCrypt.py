import asyncio
from functools import partial
import json
import os
import getpass
import subprocess
import platform
import shutil
import datetime
import time
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from concurrent.futures import ThreadPoolExecutor
ZIP_EXT = '.7z'
class ByteCrypt:
    def __init__(self, root_dir):
        print("ByteCrypt v0.1 Initializing...")
        self.root_dir = root_dir
        self.password_file_path = os.path.join(self.root_dir, 'password.json')
        self.config_file_path = os.path.join(root_dir, 'config.json')
        self.password = None  # Initialize password as None
        self.pass_config = {}  # Initialize password config as empty dict
        # If the configuration file doesn't exist, do the initial setup
        if not os.path.exists(self.config_file_path):
            self.initial_setup()

        # At this point, the configuration file should exist. Load it.
        self.config = self._load_config('config.json')
        self.unencrypted_directory = os.path.join(self.root_dir, self.config.get('unencrypted_directory'))
        self.encrypted_directory = os.path.join(self.root_dir, self.config.get('encrypted_directory'))
        self.encrypted_directoryStr = os.path.splitext(self.config.get('encrypted_directory'))[0].split('/')[-1]
        self.backup_dir = self.config.get('backup_dir')
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
        if os.path.exists(self.password_file_path):
            self.password = self._load_password(self.password_file_path)
        elif not self.password:
            if not os.path.exists(self.encrypted_directory):
                self.password = self._get_password("encrypt")
            else:
                self.password = self._get_password("decrypt")

        self.custom_encryption_password = self.password
        print("ByteCrypt v0.1 Initialized.")

    def initial_setup(self):
        self.config = {}
        # Display the folders one level up from the script
        print("Select the folder to encrypt from the list:")
        parent_directory = os.path.dirname(self.root_dir)
        directories = [dir for dir in os.listdir(parent_directory) if os.path.isdir(os.path.join(parent_directory, dir))]
        for i, dir in enumerate(directories, start=1):
            print(f"{i}. {dir}")

        # User selects the directory to encrypt
        selection = int(input("Enter the number corresponding to your choice: ")) - 1
        self.config['unencrypted_directory'] = "../"+ directories[selection]
        self.config['encrypted_directory'] = "../"+input("Enter the name of the output encrypted file: ")
        self.config['backup_dir'] = "../"+input("Enter the name of the backup directory: ")
        os.makedirs(self.config['backup_dir'], exist_ok=True)

        with open(os.path.join(self.root_dir, 'config.json'), 'w') as f:
            json.dump(self.config, f)


    def _load_config(self, config_file):
        with open(os.path.join(self.root_dir, config_file), 'r') as f:
            return json.load(f)

    def _load_password(self, password_file):
        try:
            with open(password_file, 'r') as f:
                password_data = json.load(f)
            return password_data.get('password')
        except FileNotFoundError:
            return None

    def _get_7z_path(self):
        base_dir = os.path.dirname(os.path.realpath(__file__))
        if platform.system() == 'Windows':
            return os.path.join(base_dir, './7z/windows/7z.exe')
        elif platform.system() == 'Linux':
            return os.path.join(base_dir, './7z/linux/7zz')
        else:
            raise Exception('Unsupported platform')

    def _get_key(self, password: str, salt=None):
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

    async def _custom_encrypt(self, password: str, input_file: str):
        salt, key = self._get_key(password)
        cipher_suite = Fernet(key)
        with open(input_file, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        with open(input_file, 'wb') as file:
            file.write(salt + encrypted_data)

    async def _custom_decrypt(self, password: str, input_file: str):
        # Define a decrypting task
        async def decryption_task():
            try:
                with open(input_file, 'rb') as file:
                    file_data = file.read()
                salt = file_data[:16]
                file_data = file_data[16:]
                _, key = self._get_key(password, salt)
                cipher_suite = Fernet(key)
                unencrypted_data = cipher_suite.decrypt(file_data)
                with open(input_file, 'wb') as file:
                    file.write(unencrypted_data)
            except cryptography.fernet.InvalidToken:
                print("\nFailed to decrypt data. This may be because the provided password was incorrect, or the file is not a valid encrypted file.")
                self.password = self._get_password("decrypt")  # Prompt user to re-enter their password
                await self._custom_decrypt(self.password, input_file)  # Retry decryption with the new password

        # Define a progress display task
        async def progress_display_task():
            print("Decrypting", end="")
            while not decryption.done():
                print("...", end="")
                await asyncio.sleep(1)
            print()  # move the cursor to the next line

        decryption = asyncio.create_task(decryption_task())
        display = asyncio.create_task(progress_display_task())
        await asyncio.gather(decryption, display)

    async def _create_encrypted_7z(self, password):
        subprocess_run = partial(
            subprocess.run,
            [self._get_7z_path(), 'a', '-p{}'.format(password), '-mhe', self.encrypted_directory, self.unencrypted_directory+"\."],
            check=True
        )
        await self.loop.run_in_executor(self.executor, subprocess_run)
        await self._custom_encrypt(self.custom_encryption_password, self.encrypted_directory)

    async def _extract_encrypted_7z(self, password):
        subprocess_run = partial(
            subprocess.run,
            [self._get_7z_path(), 'x', '-p{}'.format(password), '-o{}'.format(self.unencrypted_directory), self.encrypted_directory],
            check=True,
            capture_output=True,
            text=True
        )
        result = await self.loop.run_in_executor(self.executor, subprocess_run)
        if result.returncode == 2:
            print("Incorrect password.")
            password = self._get_password("decrypt")
            await self._extract_encrypted_7z(password)
        else:
            print("Decrypt Successful.")
            os.remove(os.path.splitext(self.encrypted_directory)[0]+ZIP_EXT)

    def _set_permissions_recursive(self, path):
        for root, dirs, files in os.walk(path):
            for dir in dirs:
                os.chmod(os.path.join(root, dir), 0o700)
            for file in files:
                os.chmod(os.path.join(root, file), 0o700)

    def _get_password(self, encrypt_or_decrypt):
        if encrypt_or_decrypt == "encrypt":
            password1 = getpass.getpass("Enter the password to encrypt: ")
            password2 = getpass.getpass("Enter the password again: ")
            if password1 != password2:
                print("Passwords do not match. Try again.")
                return self._get_password("encrypt")
            save_password_option = input("Do you want to save the entered password to automate the script? (yes/no): ")
            if save_password_option.lower() == 'yes':
                self.pass_config['password'] = password1
                with open(self.password_file_path, 'w') as f:
                    json.dump({'password': self.pass_config['password']}, f)
            return password1
        elif encrypt_or_decrypt == "decrypt":
            return getpass.getpass("Enter the password to decrypt: ")

    async def run(self):
        if os.path.exists(os.path.join(self.root_dir, self.encrypted_directory)):
            print(f"Encrypted Directory {self.encrypted_directory} exists.")
            try:
                await self._custom_decrypt(self.custom_encryption_password, self.encrypted_directory)
                print("Decryption finished.")
                await self._extract_encrypted_7z(self.password)
            except Exception as e:
                print(f"\nAn error occurred while decrypting: {str(e)}")
        else:
            print(f"Archive {self.encrypted_directory} does not exist.")
            await self._create_encrypted_7z(self.password)
            current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            archive_name_with_datetime = f"{self.encrypted_directoryStr}_{current_datetime}.bcz"
            dest = os.path.join(self.root_dir, self.backup_dir)+"\\"
            shutil.copy(self.encrypted_directory,  os.path.join(dest+archive_name_with_datetime))
            self._set_permissions_recursive(self.unencrypted_directory)

            time.sleep(1)
            shutil.rmtree(self.unencrypted_directory)

    async def setup(self):
        self.loop = asyncio.get_event_loop()
        self.executor = ThreadPoolExecutor(max_workers=4)
        await self.run()

if __name__ == '__main__':
    root_dir = os.path.dirname(os.path.abspath(__file__))
    byte_crypt = ByteCrypt(root_dir)
    asyncio.run(byte_crypt.setup())
