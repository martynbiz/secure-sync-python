import argparse
import os
import hashlib
import base64
import time
import getpass
# from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

CHECKSUM_FILE = 'checksum.txt'

def hash_passphrase(passphrase: str) -> str:
    """Hash the passphrase using SHA-256 and return the hex digest."""
    return hashlib.sha256(passphrase.encode()).hexdigest()

def store_passphrase_hash(passphrase: str):
    """Store the hashed passphrase in a text file."""
    hashed_passphrase = hash_passphrase(passphrase)
    with open(CHECKSUM_FILE, 'w') as f:
        f.write(hashed_passphrase)

def load_passphrase_hash() -> str:
    """Load the hashed passphrase from the text file."""
    if os.path.exists(CHECKSUM_FILE):
        with open(CHECKSUM_FILE, 'r') as f:
            return f.read().strip()
    return None

def prompt_for_passphrase(hide_input: bool = True) -> str:
    """Prompt the user to confirm their passphrase."""
    if hide_input:
        return getpass.getpass("Enter your passphrase: ")
    else:
        return input("Enter your passphrase: ")

def verify_passphrase(passphrase: str) -> bool:
    """Verify the entered passphrase against the stored hash."""
    stored_hash = load_passphrase_hash()
    if stored_hash is None:
        # If no hash is stored, store the new passphrase
        store_passphrase_hash(passphrase)
        return True
    return hash_passphrase(passphrase) == stored_hash

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a key from the passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())  # Return the raw key bytes

def encrypt_filename(relative_path: str, passphrase: str) -> str:
    """Encrypt a relative_path using a passphrase and return it as a hexadecimal string."""
    
    # Use a fixed salt
    salt = b'fixed_salt_value123'  # Replace with a constant value
    key = derive_key(passphrase, salt)
    
    # Use a fixed IV for deterministic encryption (must be 16 bytes)
    iv = b'1234567890abcdef'  # This is also 16 bytes long

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the relative_path to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_path = padder.update(relative_path.encode()) + padder.finalize()
    
    # Encrypt the padded relative_path
    encrypted_relative_path = encryptor.update(padded_path) + encryptor.finalize()

    # Convert the encrypted bytes to a hexadecimal string
    return encrypted_relative_path.hex()

def decrypt_filename(encrypted_filename: str, passphrase: str) -> str:
    """Decrypt an encrypted filename using the passphrase."""
    
    # Use a fixed salt
    salt = b'fixed_salt_value123'  # Must match the salt used during encryption
    key = derive_key(passphrase, salt)
    
    # Use the same fixed IV for decryption
    iv = b'1234567890abcdef'  # This is also 16 bytes long

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Convert the hex string back to bytes
    encrypted_bytes = bytes.fromhex(encrypted_filename)

    # Decrypt the encrypted bytes
    decrypted_padded_path = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_path = unpadder.update(decrypted_padded_path) + unpadder.finalize()

    return decrypted_path.decode()

def encrypt_file(src_file_path: str, source_dir: str, dest_dir: str, passphrase: str):
    """Encrypt a single file using a passphrase."""
    
    # Generate a random salt
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    fernet_key = base64.urlsafe_b64encode(key)
    fernet = Fernet(fernet_key)

    with open(src_file_path, 'rb') as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    # Get the relative path
    relative_path = os.path.relpath(src_file_path, source_dir)

    # # src_filename = os.path.basename(src_file_path)
    dest_filename = encrypt_filename(relative_path, passphrase)
    dest_file_path = os.path.join(dest_dir, dest_filename)

    # Write the encrypted data to the destination file
    with open(dest_file_path, 'wb') as dest_file:
        dest_file.write(salt + encrypted_data)

    return dest_file_path

def decrypt_file(dest_file_path: str, source_dir: str, dest_dir: str, passphrase: str):
    """Decrypt a single file using a passphrase."""
    
    # Read the encrypted data from the file
    with open(dest_file_path, 'rb') as file:
        salt = file.read(16)
        encrypted_data = file.read()  # Read the rest of the file

    # Derive the key using the same passphrase and salt
    key = derive_key(passphrase, salt)
    fernet_key = base64.urlsafe_b64encode(key)
    fernet = Fernet(fernet_key)

    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Get the original file name by decrypting the destination filename
    relative_path = decrypt_filename(os.path.basename(dest_file_path), passphrase)
    original_file_path = os.path.join(source_dir, relative_path)

    # Create the directory if it does not exist
    os.makedirs(os.path.dirname(original_file_path), exist_ok=True)

    # Write the decrypted data to the original file path
    with open(original_file_path, 'wb') as original_file:
        original_file.write(decrypted_data)

    return original_file_path

def delete_file_from_dest(src_file_path: str, source_dir: str, dest_dir: str, passphrase: str):
    """Delete the corresponding encrypted file from the destination directory."""
    
    # Get the relative path
    relative_path = os.path.relpath(src_file_path, source_dir)

    # # src_filename = os.path.basename(src_file_path)
    dest_filename = encrypt_filename(relative_path, passphrase)
    dest_file_path = os.path.join(dest_dir, dest_filename)
    
    if os.path.exists(dest_file_path):
        os.remove(dest_file_path)

class Watcher:
    def __init__(self, source_dir, dest_dir, passphrase):
        self.source_dir = source_dir
        self.dest_dir = dest_dir
        self.passphrase = passphrase
        self.observer = Observer()

    def run(self):
        event_handler = Handler(self.source_dir, self.dest_dir, self.passphrase)
        self.observer.schedule(event_handler, self.source_dir, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, source_dir, dest_dir, passphrase):
        self.source_dir = source_dir
        self.dest_dir = dest_dir
        self.passphrase = passphrase

    def on_created(self, event):
        if not event.is_directory:
            print(f"Created: {event.src_path}")
            encrypt_file(event.src_path, self.source_dir, self.dest_dir, self.passphrase)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"Modified: {event.src_path}")
            encrypt_file(event.src_path, self.source_dir, self.dest_dir, self.passphrase)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"Deleted: {event.src_path}")
            delete_file_from_dest(event.src_path, self.source_dir, self.dest_dir, self.passphrase)

    def on_moved(self, event):
        if not event.is_directory:
            print(f"Moved: {event.src_path} to {event.dest_path}")
            delete_file_from_dest(event.src_path, self.source_dir, self.dest_dir, self.passphrase)
            encrypt_file(event.dest_path, self.source_dir, self.dest_dir, self.passphrase)

def main():
    
    # Create the parser
    parser = argparse.ArgumentParser(description='Process some directories.')

    # Add arguments
    parser.add_argument('--source-dir', '-s', type=str, required=True, help='Path to the source directory')
    parser.add_argument('--dest-dir', '-d', type=str, required=True, help='Path to the destination directory')
    parser.add_argument('--mode', '-m', type=str, choices=['enc', 'dec'], help='Mode of operation: enc for encode, dec for decode')
    parser.add_argument('--force', '-f', action='store_true', help='Force the operation, if applicable')

    # Parse the arguments
    args = parser.parse_args()

    source_dir = args.source_dir
    dest_dir = args.dest_dir
    mode = args.mode
    force_overwrite = args.force

    stored_hash = load_passphrase_hash()
    if stored_hash is None:
        passphrase = prompt_for_passphrase(False)
        passphrase_confirm = prompt_for_passphrase()
        if passphrase != passphrase_confirm:
            print("Error: Passphrase does not match.")
            return
    else:
        passphrase = prompt_for_passphrase()

    if verify_passphrase(passphrase):
        print("Passphrase verified successfully.")

        match mode:
            case "enc":

                encrypted_file_paths = []
                    
                for dirpath, dirnames, filenames in os.walk(source_dir):
                    for filename in filenames:
                        file_path = os.path.join(dirpath, filename)
                        dest_file_path = encrypt_file(file_path, source_dir, dest_dir, passphrase)
                        encrypted_file_paths.append(dest_file_path)
                        print(f'Encrypted {file_path}')

                if force_overwrite:
                    for filename in os.listdir(dest_dir):
                        dest_file_path = os.path.join(dest_dir, filename)
                        if dest_file_path not in encrypted_file_paths:
                            print(f'Removed {dest_file_path}')
                            os.remove(dest_file_path)
                        
            case "dec":

                decrypted_file_paths = []
                
                for filename in os.listdir(dest_dir):
                    file_path = os.path.join(dest_dir, filename)
                    src_file_path = decrypt_file(file_path, source_dir, dest_dir, passphrase)
                    decrypted_file_paths.append(src_file_path)
                    print(f'Decrypted {file_path}')

                if force_overwrite:
                    for dirpath, dirnames, filenames in os.walk(source_dir):
                        for filename in filenames:
                            src_file_path = os.path.join(dirpath, filename)
                            if src_file_path not in decrypted_file_paths:
                                os.remove(src_file_path)

            case _:
                
                print(f'Watching files {source_dir}')
                watcher = Watcher(source_dir, dest_dir, passphrase)
                watcher.run()
                
    else:
        print("Error: Incorrect passphrase.")

if __name__ == '__main__':
    main()
