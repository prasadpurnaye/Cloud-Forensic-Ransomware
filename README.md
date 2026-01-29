# Ransomware Encryption Analysis - Cloud Forensics Study

## ⚠️ EDUCATIONAL PURPOSE ONLY

This repository contains **educational materials** for studying ransomware behavior, encryption techniques, and digital forensics in cloud environments. These scripts are designed for:

- **Academic research** in cybersecurity
- **Forensic analysis training**
- **Incident response preparation**
- **Controlled lab environment testing**

**⚠️ WARNING: Unauthorized use of these tools on systems you don't own or have explicit permission to test is illegal and unethical.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Technical Architecture](#technical-architecture)
- [Scripts Description](#scripts-description)
- [Encryption Mechanism](#encryption-mechanism)
- [File Structure](#file-structure)
- [Installation](#installation)
- [Usage (Lab Environment Only)](#usage-lab-environment-only)
- [Forensic Analysis Points](#forensic-analysis-points)
- [Detection & Prevention](#detection--prevention)
- [Legal & Ethical Considerations](#legal--ethical-considerations)
- [References](#references)

---

## 🔍 Overview

This project demonstrates a realistic ransomware encryption/decryption workflow using **hybrid cryptography** (AES-256 + RSA-4096). It simulates how modern ransomware operates by:

1. Encrypting user files with symmetric encryption (AES-256)
2. Protecting the AES key with asymmetric encryption (RSA-4096)
3. Implementing parallel file traversal using Breadth-First Search (BFS)
4. Creating ransom notes and visual indicators
5. Providing a decryption mechanism with proper key management

### Key Learning Objectives

- Understand hybrid cryptographic systems used in ransomware
- Analyze file system traversal techniques
- Study encryption key management and distribution
- Learn forensic artifact identification
- Practice incident response procedures

---

## 🏗️ Technical Architecture

### Cryptographic Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Encryption Process                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Generate Random AES-256 Key (32 bytes)                 │
│                    ↓                                        │
│  2. Encrypt AES Key with RSA-4096 Public Key               │
│     (OAEP padding with SHA-256)                            │
│                    ↓                                        │
│  3. For each file:                                         │
│     ├─ Generate Random IV (16 bytes)                       │
│     ├─ Apply PKCS7 Padding                                 │
│     ├─ Encrypt with AES-256-CBC                            │
│     ├─ Generate HMAC-SHA256 for integrity                  │
│     └─ Save as: [IV][Ciphertext][HMAC]                    │
│                    ↓                                        │
│  4. Save encrypted AES key to disk                         │
│  5. Original files deleted, .locked files remain           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### File Encryption Format

```
┌──────────────────────────────────────────────────────────┐
│                    .locked File Structure                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Bytes 0-15:    Initialization Vector (IV)              │
│  Bytes 16-N:    AES-256-CBC Encrypted Data              │
│  Bytes N+1-N+32: HMAC-SHA256 (Integrity Check)          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 📁 Scripts Description

### 1. `windows_directory_encrypt_with_pubkey_new.py`

**Purpose:** Simulates ransomware encryption behavior

**Features:**
- Parallel BFS directory traversal (multi-threaded)
- AES-256-CBC encryption with random IV per file
- RSA-4096 public key encryption for AES key protection
- HMAC-SHA256 for file integrity verification
- Targets standard Windows user directories:
  - Documents
  - Desktop
  - Downloads
  - Music
  - Videos
  - Pictures
  - AppData/Roaming
- Generates ransom notes and wallpaper
- Saves encrypted AES key in multiple formats

**Key Components:**
```python
class AdvancedEncryptionTraversal:
    - load_rsa_public_key()      # Load RSA public key from PEM
    - encrypt_aes_key_with_rsa() # Encrypt AES key with RSA
    - encrypt_file_aes256()      # Encrypt individual file
    - bfs_traverse_directory()   # Parallel directory traversal
    - save_encrypted_key()       # Save encrypted AES key
    - save_results_to_file()     # Generate ransom note
```

### 2. `windows_directory_decrypt_advanced.py`

**Purpose:** Decrypts files encrypted by the encryption script

**Features:**
- Decrypts RSA-encrypted AES key using private key
- Verifies HMAC before decryption (prevents corruption)
- Parallel decryption with multi-threading
- Restores original filenames
- Comprehensive error handling and reporting
- Interactive CLI with safety confirmations

**Key Components:**
```python
class AdvancedDecryptionTraversal:
    - decrypt_aes_key_with_rsa() # Decrypt AES key with RSA private key
    - decrypt_file_aes256()      # Decrypt individual .locked file
    - bfs_traverse_directory()   # Find and decrypt .locked files
    - print_summary()            # Display decryption results
```

---

## 🔐 Encryption Mechanism

### Step-by-Step Process

#### Encryption Phase

1. **Key Generation**
   - Random AES-256 key generated (32 bytes)
   - RSA public key loaded from embedded PEM or file
   - AES key encrypted with RSA-OAEP-SHA256

2. **File Processing**
   ```python
   For each file:
     - Generate random 16-byte IV
     - Apply PKCS7 padding to plaintext
     - Encrypt with AES-256-CBC mode
     - Calculate HMAC-SHA256 over IV + ciphertext
     - Write: [IV][Ciphertext][HMAC] to .locked file
     - Delete original file
   ```

3. **Artifact Creation**
   - ENCRYPTED_AES_KEY.bin (binary format)
   - ENCRYPTED_AES_KEY.txt (base64 format)
   - RANSOM NOTE.txt (instructions)
   - HOW_TO_DECRYPT.txt (detailed guide)
   - wallpaper.png (visual indicator)

#### Decryption Phase

1. **Key Recovery**
   - Load RSA private key (password-protected)
   - Decrypt AES key using RSA-OAEP-SHA256
   - Validate AES key availability

2. **File Processing**
   ```python
   For each .locked file:
     - Read [IV][Ciphertext][HMAC]
     - Verify HMAC-SHA256 (integrity check)
     - Decrypt ciphertext with AES-256-CBC
     - Remove PKCS7 padding
     - Write to original filename
     - Delete .locked file
   ```

### Cryptographic Specifications

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Symmetric Cipher | AES-256-CBC | 256 bits | One key for all files |
| Asymmetric Cipher | RSA-OAEP | 4096 bits | Public/Private key pair |
| Key Derivation | Random | 256 bits | Cryptographically secure |
| Padding Scheme | PKCS7 | 128 bits | Block size for AES |
| Integrity Check | HMAC-SHA256 | 256 bits | Per-file verification |
| IV Generation | Random | 128 bits | Unique per file |

---

## 📂 File Structure

```
ransomware-forensics-study/
│
├── README.md                                    # This file
├── windows_directory_encrypt_with_pubkey_new.py # Encryption script
├── windows_directory_decrypt_advanced.py        # Decryption script
│
├── keys/                                        # Key management (not included)
│   ├── public_key.pem                          # RSA public key
│   └── private_key.pem                         # RSA private key (encrypted)
│
├── samples/                                     # Sample encrypted files
│   ├── document.txt.locked                     # Example encrypted file
│   └── ENCRYPTED_AES_KEY.bin                   # Encrypted AES key
│
├── docs/                                        # Additional documentation
│   ├── forensic_analysis.md                    # Forensic investigation guide
│   ├── detection_methods.md                    # Detection strategies
│   └── incident_response.md                    # IR procedures
│
└── lab_setup/                                   # Lab environment setup
    ├── vm_setup.md                             # Virtual machine configuration
    └── test_data_generator.py                  # Generate test files
```

---

## 🛠️ Installation

### Prerequisites

```bash
# Python 3.8 or higher required
python --version

# Install required packages
pip install cryptography pillow
```

### Dependencies

```txt
cryptography>=41.0.0    # For AES, RSA, HMAC operations
Pillow>=10.0.0         # For wallpaper generation (encryption script only)
```

### Generate RSA Key Pair (for testing)

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

# Save private key (password-protected)
with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            b'ransomware_master_password'
        )
    ))

# Extract and save public key
public_key = private_key.public_key()
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
```

---

## 🧪 Usage (Lab Environment Only)

### Setting Up Test Environment

**⚠️ CRITICAL: Only run in isolated VMs or test environments!**

1. **Create Virtual Machine**
   - Use VirtualBox, VMware, or Hyper-V
   - Install Windows 10/11 (clean installation)
   - Take snapshot before testing
   - Disable network adapter (air-gap the VM)

2. **Prepare Test Data**
   ```bash
   # Create sample directories and files
   mkdir -p ~/TestData/{Documents,Desktop,Downloads}
   echo "Test content" > ~/TestData/Documents/test1.txt
   echo "Sample data" > ~/TestData/Desktop/test2.pdf
   ```

### Running Encryption Script

```bash
# 1. Configure RSA public key in script
# Edit windows_directory_encrypt_with_pubkey_new.py
# Paste your public key in RSA_PUBLIC_KEY_PEM variable

# 2. Run encryption
python windows_directory_encrypt_with_pubkey_new.py

# 3. Observe artifacts created:
#    - *.locked files in user directories
#    - ENCRYPTED_AES_KEY.bin on Desktop
#    - RANSOM NOTE.txt on Desktop
#    - HOW_TO_DECRYPT.txt on Desktop
```

### Running Decryption Script

```bash
# 1. Run decryption tool
python windows_directory_decrypt_advanced.py

# 2. Follow interactive prompts:
#    - Provide path to RSA private key
#    - Enter private key password
#    - Provide path to ENCRYPTED_AES_KEY.bin
#    - Type 'DECRYPT' to confirm

# 3. Verify file restoration
#    - Check that .locked files are removed
#    - Original files restored with correct content
```

### Expected Output

**Encryption:**
```
Starting parallel BFS traversal with encryption (4 workers)...
Directories to traverse: Documents, Desktop, Downloads, Music, Videos, Pictures

[Documents] Starting traversal of: C:\Users\User\Documents
[Desktop] Starting traversal of: C:\Users\User\Desktop
[Documents] Encrypted: report.docx → report.docx.locked
[Desktop] Encrypted: photo.jpg → photo.jpg.locked

ENCRYPTION SUMMARY
======================================================================
TOTAL FILES PROCESSED: 1,234
SUCCESSFULLY ENCRYPTED: 1,230
FAILED: 4
SKIPPED: 0
```

**Decryption:**
```
✓ Private key loaded successfully!
✓ Encrypted AES key loaded successfully!
✓ AES-256 key decrypted successfully!

[Documents] Decrypted: report.docx.locked → report.docx
[Desktop] Decrypted: photo.jpg.locked → photo.jpg

DECRYPTION SUMMARY
======================================================================
TOTAL FILES PROCESSED: 1,234
SUCCESSFULLY DECRYPTED: 1,230
FAILED: 4
```

---

## 🔬 Forensic Analysis Points

### Digital Artifacts to Examine

1. **File System Evidence**
   - `.locked` file extensions and timestamps
   - Deletion logs for original files
   - File creation patterns (batch operations)
   - MFT (Master File Table) entries

2. **Cryptographic Artifacts**
   ```
   Desktop/ENCRYPTED_AES_KEY.bin    # RSA-encrypted AES key
   Desktop/ENCRYPTED_AES_KEY.txt    # Base64 encoded version
   Desktop/RANSOM NOTE.txt          # Ransom instructions
   Desktop/HOW_TO_DECRYPT.txt       # Decryption guide
   Desktop/wallpaper.png            # Visual indicator
   ```

3. **Process Artifacts**
   - Python process execution logs
   - Thread creation patterns (parallel processing)
   - Memory dumps showing cryptographic operations
   - Network activity (if C2 communication present)

4. **Registry Changes** (if wallpaper set)
   - `HKCU\Control Panel\Desktop\Wallpaper`
   - Desktop background modification timestamp

### Forensic Investigation Steps

```plaintext
1. Preserve Evidence
   ├─ Create disk image
   ├─ Document system state
   └─ Collect memory dump

2. Timeline Analysis
   ├─ Identify encryption start time
   ├─ Map file modification sequence
   └─ Correlate with process execution

3. Cryptographic Analysis
   ├─ Extract encryption parameters
   ├─ Analyze key management
   └─ Document algorithm implementation

4. Artifact Collection
   ├─ Gather ransom notes
   ├─ Extract encrypted key files
   └─ Document file naming patterns

5. Recovery Assessment
   ├─ Evaluate backup availability
   ├─ Test decryption feasibility
   └─ Document data loss extent
```

### YARA Rules for Detection

```yara
rule Ransomware_AES_RSA_Hybrid {
    meta:
        description = "Detects AES-RSA hybrid ransomware pattern"
        author = "Forensics Team"
        date = "2024-01-29"
    
    strings:
        $aes = "AES-256-CBC" nocase
        $rsa = "RSA" nocase
        $locked = ".locked" nocase
        $ransom = "RANSOM NOTE" nocase
        $crypto1 = "cryptography.hazmat" nocase
        $crypto2 = "OAEP" nocase
        $hmac = "HMAC-SHA256" nocase
    
    condition:
        4 of them
}
```

---

## 🛡️ Detection & Prevention

### Detection Methods

1. **Behavioral Detection**
   - Rapid file modification patterns
   - Mass file renaming to `.locked` extension
   - Unusual CPU usage (encryption operations)
   - Suspicious process names (Python, scripting engines)

2. **File System Monitoring**
   ```powershell
   # Monitor for .locked file creation
   Get-ChildItem -Path C:\Users -Recurse -Filter *.locked -File
   
   # Check for ransom notes
   Get-ChildItem -Path C:\Users -Recurse -Filter "*RANSOM*" -File
   ```

3. **Network Monitoring**
   - Unusual outbound connections
   - C2 (Command & Control) communication
   - Data exfiltration attempts

### Prevention Strategies

1. **Endpoint Protection**
   - Deploy EDR solutions
   - Enable ransomware protection in Windows Defender
   - Implement application whitelisting
   - Use behavior-based detection

2. **Access Controls**
   - Principle of least privilege
   - Disable unnecessary script interpreters
   - Implement AppLocker policies
   - Segment network access

3. **Backup Strategy**
   - Regular automated backups (3-2-1 rule)
   - Offline/immutable backups
   - Test restore procedures
   - Versioned file systems

4. **User Training**
   - Phishing awareness
   - Safe browsing practices
   - Suspicious attachment identification
   - Incident reporting procedures

### Windows Defender Configuration

```powershell
# Enable controlled folder access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add protected folders
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\$env:USERNAME\Documents"

# Enable cloud-delivered protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
```

---

## ⚖️ Legal & Ethical Considerations

### Legal Framework

**⚠️ IMPORTANT: Violating these laws can result in severe criminal penalties**

| Jurisdiction | Relevant Laws |
|--------------|---------------|
| United States | Computer Fraud and Abuse Act (CFAA) 18 U.S.C. § 1030 |
| European Union | General Data Protection Regulation (GDPR) |
| United Kingdom | Computer Misuse Act 1990 |
| International | Budapest Convention on Cybercrime |

### Ethical Guidelines

1. **Authorized Use Only**
   - Obtain explicit written permission
   - Only test on systems you own
   - Use isolated lab environments
   - Document all testing activities

2. **Responsible Disclosure**
   - Report vulnerabilities ethically
   - Follow coordinated disclosure timelines
   - Protect user data and privacy
   - Assist in remediation efforts

3. **Educational Purpose**
   - Share knowledge responsibly
   - Promote defensive security
   - Train incident responders
   - Advance cybersecurity research

4. **Professional Standards**
   - Follow industry best practices
   - Maintain confidentiality
   - Respect intellectual property
   - Adhere to professional codes of conduct

### Prohibited Activities

- ❌ Deploying on production systems
- ❌ Unauthorized testing on third-party systems
- ❌ Using for malicious purposes
- ❌ Distributing compiled malware
- ❌ Bypassing security controls without permission
- ❌ Causing harm or data loss

---

## 📚 References

### Academic Resources

1. **Ransomware Analysis**
   - [Understanding Ransomware Encryption Techniques](https://example.com)
   - [Hybrid Cryptography in Modern Ransomware](https://example.com)
   - [Forensic Analysis of Crypto-Ransomware](https://example.com)

2. **Cryptography**
   - [NIST Special Publication 800-175B](https://csrc.nist.gov/publications/detail/sp/800-175b/final) - Guideline for Using Cryptographic Standards
   - [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

3. **Incident Response**
   - [SANS Ransomware Response Guide](https://www.sans.org/)
   - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Tools & Frameworks

- **Python Cryptography Library**: https://cryptography.io/
- **YARA Rules**: https://virustotal.github.io/yara/
- **Volatility Framework**: https://www.volatilityfoundation.org/
- **Autopsy Digital Forensics**: https://www.autopsy.com/

### Industry Reports

- Verizon Data Breach Investigations Report (DBIR)
- Sophos State of Ransomware Report
- IBM Cost of a Data Breach Report

---

## 🤝 Contributing

This is an educational project. Contributions that enhance learning objectives are welcome:

- Improve documentation
- Add forensic analysis examples
- Enhance detection methods
- Submit bug fixes
- Suggest educational enhancements

**Please ensure all contributions maintain ethical and educational focus.**

---

## 📄 License

This project is licensed under MIT License for **educational purposes only**.

```
MIT License

Copyright (c) 2024 [Your Institution/Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Disclaimer

```
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.

The authors and contributors:
- DO NOT condone malicious use of this software
- ARE NOT responsible for any misuse or damage caused
- REQUIRE users to comply with all applicable laws
- EXPECT ethical and responsible usage
- RECOMMEND use only in controlled lab environments

By using this software, you agree to use it responsibly and ethically,
and accept full responsibility for your actions.
```

---

## 📞 Contact & Support

For educational inquiries, vulnerability reports, or ethical use questions:

- **Email**: [your-email@institution.edu]
- **Issues**: [GitHub Issues Page]
- **Discussions**: [GitHub Discussions]

**Emergency Security Incidents:**
- Report to your organization's security team
- Contact relevant law enforcement (FBI IC3, Europol, etc.)
- Engage incident response professionals

---

## 🎓 Learning Outcomes

After studying this project, you should understand:

✅ Hybrid cryptographic systems (symmetric + asymmetric)  
✅ File system traversal and manipulation techniques  
✅ Ransomware behavioral patterns and TTPs  
✅ Digital forensic artifact identification  
✅ Incident response procedures  
✅ Cryptographic key management  
✅ Integrity verification mechanisms (HMAC)  
✅ Detection and prevention strategies  

---

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01-29 | Initial release with encryption/decryption scripts |

---

**Remember: Knowledge is power. Use it responsibly. 🛡️**
