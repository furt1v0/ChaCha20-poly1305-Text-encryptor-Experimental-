# ChaCha20-Poly1305 Encryption System [BY - furt1v0]

A robust and user-friendly file and text encryption system built with Python and Tkinter, featuring the secure ChaCha20-Poly1305 authenticated encryption algorithm.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-ChaCha20--Poly1305-orange.svg)

##################################### FEATURES  ###################################

###  File Encryption
- **Secure Encryption**: ChaCha20-Poly1305 authenticated encryption
- **Metadata Preservation**: Automatically preserves original filename, extension, and file type
- **Automatic Key Generation**: Cryptographically secure random keys
- **Format Detection**: Supports all file types (PDF, PNG, JPG, DOCX, etc.)
- **Header System**: Custom header format for metadata preservation

###################################  Text Encryption  ###################################
- **Real-time Encryption**: Instant text encryption/decryption
- **JSON Output**: Structured output for easy data management
- **Multiple Formats**: Support for both JSON and manual key input

###################################  User Interface ###################################
- **Dual Tab Interface**: Separate tabs for file and text operations
- **Detailed Logging**: Comprehensive operation log with copy/clear functions
- **Progress Tracking**: Real-time operation feedback
- **Error Handling**: Robust error handling with detailed messages

################################### Installation ###################################

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Dependencies
```bash
pip install cryptography
