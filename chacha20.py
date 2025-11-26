import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import secrets
import json
import struct
import base64

class ChaCha20GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20-Poly1305 Encryption System - For the Master")
        self.root.geometry("900x700")
        
        # Variables
        self.selected_file = None
        
        self.create_interface()
    
    def create_interface(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: File Encryption
        self.files_tab = ttk.Frame(notebook)
        notebook.add(self.files_tab, text="File Encryption")
        
        # Tab 2: Text Encryption
        self.text_tab = ttk.Frame(notebook)
        notebook.add(self.text_tab, text="Text Encryption")
        
        self.create_files_tab()
        self.create_text_tab()
    
    def create_files_tab(self):
        # Main frame for files tab
        main_frame = ttk.Frame(self.files_tab, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title = ttk.Label(main_frame, text="File Encryption - ChaCha20-Poly1305", 
                          font=('Arial', 14, 'bold'))
        title.pack(pady=(0, 20))
        
        # Section: File Selection
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.pack(fill='x', pady=(0, 10))
        
        self.btn_select_file = ttk.Button(file_frame, text="Select File", 
                                                command=self.select_file)
        self.btn_select_file.pack(side='left', padx=(0, 10))
        
        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.pack(side='left')
        
        # Section: File Information
        self.info_frame = ttk.LabelFrame(main_frame, text="File Information", padding="10")
        self.info_frame.pack(fill='x', pady=(0, 10))
        
        self.info_label = ttk.Label(self.info_frame, text="Select a file to see information")
        self.info_label.pack()
        
        # Section: Operations
        operations_frame = ttk.LabelFrame(main_frame, text="Operations", padding="10")
        operations_frame.pack(fill='x', pady=(0, 10))
        
        self.btn_encrypt = ttk.Button(operations_frame, text="Encrypt File", 
                                          command=self.encrypt_file, state="disabled")
        self.btn_encrypt.pack(side='left', padx=(0, 10))
        
        self.btn_decrypt = ttk.Button(operations_frame, text="Decrypt File", 
                                             command=self.decrypt_file, state="disabled")
        self.btn_decrypt.pack(side='left')
        
        # Section: Operations Log
        log_frame = ttk.LabelFrame(main_frame, text="Operations Log and Keys", padding="10")
        log_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # Frame for log buttons
        log_buttons_frame = ttk.Frame(log_frame)
        log_buttons_frame.pack(fill='x', pady=(0, 5))
        
        self.btn_clear_log = ttk.Button(log_buttons_frame, text="Clear Log", 
                                        command=self.clear_log)
        self.btn_clear_log.pack(side='left')
        
        self.btn_copy_log = ttk.Button(log_buttons_frame, text="Copy Log", 
                                        command=self.copy_log)
        self.btn_copy_log.pack(side='left', padx=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80, wrap=tk.WORD)
        self.log_text.pack(fill='both', expand=True)
        
        # Add initial message to log
        self.log_operation("System initialized. Select a file to begin.")
    
    def create_text_tab(self):
        # Main frame for text tab
        main_frame = ttk.Frame(self.text_tab, padding="10")
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title = ttk.Label(main_frame, text="Text Encryption - ChaCha20-Poly1305", 
                          font=('Arial', 14, 'bold'))
        title.pack(pady=(0, 20))
        
        # Section: Original Text
        text_original_frame = ttk.LabelFrame(main_frame, text="Original Text", padding="10")
        text_original_frame.pack(fill='x', pady=(0, 10))
        
        self.text_input = scrolledtext.ScrolledText(text_original_frame, height=6, wrap=tk.WORD)
        self.text_input.pack(fill='both', expand=True)
        
        # Section: Text Operations
        text_operations_frame = ttk.LabelFrame(main_frame, text="Text Operations", padding="10")
        text_operations_frame.pack(fill='x', pady=(0, 10))
        
        self.btn_encrypt_text = ttk.Button(text_operations_frame, text="Encrypt Text", 
                                                command=self.encrypt_text_tab)
        self.btn_encrypt_text.pack(side='left', padx=(0, 10))
        
        self.btn_decrypt_text = ttk.Button(text_operations_frame, text="Decrypt Text", 
                                                   command=self.decrypt_text_tab)
        self.btn_decrypt_text.pack(side='left')
        
        # Section: Result
        result_frame = ttk.LabelFrame(main_frame, text="Result", padding="10")
        result_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.text_result = scrolledtext.ScrolledText(result_frame, height=8, wrap=tk.WORD, state="disabled")
        self.text_result.pack(fill='both', expand=True)
    
    def generate_automatic_key(self):
        """Generates a random 32-byte key automatically"""
        return secrets.token_bytes(32)
    
    def get_file_extension(self, file_path):
        """Gets file extension and additional information"""
        filename = os.path.basename(file_path)
        extension = os.path.splitext(filename)[1].lower()
        size = os.path.getsize(file_path)
        
        # Mapping of extensions to known types
        file_types = {
            '.pdf': 'PDF Document',
            '.png': 'PNG Image',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.gif': 'GIF Image',
            '.bmp': 'BMP Image',
            '.txt': 'Text File',
            '.doc': 'Word Document',
            '.docx': 'Word Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet',
            '.zip': 'Compressed File',
            '.rar': 'Compressed File',
            '.mp3': 'MP3 Audio',
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mkv': 'MKV Video',
            '.exe': 'Executable File',
            '.dll': 'Dynamic Library',
            '.py': 'Python Script',
            '.java': 'Java Code',
            '.cpp': 'C++ Code',
            '.html': 'Web Page',
            '.css': 'CSS Style',
            '.js': 'JavaScript',
            '.json': 'JSON File',
            '.xml': 'XML File'
        }
        
        file_type = file_types.get(extension, f'{extension.upper()} File' if extension else 'File without extension')
        
        return {
            'original_name': filename,
            'extension': extension,
            'type': file_type,
            'size': size
        }
    
    def create_file_header(self, file_info):
        """Creates a header with file metadata - SIMPLIFIED VERSION"""
        try:
            # Magic number to identify our format (8 bytes for easier handling)
            magic = b'CHACHA20'  # 8 bytes
            
            # Format version (1 byte)
            version = 1
            
            # Encode filename in base64
            encoded_name = base64.b64encode(file_info['original_name'].encode('utf-8'))
            name_size = len(encoded_name)
            
            # Original data size (8 bytes for large files)
            data_size = file_info['size']
            
            # Create header as simple bytes
            header = magic + bytes([version])
            
            # Add name size (2 bytes)
            header += name_size.to_bytes(2, byteorder='big')
            
            # Add data size (8 bytes)
            header += data_size.to_bytes(8, byteorder='big')
            
            # Add encoded name
            header += encoded_name
            
            return header
            
        except Exception as e:
            self.log_operation(f"Error creating header: {str(e)}")
            return None
    
    def read_file_header(self, data):
        """Reads file header - SIMPLIFIED VERSION"""
        try:
            # Check magic number
            if len(data) < 8 or data[:8] != b'CHACHA20':
                return None, data
            
            # Extract version
            version = data[8]
            
            # Extract name size (2 bytes)
            name_size = int.from_bytes(data[9:11], byteorder='big')
            
            # Extract data size (8 bytes)
            data_size = int.from_bytes(data[11:19], byteorder='big')
            
            # Check if we have enough data
            if len(data) < 19 + name_size:
                return None, data
            
            # Extract encoded name
            encoded_name = data[19:19 + name_size]
            
            # Decode name
            original_name = base64.b64decode(encoded_name).decode('utf-8')
            
            file_info = {
                'original_name': original_name,
                'extension': os.path.splitext(original_name)[1].lower(),
                'original_size': data_size,
                'version': version
            }
            
            # Return remaining data (after complete header)
            remaining_data = data[19 + name_size:]
            
            return file_info, remaining_data
            
        except Exception as e:
            self.log_operation(f"Error reading header: {str(e)}")
            return None, data
    
    def select_file(self):
        """Selects a file for encryption/decryption"""
        self.selected_file = filedialog.askopenfilename(
            title="Select file",
            filetypes=[("All files", "*.*")]
        )
        
        if self.selected_file:
            info = self.get_file_extension(self.selected_file)
            self.file_label.config(text=f"File: {info['original_name']}")
            
            # Show file information
            info_text = f"Type: {info['type']} | Size: {self.format_size(info['size'])} | Extension: {info['extension'] or 'None'}"
            self.info_label.config(text=info_text)
            
            self.btn_encrypt.config(state="normal")
            self.btn_decrypt.config(state="normal")
            self.log_operation(f"File selected: {info['original_name']} ({info['type']})")
    
    def format_size(self, size_bytes):
        """Formats size in bytes to a readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def encrypt_file(self):
        """Encrypts the selected file"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Select a file first")
            return
        
        try:
            # Get file information
            file_info = self.get_file_extension(self.selected_file)
            
            # Generate key automatically
            key = self.generate_automatic_key()
            key_hex = key.hex()
            
            # Read file data
            with open(self.selected_file, 'rb') as f:
                original_data = f.read()
            
            # Create header BEFORE encryption
            header = self.create_file_header(file_info)
            if header is None:
                raise Exception("Failed to create file header")
            
            self.log_operation(f"Header size: {len(header)} bytes")
            
            # Encrypt original data
            chacha = ChaCha20Poly1305(key)
            nonce = os.urandom(12)
            encrypted_data = chacha.encrypt(nonce, original_data, None)
            
            # Build final structure: HEADER + NONCE + ENCRYPTED_DATA
            final_data = header + nonce + encrypted_data
            
            # Save encrypted file
            output_file = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc")]
            )
            
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(final_data)
                
                # Display information in log
                self.log_operation("=== FILE ENCRYPTED SUCCESSFULLY ===")
                self.log_operation(f"Original file: {file_info['original_name']}")
                self.log_operation(f"Type: {file_info['type']}")
                self.log_operation(f"Original size: {self.format_size(file_info['size'])}")
                self.log_operation(f"Encrypted size: {self.format_size(len(final_data))}")
                self.log_operation(f"Encrypted file: {os.path.basename(output_file)}")
                self.log_operation(f"ENCRYPTION KEY: {key_hex}")
                self.log_operation(f"Nonce used: {nonce.hex()}")
                self.log_operation("=== KEEP THIS KEY FOR DECRYPTION ===")
                self.log_operation("")
                
                messagebox.showinfo("Success", 
                                  f"File encrypted successfully!\n\n"
                                  f"Type: {file_info['type']}\n"
                                  f"Generated key: {key_hex}\n"
                                  f"Complete key available in log.")
                
        except Exception as e:
            self.log_operation(f"ERROR in encryption: {str(e)}")
            messagebox.showerror("Error", f"Failed to encrypt: {str(e)}")
    
    def decrypt_file(self):
        """Decrypts the selected file"""
        if not self.selected_file:
            messagebox.showwarning("Warning", "Select a file first")
            return
        
        # Dialog to get the key
        key_hex = self.get_user_key("Enter decryption key (hexadecimal):")
        if not key_hex:
            return
        
        try:
            key = bytes.fromhex(key_hex)
            
            # Read encrypted file
            with open(self.selected_file, 'rb') as f:
                complete_data = f.read()
            
            self.log_operation(f"Encrypted file size: {len(complete_data)} bytes")
            
            # Try to read header
            file_info, remaining_data = self.read_file_header(complete_data)
            
            if file_info:
                self.log_operation(f"Header detected: {file_info['original_name']}")
                self.log_operation(f"Expected size: {file_info['original_size']} bytes")
                self.log_operation(f"Data size after header: {len(remaining_data)} bytes")
                
                # Check if we have nonce + encrypted data
                if len(remaining_data) < 12:
                    raise Exception(f"Insufficient data after header: {len(remaining_data)} bytes")
                
                # Extract nonce (12 bytes) and encrypted data
                nonce = remaining_data[:12]
                encrypted_data = remaining_data[12:]
                
                self.log_operation(f"Nonce extracted: {nonce.hex()}")
                self.log_operation(f"Encrypted data size: {len(encrypted_data)} bytes")
                
                # Decrypt
                chacha = ChaCha20Poly1305(key)
                original_data = chacha.decrypt(nonce, encrypted_data, None)
                
                self.log_operation(f"Decrypted data size: {len(original_data)} bytes")
                
                # Check if size matches
                if len(original_data) != file_info['original_size']:
                    self.log_operation(f"WARNING: Size mismatch - Expected: {file_info['original_size']}, Got: {len(original_data)}")
                
                # Suggest original name
                suggested_name = file_info['original_name']
                file_types = [(f"*{file_info['extension']}", file_info['extension'].upper())] if file_info['extension'] else [("All files", "*.*")]
                
            else:
                self.log_operation("Header not detected - using old format")
                
                # Old format (without header) - compatibility
                if len(complete_data) < 12:
                    raise Exception("Insufficient data for nonce")
                
                nonce = complete_data[:12]
                encrypted_data = complete_data[12:]
                
                self.log_operation(f"Nonce (old format): {nonce.hex()}")
                self.log_operation(f"Encrypted data: {len(encrypted_data)} bytes")
                
                chacha = ChaCha20Poly1305(key)
                original_data = chacha.decrypt(nonce, encrypted_data, None)
                
                suggested_name = "recovered_file"
                file_types = [("All files", "*.*")]
                file_info = {'original_name': 'recovered_file', 'extension': '', 'type': 'Unknown type'}
            
            # Save decrypted file
            output_file = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=suggested_name,
                filetypes=file_types
            )
            
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(original_data)
                
                # Success log
                self.log_operation("=== FILE DECRYPTED SUCCESSFULLY ===")
                self.log_operation(f"Recovered file: {os.path.basename(output_file)}")
                if file_info:
                    self.log_operation(f"Original type: {file_info.get('type', 'Unknown')}")
                    self.log_operation(f"Original name: {file_info['original_name']}")
                self.log_operation(f"Recovered size: {self.format_size(len(original_data))}")
                self.log_operation("")
                
                messagebox.showinfo("Success", 
                                  f"File decrypted successfully!\n\n"
                                  f"File saved as: {os.path.basename(output_file)}\n"
                                  f"Size: {self.format_size(len(original_data))}")
                
        except Exception as e:
            self.log_operation(f"ERROR in decryption: {str(e)}")
            messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")
    
    def get_user_key(self, message="Enter key (hexadecimal):"):
        """Dialog to get key from user"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Key")
        dialog.geometry("500x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=message).pack(pady=(10, 5))
        
        key_entry = ttk.Entry(dialog, width=70)
        key_entry.pack(pady=5, padx=10)
        key_entry.focus()
        
        result = [None]
        
        def confirm():
            key = key_entry.get().strip()
            # Remove spaces and check if it has 64 hex characters
            key = key.replace(' ', '')
            if len(key) == 64:  # 32 bytes in hex = 64 characters
                result[0] = key
                dialog.destroy()
            else:
                messagebox.showerror("Error", f"Invalid key. Must have 64 hexadecimal characters. Current: {len(key)}")
        
        def cancel():
            dialog.destroy()
        
        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        ttk.Button(buttons_frame, text="Confirm", command=confirm).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame, text="Cancel", command=cancel).pack(side='left')
        
        dialog.wait_window()
        return result[0]
    
    def get_key_and_nonce(self):
        """Dialog to get key and nonce from user"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Key and Nonce")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Enter decryption key (64 hex characters):").pack(pady=(10, 5))
        
        key_entry = ttk.Entry(dialog, width=70)
        key_entry.pack(pady=5, padx=10)
        
        ttk.Label(dialog, text="Enter nonce (24 hex characters):").pack(pady=(10, 5))
        
        nonce_entry = ttk.Entry(dialog, width=70)
        nonce_entry.pack(pady=5, padx=10)
        
        key_entry.focus()
        
        result = [None, None]
        
        def confirm():
            key = key_entry.get().strip()
            nonce = nonce_entry.get().strip()
            
            # Remove spaces
            key = key.replace(' ', '')
            nonce = nonce.replace(' ', '')
            
            if len(key) == 64 and len(nonce) == 24:
                result[0] = key
                result[1] = nonce
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Key must have 64 characters and nonce 24 hexadecimal characters.")
        
        def cancel():
            dialog.destroy()
        
        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        ttk.Button(buttons_frame, text="Confirm", command=confirm).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame, text="Cancel", command=cancel).pack(side='left')
        
        dialog.wait_window()
        return result[0], result[1]
    
    def encrypt_text_tab(self):
        """Encrypts text in the text tab"""
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "Enter some text to encrypt")
            return
        
        try:
            # Generate key automatically
            key = self.generate_automatic_key()
            key_hex = key.hex()
            
            chacha = ChaCha20Poly1305(key)
            nonce = os.urandom(12)
            nonce_hex = nonce.hex()
            
            encrypted_text = chacha.encrypt(nonce, text.encode('utf-8'), None)
            encrypted_text_hex = encrypted_text.hex()
            
            # Format result in JSON for easy decryption
            result_json = {
                "key": key_hex,
                "nonce": nonce_hex,
                "encrypted_text": encrypted_text_hex
            }
            
            result = f"=== ENCRYPTED TEXT ===\n"
            result += f"JSON format (use for decryption):\n"
            result += json.dumps(result_json, indent=2)
            result += f"\n\n=== INDIVIDUAL DATA ===\n"
            result += f"Key: {key_hex}\n"
            result += f"Nonce: {nonce_hex}\n"
            result += f"Encrypted Text: {encrypted_text_hex}\n"
            result += f"=== KEEP THIS DATA FOR DECRYPTION ==="
            
            # Display result
            self.text_result.config(state="normal")
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert("1.0", result)
            self.text_result.config(state="disabled")
            
            # Log in files tab
            self.log_operation("=== TEXT ENCRYPTED IN TEXT TAB ===")
            self.log_operation(f"Key generated: {key_hex}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt text: {str(e)}")
    
    def decrypt_text_tab(self):
        """Decrypts text in the text tab"""
        text_input = self.text_input.get("1.0", tk.END).strip()
        if not text_input:
            messagebox.showwarning("Warning", "Paste encrypted data")
            return
        
        try:
            # Try to detect if it's JSON
            if text_input.startswith('{') and text_input.endswith('}'):
                # It's JSON - extract key, nonce and text
                data = json.loads(text_input)
                key_hex = data.get('key', '')
                nonce_hex = data.get('nonce', '')
                encrypted_text_hex = data.get('encrypted_text', '')
                
                if not all([key_hex, nonce_hex, encrypted_text_hex]):
                    raise ValueError("Incomplete JSON")
                    
            else:
                # Not JSON - ask for key and nonce separately
                key_hex, nonce_hex = self.get_key_and_nonce()
                if not key_hex or not nonce_hex:
                    return
                encrypted_text_hex = text_input
            
            # Convert to bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            encrypted_text = bytes.fromhex(encrypted_text_hex)
            
            # Decrypt
            chacha = ChaCha20Poly1305(key)
            decrypted_text = chacha.decrypt(nonce, encrypted_text, None)
            original_text = decrypted_text.decode('utf-8')
            
            # Display result
            result = f"=== DECRYPTED TEXT ===\n{original_text}\n\n"
            result += f"=== USED DATA ===\n"
            result += f"Key: {key_hex}\n"
            result += f"Nonce: {nonce_hex}\n"
            result += f"Encrypted Text: {encrypted_text_hex}"
            
            self.text_result.config(state="normal")
            self.text_result.delete("1.0", tk.END)
            self.text_result.insert("1.0", result)
            self.text_result.config(state="disabled")
            
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON format. Use the format generated by encryption or enter key and nonce manually.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt text: {str(e)}")
    
    def clear_log(self):
        """Clears all log content"""
        self.log_text.delete("1.0", tk.END)
        self.log_operation("Log cleared.")
    
    def copy_log(self):
        """Copies all log content to clipboard"""
        content = self.log_text.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Success", "Log copied to clipboard")
    
    def log_operation(self, message):
        """Adds message to log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChaCha20GUI(root)
    root.mainloop()