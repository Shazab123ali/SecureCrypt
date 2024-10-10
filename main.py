import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64

# Function to hash the key using SHA-256 to generate a 16-byte key for AES
def get_key(key):
    hasher = SHA256.new(key.encode('utf-8'))
    return hasher.digest()

# Function to pad the message to be a multiple of the AES block size (16 bytes)
def pad_message(message):
    pad_length = AES.block_size - len(message) % AES.block_size
    return message + (chr(pad_length) * pad_length)

# Function to remove padding from the decrypted message
def unpad_message(message):
    return message[:-ord(message[len(message) - 1:])]

# Function to encrypt text
def encrypt_text():
    key = key_entry.get()
    message = input_text.get().strip()
    if not key or not message:
        messagebox.showerror("Input Error", "Please provide both the message and the key.")
        return
    try:
        key = get_key(key)
        message = pad_message(message)
        iv = Random.new().read(AES.block_size)  # Generate Initialization Vector
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = base64.b64encode(iv + cipher.encrypt(message.encode('utf-8')))
        output_text.delete(0, tk.END)
        output_text.insert(tk.END, encrypted_message.decode('utf-8'))
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

# Function to decrypt text
def decrypt_text():
    key = key_entry.get()
    encrypted_message = input_text.get().strip()
    if not key or not encrypted_message:
        messagebox.showerror("Input Error", "Please provide both the encrypted message and the key.")
        return
    try:
        key = get_key(key)
        encrypted_message = base64.b64decode(encrypted_message)
        iv = encrypted_message[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad_message(cipher.decrypt(encrypted_message[AES.block_size:])).decode('utf-8')
        output_text.delete(0, tk.END)
        output_text.insert(tk.END, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Function to encrypt a file
def encrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    key = file_key_entry.get()
    if not key:
        messagebox.showerror("Input Error", "Please provide a key for file encryption.")
        return
    try:
        key = get_key(key)
        with open(filepath, 'rb') as f:
            file_data = f.read()
        file_data = pad_message(file_data.decode('utf-8')).encode('utf-8')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_file_data = iv + cipher.encrypt(file_data)
        with open(filepath + ".enc", 'wb') as f:
            f.write(encrypted_file_data)
        messagebox.showinfo("Success", f"File encrypted successfully: {filepath}.enc")
    except Exception as e:
        messagebox.showerror("Error", f"File encryption failed: {e}")

# Function to decrypt a file with proper error handling for wrong key
def decrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    key = file_key_entry.get()
    if not key:
        messagebox.showerror("Input Error", "Please provide a key for file decryption.")
        return
    try:
        key = get_key(key)
        with open(filepath, 'rb') as f:
            encrypted_file_data = f.read()
        iv = encrypted_file_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_file_data = cipher.decrypt(encrypted_file_data[AES.block_size:])
        
        # Try to unpad the data (will raise an error if padding is invalid)
        decrypted_file_data = unpad_message(decrypted_file_data)
        
        # Write decrypted file
        with open(filepath.replace(".enc", ""), 'wb') as f:
            f.write(decrypted_file_data)
        messagebox.showinfo("Success", f"File decrypted successfully: {filepath.replace('.enc', '')}")
    except (ValueError, KeyError) as e:
        # Catch padding errors and key errors, which indicate decryption failure
        messagebox.showerror("Decryption Error", "Decryption failed. Wrong key or corrupted file.")


# Create the tkinter window
root = tk.Tk()
root.title("Secure Crypt")
root.geometry("600x400")
root.resizable(True, True)

# Set up a dark grey, light grey, and neon blue futuristic theme
style = ttk.Style()
root.configure(bg="#1f1f1f")  # Dark grey background

style.configure("TLabel", foreground="#00ffff", background="#1f1f1f", font=("Helvetica", 10, "bold"))  # Neon light blue labels
style.configure("TButton", foreground="#00ffff", background="#3e3e3e", font=("Helvetica", 10, "bold"), padding=6)
style.map("TButton", background=[('active', '#00ffff')])  # Button turns neon blue on hover

style.configure("TEntry", fieldbackground="#e0e0e0", background="#3e3e3e", foreground="#000000")  # Light grey entry with neon blue text

# Add a logo (replace 'logo.png' with the path to your logo)
logo = tk.PhotoImage(file="logo.png")  # Ensure you have a logo.png in the directory
logo_label = tk.Label(root, image=logo, bg="#1f1f1f")
logo_label.pack(pady=10)

# First line - Input box, key box, encrypt and decrypt buttons
input_frame = ttk.Frame(root, style="TFrame")
input_frame.pack(pady=10)

ttk.Label(input_frame, text="Input Text:").grid(row=0, column=0, padx=5)
input_text = ttk.Entry(input_frame, width=40, style="TEntry")
input_text.grid(row=0, column=1, padx=5)

ttk.Label(input_frame, text="Key:").grid(row=0, column=2, padx=5)
key_entry = ttk.Entry(input_frame, width=20, style="TEntry")
key_entry.grid(row=0, column=3, padx=5)

ttk.Button(input_frame, text="Encrypt", command=encrypt_text).grid(row=0, column=4, padx=5)
ttk.Button(input_frame, text="Decrypt", command=decrypt_text).grid(row=0, column=5, padx=5)

# Second line - Output box
output_frame = ttk.Frame(root, style="TFrame")
output_frame.pack(pady=10)

ttk.Label(output_frame, text="Output:").grid(row=0, column=0, padx=5)
output_text = ttk.Entry(output_frame, width=60, style="TEntry")
output_text.grid(row=0, column=1, padx=5)

# Third line - File encryption/decryption
file_frame = ttk.Frame(root, style="TFrame")
file_frame.pack(pady=10)

ttk.Label(file_frame, text="Key:").grid(row=0, column=0, padx=5)
file_key_entry = ttk.Entry(file_frame, width=20, style="TEntry")
file_key_entry.grid(row=0, column=1, padx=5)

ttk.Button(file_frame, text="Encrypt File", command=encrypt_file).grid(row=0, column=2, padx=5)
ttk.Button(file_frame, text="Decrypt File", command=decrypt_file).grid(row=0, column=3, padx=5)

root.mainloop()
