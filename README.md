Secure Crypt
This is a Python-based AES Encryption/Decryption tool with a graphical user interface (GUI) built using `tkinter`. It allows users to securely encrypt and decrypt both text and files using a key provided by the user. The tool is designed to work seamlessly on Linux systems.
Features
- Text Encryption/Decryption:
    - Enter any text and a key to encrypt or decrypt the message.
    - AES encryption is applied with proper handling of padding and an initialization vector (IV).
- File Encryption/Decryption:
    - Encrypt or decrypt files using AES encryption.
    - Proper error handling is provided for cases where an incorrect key is used.
Prerequisites
Before running the tool, ensure you have the following dependencies installed on your Linux machine:
1. Python 3
   - Most Linux distributions come with Python pre-installed. To check if Python is installed, run:
     ```bash
     python3 --version
     ```
2. tkinter
   - `tkinter` is required for the GUI. It is usually installed with Python, but if not, you can install it by running:
     ```bash
     sudo apt-get install python3-tk
     ```

3. pycryptodome
   - This library provides the AES encryption functionality. Install it using `pip`:
     ```bash
     pip install pycryptodome
     ```
Installation

1. Clone the Repository:
   Open a terminal and clone the repository to your local machine using Git:
   ```bash
   git clone https://github.com/Shazab123ali/SecureCrypt.git
   cd aes-encryption-tool
Install the Dependencies: Make sure you have all the dependencies installed. If you haven't already installed pycryptodome, run:
  pip install pycryptodome
  Running the Tool
Launch the Tool: In the terminal, navigate to the directory where the tool is located and run the Python script:
  python main.py
  
