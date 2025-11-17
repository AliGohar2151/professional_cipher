# Professional Cipher

```
   ___  ___ ___ ___ ___
  / __|/ __/ __| _ \ __|
 | (__ \__ \__ \   / _|
  \___||___/___/_|_\___|
```

A simple yet robust command-line tool for securely encrypting and decrypting secrets using AES-256-GCM. It's designed for professionals who need a quick and secure way to handle sensitive information directly from the terminal.

## Features

- **Strong Encryption**: Uses AES-256 in GCM mode for authenticated encryption, ensuring both confidentiality and integrity.
- **Secure Key Derivation**: Derives the encryption key from your master password using PBKDF2 with a high iteration count (`200,000`) to protect against brute-force attacks.
- **Multi-line Support**: Encrypt and decrypt multiple lines of text at once.
- **Clipboard Integration**: Automatically copies the output (encrypted or decrypted text) to your clipboard for convenience.
- **User-Friendly Interface**: A clean, interactive CLI built with the `rich` library.

## Security

The security of your encrypted data relies entirely on the strength and secrecy of your master password.

- **Encryption**: AES-GCM is an industry-standard authenticated encryption algorithm. It not only encrypts your data but also generates a tag to verify its integrity, protecting it from tampering.
- **Password Handling**: The master password is never stored. It is used with a unique, randomly generated salt for each encryption to derive a key via PBKDF2.

> **Warning**: Keep your master password safe. Without it, your data cannot be decrypted. There is no recovery mechanism.

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/AliGohar2151/professional_cipher
    cd professional_cipher
    ```

2.  **Create and activate a virtual environment:**
    It is highly recommended to use a virtual environment to manage dependencies.

    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from the root directory of the project:

```bash
python src/cipher.py
```

The tool will prompt you to enter your master password and then present you with three options:

1.  **`[E]` Encrypt**:

    - You will be asked to enter your secrets, one per line.
    - Press `Enter` on an empty line to finish.
    - The resulting encrypted string will be printed to the console and automatically copied to your clipboard.

2.  **`[D]` Decrypt**:

    - You will be asked to paste the encrypted string.
    - The decrypted secrets will be printed to the console and copied to your clipboard, with each secret on a new line.

3.  **`[Q]` Quit**:
    - Exits the program.

### Example Workflow

```
> python src/cipher.py
Enter your master password: ************

[E] Encrypt / [D] Decrypt / [Q] Quit: e
Enter multiple secrets (finish with an empty line):
My API Key is 123-abc
The secret meeting is at dawn

Encrypted output:
... (long encrypted string) ...

Copied to clipboard!
```
