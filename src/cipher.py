import base64
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pyperclip
from rich import print
from rich.panel import Panel
from rich.box import DOUBLE

# =========================
#    ___  ___ ___ ___ ___
#   / __|/ __/ __| _ \ __|
#  | (__ \__ \__ \   / _|
#   \___||___/___/_|_\___|
#   PROFESSIONAL CIPHER
# =========================

BANNER = r"""
   ___  ___ ___ ___ ___
  / __|/ __/ __| _ \ __|
 | (__ \__ \__ \   / _|
  \___||___/___/_|_\___|
  PROFESSIONAL CIPHER
"""

INSTRUCTIONS = """
Welcome to Professional Cipher!

How to use:
1. Select [E] to encrypt multiple secrets. Enter each secret line by line.
   Finish by pressing Enter on an empty line.
2. Select [D] to decrypt. Paste the encrypted string.
3. Select [Q] to quit the program.

All secrets are encrypted securely using AES-GCM with a master password.
Keep your master password safe. Without it, decryption will fail.
"""

print(Panel(BANNER, box=DOUBLE))
print(INSTRUCTIONS)

# --- Encryption parameters ---
PBKDF2_ITERATIONS = 200000
KEY_LENGTH = 32  # AES-256


def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)


def encrypt_item(item, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(item.encode())
    combined = salt + cipher.nonce + tag + ct
    return base64.b64encode(combined).decode()


def decrypt_item(encoded, password):
    try:
        combined = base64.b64decode(encoded)
        salt, nonce, tag, ct = (
            combined[:16],
            combined[16:32],
            combined[32:48],
            combined[48:],
        )
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode()
    except:
        return "[ERROR] Decryption failed. Wrong master password or corrupted data."


def encrypt_items(items, password):
    return "||".join(encrypt_item(item, password) for item in items)


def decrypt_items(encrypted_string, password):
    return [decrypt_item(item, password) for item in encrypted_string.split("||")]


# --- Main interactive CLI ---
master_password = getpass("Enter your master password: ")

while True:
    print(Panel(BANNER, box=DOUBLE))  # Professional banner
    choice = input("[E] Encrypt / [D] Decrypt / [Q] Quit: ").lower()

    if choice == "e":
        print("Enter multiple secrets (finish with an empty line):")
        items = []
        while True:
            item = input()
            if item.strip() == "":
                break
            items.append(item)
        encrypted_string = encrypt_items(items, master_password)
        pyperclip.copy(encrypted_string)
        print(
            Panel(
                f"[green]Encrypted output:[/green]\n{encrypted_string}\n\n[bold yellow]Copied to clipboard![/bold yellow]",
                title="Success",
            )
        )

    elif choice == "d":
        encrypted_string = input("Paste the encrypted string: ")
        decrypted_items = decrypt_items(encrypted_string, master_password)
        pyperclip.copy("\n".join(decrypted_items))
        print(
            Panel(
                f"[green]Decrypted output:[/green]\n"
                + "\n".join(decrypted_items)
                + "\n\n[bold yellow]Copied to clipboard![/bold yellow]",
                title="Success",
            )
        )

    elif choice == "q":
        print("\nExiting Professional Cipher. Stay secure!")
        break

    else:
        print("[red]Invalid choice! Enter E, D, or Q.[/red]")
