# professional_cipher_gui_neon.py
import sys
import base64
import json
import time
from pathlib import Path
from typing import List, Tuple
import os

from PyQt6 import QtCore, QtGui, QtWidgets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


def resource_path(relative_path):
    # Get absolute path to resource, works for dev and PyInstaller
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except Exception:
        base_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )  # go up from src
    return os.path.join(base_path, relative_path)


# -------------------
# Crypto parameters
# -------------------
PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32  # AES-256 default
DEFAULT_CLIP_CLEAR_SECONDS = 20


# -------------------
# Utility functions
# -------------------
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(
        password.encode("utf-8"), salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS
    )


def encrypt_item(item: str, password: str) -> str:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(item.encode("utf-8"))
    combined = salt + cipher.nonce + tag + ct
    return base64.b64encode(combined).decode("utf-8")


def decrypt_item(encoded: str, password: str) -> str:
    combined = base64.b64decode(encoded)
    if len(combined) < 48:
        raise ValueError("Invalid encrypted payload length.")
    salt = combined[:16]
    nonce = combined[16:32]
    tag = combined[32:48]
    ct = combined[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode("utf-8")


def encrypt_items(items: List[str], password: str) -> str:
    return "||".join(encrypt_item(i, password) for i in items)


def decrypt_items(encrypted_string: str, password: str) -> List[str]:
    if not encrypted_string.strip():
        return []
    parts = encrypted_string.split("||")
    return [decrypt_item(p, password) for p in parts]


# Simple password strength estimator (no external deps)
def password_strength(password: str) -> Tuple[int, str]:
    length = len(password)
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    score = min(4, classes + (length >= 12) + (length >= 16))
    # score 0..4
    if score <= 1:
        label = "Very weak"
    elif score == 2:
        label = "Weak"
    elif score == 3:
        label = "Good"
    else:
        label = "Strong"
    return score, label


# -------------------
# Stylesheet (dark neon)
# -------------------
NEON_STYLE = """
QWidget {
    background: #0b0f14;
    color: #cfefff;
    font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial;
}
QLineEdit, QPlainTextEdit, QTextEdit {
    background: #071018;
    border: 1px solid #0f6b9a;
    border-radius: 8px;
    padding: 8px;
    selection-background-color: #0b4f73;
}
QPushButton {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #052a3c, stop:1 #063a56);
    border: 1px solid #11a6ff;
    border-radius: 10px;
    padding: 8px 12px;
}
QPushButton:hover { border: 1px solid #6fe0ff; }
QPushButton:pressed { background: #03222d; }
QTabWidget::pane { border: none; }
QTabBar::tab {
    background: #071018;
    border: 1px solid #0f6b9a;
    padding: 8px 14px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #08304a, stop:1 #0b4f73);
    color: #e6fbff;
    border-bottom: 2px solid #00aaff;
}
QStatusBar { background: #05080a; border: none; color: #7fd6ff; }
QListWidget {
    background: #071018;
    border: 1px solid #0f6b9a;
    border-radius: 6px;
    padding: 6px;
}
QSpinBox { background: #071018; border: 1px solid #0f6b9a; border-radius: 6px; padding: 4px; }
QLabel#titleLabel { color: #8be9ff; font-weight: 700; font-size: 18px; }
"""


# -------------------
# Main Application
# -------------------
class NeonCipherApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional Cipher")
        self.setWindowIcon(QtGui.QIcon(resource_path("assets/icons/encrypt.png")))
        self.setMinimumSize(980, 640)
        self.clip_clear_seconds = DEFAULT_CLIP_CLEAR_SECONDS
        self._init_ui()
        self.setStyleSheet(NEON_STYLE)

    def _init_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)
        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("PROFESSIONAL CIPHER")
        title.setObjectName("titleLabel")
        header.addWidget(title)
        header.addStretch()
        main_layout.addLayout(header)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tabs)

        # Encrypt tab
        self.tab_encrypt = QtWidgets.QWidget()
        self._build_encrypt_tab()
        self.tabs.addTab(self.tab_encrypt, "Encrypt")

        # Decrypt tab
        self.tab_decrypt = QtWidgets.QWidget()
        self._build_decrypt_tab()
        self.tabs.addTab(self.tab_decrypt, "Decrypt")

        # Vault tab
        self.tab_vault = QtWidgets.QWidget()
        self._build_vault_tab()
        self.tabs.addTab(self.tab_vault, "Vault")

        # Status bar
        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)

    # -------------------
    # Encrypt Tab UI
    # -------------------
    def _build_encrypt_tab(self):
        layout = QtWidgets.QVBoxLayout(self.tab_encrypt)
        hint = QtWidgets.QLabel(
            "Enter secrets (one per line). Strong master password is recommended."
        )
        layout.addWidget(hint)

        self.plain_input = QtWidgets.QPlainTextEdit()
        self.plain_input.setPlaceholderText(
            "my-secret-1\napi-token-xxx\nanother-secret"
        )
        layout.addWidget(self.plain_input, stretch=3)

        pwd_row = QtWidgets.QHBoxLayout()
        self.pwd_enc = QtWidgets.QLineEdit()
        self.pwd_enc.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.pwd_enc.setPlaceholderText("Master password")
        self.pwd_enc.textChanged.connect(self._update_strength_enc)
        pwd_row.addWidget(self.pwd_enc)

        self.pwd_show_enc = QtWidgets.QPushButton("Show")
        self.pwd_show_enc.setCheckable(True)
        self.pwd_show_enc.clicked.connect(
            lambda: self._toggle_password(self.pwd_enc, self.pwd_show_enc)
        )
        pwd_row.addWidget(self.pwd_show_enc)

        self.strength_label_enc = QtWidgets.QLabel("Strength: —")
        pwd_row.addWidget(self.strength_label_enc)
        pwd_row.addStretch()
        layout.addLayout(pwd_row)

        btn_row = QtWidgets.QHBoxLayout()
        self.encrypt_btn = QtWidgets.QPushButton("Encrypt • LOCK")
        self.encrypt_btn.clicked.connect(self._on_encrypt)
        btn_row.addWidget(self.encrypt_btn)

        self.copy_enc_btn = QtWidgets.QPushButton("Copy Encrypted")
        self.copy_enc_btn.clicked.connect(self._copy_encrypted_to_clipboard)
        btn_row.addWidget(self.copy_enc_btn)

        btn_row.addStretch()
        btn_row.addWidget(QtWidgets.QLabel("Auto-clear (sec):"))
        self.clear_spin = QtWidgets.QSpinBox()
        self.clear_spin.setRange(5, 300)
        self.clear_spin.setValue(self.clip_clear_seconds)
        self.clear_spin.valueChanged.connect(self._on_clear_seconds_changed)
        btn_row.addWidget(self.clear_spin)
        layout.addLayout(btn_row)

        layout.addWidget(QtWidgets.QLabel("Encrypted output:"))
        self.encrypted_output = QtWidgets.QPlainTextEdit()
        self.encrypted_output.setReadOnly(True)
        self.encrypted_output.setPlaceholderText("Encrypted data will appear here...")
        layout.addWidget(self.encrypted_output, stretch=3)

    # -------------------
    # Decrypt Tab UI
    # -------------------
    def _build_decrypt_tab(self):
        layout = QtWidgets.QVBoxLayout(self.tab_decrypt)
        hint = QtWidgets.QLabel(
            "Paste encrypted string to decrypt (single or multi-entry)."
        )
        layout.addWidget(hint)

        self.encrypted_input = QtWidgets.QPlainTextEdit()
        self.encrypted_input.setPlaceholderText("paste-encrypted-data-here")
        layout.addWidget(self.encrypted_input, stretch=3)

        pwd_row = QtWidgets.QHBoxLayout()
        self.pwd_dec = QtWidgets.QLineEdit()
        self.pwd_dec.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.pwd_dec.setPlaceholderText("Master password")
        self.pwd_dec.textChanged.connect(self._update_strength_dec)
        pwd_row.addWidget(self.pwd_dec)

        self.pwd_show_dec = QtWidgets.QPushButton("Show")
        self.pwd_show_dec.setCheckable(True)
        self.pwd_show_dec.clicked.connect(
            lambda: self._toggle_password(self.pwd_dec, self.pwd_show_dec)
        )
        pwd_row.addWidget(self.pwd_show_dec)

        self.strength_label_dec = QtWidgets.QLabel("Strength: —")
        pwd_row.addWidget(self.strength_label_dec)
        pwd_row.addStretch()
        layout.addLayout(pwd_row)

        btn_row = QtWidgets.QHBoxLayout()
        self.decrypt_btn = QtWidgets.QPushButton("Decrypt • OPEN")
        self.decrypt_btn.clicked.connect(self._on_decrypt)
        btn_row.addWidget(self.decrypt_btn)

        self.copy_dec_btn = QtWidgets.QPushButton("Copy Decrypted")
        self.copy_dec_btn.clicked.connect(self._copy_decrypted_to_clipboard)
        btn_row.addWidget(self.copy_dec_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addWidget(QtWidgets.QLabel("Decrypted items:"))
        self.decrypted_list = QtWidgets.QListWidget()
        layout.addWidget(self.decrypted_list, stretch=3)

    # -------------------
    # Vault Tab UI
    # -------------------
    def _build_vault_tab(self):
        layout = QtWidgets.QVBoxLayout(self.tab_vault)
        hint = QtWidgets.QLabel(
            "Save or load encrypted vault files (.cipher). Files are JSON containing 'encrypted' and metadata."
        )
        layout.addWidget(hint)

        hv = QtWidgets.QHBoxLayout()
        self.save_btn = QtWidgets.QPushButton("Save Encrypted -> .cipher")
        self.save_btn.clicked.connect(self._on_save)
        hv.addWidget(self.save_btn)

        self.load_btn = QtWidgets.QPushButton("Load .cipher")
        self.load_btn.clicked.connect(self._on_load)
        hv.addWidget(self.load_btn)

        hv.addStretch()
        layout.addLayout(hv)

        layout.addWidget(QtWidgets.QLabel("Vault file info:"))
        self.vault_info = QtWidgets.QPlainTextEdit()
        self.vault_info.setReadOnly(True)
        self.vault_info.setPlaceholderText("No file loaded.")
        layout.addWidget(self.vault_info, stretch=2)

        layout.addWidget(QtWidgets.QLabel("Saved files (last opened):"))
        self.recent_list = QtWidgets.QListWidget()
        layout.addWidget(self.recent_list, stretch=3)

        # internal recent files storage
        self._recent_files = []

    # -------------------
    # Helper / Actions
    # -------------------
    def _toggle_password(self, field: QtWidgets.QLineEdit, btn: QtWidgets.QPushButton):
        if btn.isChecked():
            field.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)
            btn.setText("Hide")
        else:
            field.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            btn.setText("Show")

    def _update_strength_enc(self, _):
        s, label = password_strength(self.pwd_enc.text())
        color = {
            0: "#ff5370",
            1: "#ff9f63",
            2: "#ffd86b",
            3: "#9be564",
            4: "#4be0a7",
        }.get(s, "#9be564")
        self.strength_label_enc.setText(f"Strength: {label}")
        self.strength_label_enc.setStyleSheet(f"color: {color}")

    def _update_strength_dec(self, _):
        s, label = password_strength(self.pwd_dec.text())
        color = {
            0: "#ff5370",
            1: "#ff9f63",
            2: "#ffd86b",
            3: "#9be564",
            4: "#4be0a7",
        }.get(s, "#9be564")
        self.strength_label_dec.setText(f"Strength: {label}")
        self.strength_label_dec.setStyleSheet(f"color: {color}")

    def _on_encrypt(self):
        pwd = self.pwd_enc.text()
        if not pwd:
            QtWidgets.QMessageBox.warning(
                self, "Missing password", "Enter a master password to encrypt."
            )
            return
        items = [
            ln.strip()
            for ln in self.plain_input.toPlainText().splitlines()
            if ln.strip()
        ]
        if not items:
            QtWidgets.QMessageBox.warning(
                self, "No secrets", "Enter one or more secrets to encrypt."
            )
            return
        try:
            enc = encrypt_items(items, pwd)
            self.encrypted_output.setPlainText(enc)
            self.status.showMessage("Encrypted ✓ (copied available)", 4000)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Encrypt error", str(e))

    def _on_decrypt(self):
        pwd = self.pwd_dec.text()
        if not pwd:
            QtWidgets.QMessageBox.warning(
                self, "Missing password", "Enter master password to decrypt."
            )
            return
        enc = self.encrypted_input.toPlainText().strip()
        if not enc:
            QtWidgets.QMessageBox.warning(
                self, "No encrypted data", "Paste encrypted data to decrypt."
            )
            return
        try:
            items = decrypt_items(enc, pwd)
            self.decrypted_list.clear()
            for i in items:
                self.decrypted_list.addItem(i)
            self.status.showMessage("Decryption successful ✓", 4000)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Decrypt error", str(e))

    def _copy_encrypted_to_clipboard(self):
        enc = self.encrypted_output.toPlainText().strip()
        if not enc:
            QtWidgets.QMessageBox.warning(
                self, "Nothing to copy", "No encrypted output available."
            )
            return
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(enc)
        self.status.showMessage("Encrypted copied to clipboard (will auto-clear)", 3000)
        QtCore.QTimer.singleShot(
            self.clip_clear_seconds * 1000,
            lambda: self._clear_clipboard_if_matches(enc),
        )

    def _copy_decrypted_to_clipboard(self):
        items = [
            self.decrypted_list.item(i).text()
            for i in range(self.decrypted_list.count())
        ]
        if not items:
            QtWidgets.QMessageBox.warning(
                self, "Nothing to copy", "No decrypted items available."
            )
            return
        text = "\n".join(items)
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(text)
        self.status.showMessage("Decrypted copied to clipboard (will auto-clear)", 3000)
        QtCore.QTimer.singleShot(
            self.clip_clear_seconds * 1000,
            lambda: self._clear_clipboard_if_matches(text),
        )

    def _clear_clipboard_if_matches(self, previous_text: str):
        cb = QtWidgets.QApplication.clipboard()
        try:
            if cb.text() == previous_text:
                cb.clear()
                self.status.showMessage("Clipboard auto-cleared ✓", 3000)
        except Exception:
            pass

    def _on_clear_seconds_changed(self, val):
        self.clip_clear_seconds = val
        self.status.showMessage(f"Auto-clear set to {val} sec", 2500)

    # -------------------
    # Save / Load Vault
    # -------------------
    def _on_save(self):
        enc = self.encrypted_output.toPlainText().strip()
        if not enc:
            QtWidgets.QMessageBox.warning(
                self, "Nothing to save", "No encrypted text to save. Encrypt first."
            )
            return
        fname, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Save Encrypted Vault",
            "vault.cipher",
            "Cipher files (*.cipher);;All Files (*)",
        )
        if not fname:
            return
        data = {
            "encrypted": enc,
            "created_at": int(time.time()),
            "count": len(enc.split("||")),
            "meta": {"app": "Professional Cipher Neon"},
        }
        try:
            Path(fname).write_text(json.dumps(data), encoding="utf-8")
            self._add_recent(fname)
            self.status.showMessage(f"Saved {Path(fname).name}", 4000)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save error", f"Failed to save: {e}")

    def _on_load(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Load Encrypted Vault", "", "Cipher files (*.cipher);;All Files (*)"
        )
        if not fname:
            return
        try:
            raw = Path(fname).read_text(encoding="utf-8")
            data = json.loads(raw)
            enc = data.get("encrypted", "")
            self.encrypted_input.setPlainText(enc)
            info = (
                f"File: {Path(fname).name}\n"
                f"Created (epoch): {data.get('created_at')}\n"
                f"Item count: {data.get('count')}\n"
                f"Note: Loaded into Decrypt tab for inspection."
            )
            self.vault_info.setPlainText(info)
            self._add_recent(fname)
            self.status.showMessage(f"Loaded {Path(fname).name}", 4000)
            # Switch to Decrypt tab to encourage user to decrypt
            self.tabs.setCurrentWidget(self.tab_decrypt)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Load error", f"Failed to load: {e}")

    def _add_recent(self, fname: str):
        if fname in self._recent_files:
            self._recent_files.remove(fname)
        self._recent_files.insert(0, fname)
        # keep last 10
        self._recent_files = self._recent_files[:10]
        self.recent_list.clear()
        for f in self._recent_files:
            self.recent_list.addItem(f)


# -------------------
# Run
# -------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = NeonCipherApp()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
