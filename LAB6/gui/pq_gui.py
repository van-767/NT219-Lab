"""
PySide6 GUI cho Lab 6 — gọi libpq_core.dll qua ctypes.
Tất cả crypto chạy trong DLL, Python chỉ là vỏ.

Install:    pip install PySide6
Run:        python gui/pq_gui.py
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from ctypes import c_char_p, c_int

from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFormLayout, QHBoxLayout, QLineEdit,
    QMainWindow, QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
    QComboBox,
)

# -----------------------------------------------------------------------
# Load shared lib
# -----------------------------------------------------------------------
def _candidate_paths() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    subdir = ("windows" if platform.system() == "Windows"
              else "macos" if platform.system() == "Darwin"
              else "linux")
    names_win = ["libpq_core.dll", "pq_core.dll"]
    names_lin = ["libpq_core.so",  "pq_core.so"]
    names_mac = ["libpq_core.dylib", "pq_core.dylib"]
    names = (names_win if platform.system() == "Windows"
             else names_mac if platform.system() == "Darwin" else names_lin)
    roots = [
        here,
        os.path.join(here, ".."),
        os.path.join(here, "..", "bin", subdir),
        os.path.join(here, "..", "build"),
        os.path.join(here, "..", "build", "Release"),
    ]
    return [os.path.join(r, n) for r in roots for n in names]


def load_lib() -> ctypes.CDLL:
    if platform.system() == "Windows":
        msys = r"C:\msys64\mingw64\bin"
        if hasattr(os, "add_dll_directory") and os.path.isdir(msys):
            try: os.add_dll_directory(msys)
            except OSError: pass
        os.environ["PATH"] = msys + os.pathsep + os.environ.get("PATH", "")

    tried = []
    for p in _candidate_paths():
        tried.append(p)
        if os.path.isfile(p):
            return ctypes.CDLL(p)
    raise FileNotFoundError(
        "libpq_core not found. Build trước (`cmake --build build`). Searched:\n  "
        + "\n  ".join(tried))


lib = load_lib()
lib.pq_last_error.restype = c_char_p

for fn in ("pq_mldsa_keygen", "pq_mldsa_sign", "pq_mldsa_verify",
           "pq_mlkem_keygen", "pq_mlkem_encaps", "pq_mlkem_decaps"):
    f = getattr(lib, fn)
    f.argtypes = [c_char_p, c_char_p, c_char_p]; f.restype = c_int

# pq_cert_verify chỉ nhận 2 tham số (ca_pub_path, cert_path)
lib.pq_cert_verify.argtypes = [c_char_p, c_char_p]
lib.pq_cert_verify.restype  = c_int

lib.pq_cert_make.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
lib.pq_cert_make.restype  = c_int


def _b(s: str) -> bytes: return s.encode("utf-8")
def _err() -> str: return lib.pq_last_error().decode("utf-8", errors="replace")


# -----------------------------------------------------------------------
# UI helpers
# -----------------------------------------------------------------------
class _FilePicker(QWidget):
    def __init__(self, save: bool = False, parent=None):
        super().__init__(parent)
        self.save = save
        self.edit = QLineEdit()
        btn = QPushButton("…"); btn.setFixedWidth(28); btn.clicked.connect(self._browse)
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0)
        lay.addWidget(self.edit, 1); lay.addWidget(btn)
    def _browse(self):
        p, _ = (QFileDialog.getSaveFileName(self, "Save") if self.save
                else QFileDialog.getOpenFileName(self, "Open"))
        if p: self.edit.setText(p)
    def text(self) -> str: return self.edit.text().strip()


# -----------------------------------------------------------------------
# Tabs
# -----------------------------------------------------------------------
class MLDSATab(QWidget):
    def __init__(self):
        super().__init__()
        self.mode = QComboBox(); self.mode.addItems(["Keygen", "Sign", "Verify"])
        self.algo = QComboBox(); self.algo.addItems(["mldsa-44", "mldsa-65", "mldsa-87"])
        self.priv = _FilePicker(save=True);  self.priv.edit.setText("priv.pem")
        self.pub  = _FilePicker(save=True);  self.pub.edit.setText("pub.pem")
        self.in_  = _FilePicker()
        self.sig  = _FilePicker(save=True)
        run = QPushButton("Run"); run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Mode:",        self.mode)
        form.addRow("Algorithm:",   self.algo)
        form.addRow("Private key:", self.priv)
        form.addRow("Public key:",  self.pub)
        form.addRow("Input file:",  self.in_)
        form.addRow("Sig file:",    self.sig)

        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        m = self.mode.currentText()
        if m == "Keygen":
            rc = lib.pq_mldsa_keygen(_b(self.algo.currentText()),
                                     _b(self.priv.text()), _b(self.pub.text()))
        elif m == "Sign":
            rc = lib.pq_mldsa_sign(_b(self.priv.text()),
                                   _b(self.in_.text()), _b(self.sig.text()))
        else:
            rc = lib.pq_mldsa_verify(_b(self.pub.text()),
                                     _b(self.in_.text()), _b(self.sig.text()))
        self.log.append(f"{m} rc={rc}: " + (_err() or "OK"))


class MLKEMTab(QWidget):
    def __init__(self):
        super().__init__()
        self.mode = QComboBox(); self.mode.addItems(["Keygen", "Encaps", "Decaps"])
        self.algo = QComboBox(); self.algo.addItems(["mlkem-512", "mlkem-768", "mlkem-1024"])
        self.priv = _FilePicker(save=True); self.priv.edit.setText("priv.pem")
        self.pub  = _FilePicker(save=True); self.pub.edit.setText("pub.pem")
        self.ct   = _FilePicker(save=True); self.ct.edit.setText("ct.bin")
        self.ss   = _FilePicker(save=True); self.ss.edit.setText("ss.bin")
        run = QPushButton("Run"); run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Mode:",          self.mode)
        form.addRow("Algorithm:",     self.algo)
        form.addRow("Private key:",   self.priv)
        form.addRow("Public key:",    self.pub)
        form.addRow("Ciphertext:",    self.ct)
        form.addRow("Shared secret:", self.ss)

        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        m = self.mode.currentText()
        if m == "Keygen":
            rc = lib.pq_mlkem_keygen(_b(self.algo.currentText()),
                                     _b(self.priv.text()), _b(self.pub.text()))
        elif m == "Encaps":
            rc = lib.pq_mlkem_encaps(_b(self.pub.text()),
                                     _b(self.ct.text()), _b(self.ss.text()))
        else:
            rc = lib.pq_mlkem_decaps(_b(self.priv.text()),
                                     _b(self.ct.text()), _b(self.ss.text()))
        self.log.append(f"{m} rc={rc}: " + (_err() or "OK"))


class CertTab(QWidget):
    def __init__(self):
        super().__init__()
        self.mode = QComboBox(); self.mode.addItems(["Make", "Verify"])
        self.algo = QComboBox(); self.algo.addItems(["mldsa-44", "mldsa-65", "mldsa-87"])
        self.ca_priv = _FilePicker();           self.ca_priv.edit.setText("ca_priv.pem")
        self.ca_pub  = _FilePicker();           self.ca_pub.edit.setText("ca_pub.pem")
        self.subj_pub = _FilePicker();          self.subj_pub.edit.setText("sub_pub.pem")
        self.subject = QLineEdit("UIT-Student-22520xxx")
        self.cert = _FilePicker(save=True);     self.cert.edit.setText("cert.json")
        run = QPushButton("Run"); run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Mode:",            self.mode)
        form.addRow("Algorithm:",       self.algo)
        form.addRow("CA private key:",  self.ca_priv)
        form.addRow("CA public key:",   self.ca_pub)
        form.addRow("Subject pub key:", self.subj_pub)
        form.addRow("Subject name:",    self.subject)
        form.addRow("Cert file:",       self.cert)

        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        m = self.mode.currentText()
        if m == "Make":
            rc = lib.pq_cert_make(_b(self.algo.currentText()),
                                  _b(self.ca_priv.text()),
                                  _b(self.subj_pub.text()),
                                  _b(self.subject.text()),
                                  _b(self.cert.text()))
        else:
            rc = lib.pq_cert_verify(_b(self.ca_pub.text()), _b(self.cert.text()))
        self.log.append(f"Cert {m} rc={rc}: " + (_err() or "OK"))


class KatTab(QWidget):
    """KAT chạy qua CLI binary (kết quả 8/8 hoặc 6/6 đã in trong CLI)."""
    def __init__(self):
        super().__init__()
        self.algo_dsa = QComboBox(); self.algo_dsa.addItems(["mldsa-44", "mldsa-65"])
        self.algo_kem = QComboBox(); self.algo_kem.addItems(["mlkem-512", "mlkem-768", "mlkem-1024"])
        b1 = QPushButton("Run MLDSA KAT"); b1.clicked.connect(self.run_dsa)
        b2 = QPushButton("Run MLKEM KAT"); b2.clicked.connect(self.run_kem)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("ML-DSA algo:", self.algo_dsa)
        form.addRow("",             b1)
        form.addRow("ML-KEM algo:", self.algo_kem)
        form.addRow("",             b2)
        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(self.log, 1)

    def _run(self, exe: str, algo: str):
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        binp = os.path.join(here, "..", "bin",
                            "windows" if platform.system() == "Windows" else "linux",
                            exe + (".exe" if platform.system() == "Windows" else ""))
        if not os.path.isfile(binp):
            self.log.append(f"FAIL: {binp} not found. Build trước.")
            return
        try:
            r = subprocess.run([binp, "kat", "--algo", algo],
                               capture_output=True, text=True, timeout=120)
            self.log.append(r.stdout + (r.stderr if r.stderr else ""))
        except Exception as e:
            self.log.append(f"FAIL: {e}")

    def run_dsa(self): self._run("MLDSA", self.algo_dsa.currentText())
    def run_kem(self): self._run("MLKEM", self.algo_kem.currentText())


# -----------------------------------------------------------------------
class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lab 6 — Post-Quantum (ML-DSA + ML-KEM)")
        self.resize(740, 540)
        tabs = QTabWidget()
        tabs.addTab(MLDSATab(), "ML-DSA")
        tabs.addTab(MLKEMTab(), "ML-KEM")
        tabs.addTab(CertTab(),  "Certificate")
        tabs.addTab(KatTab(),   "KAT")
        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    w = Main(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
