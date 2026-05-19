"""
PySide6 GUI for Lab 3 — calls the compiled rsa_core shared library via ctypes.
No cryptographic logic lives here: every primitive comes from the C ABI in
src/c_api.h, satisfying the "GUI must call the same compiled library" rule.

Install:    pip install PySide6
Run:        python rsa_gui.py
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from ctypes import c_char_p, c_int, c_double, c_ulonglong, POINTER

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPushButton, QSpinBox,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget, QComboBox,
)

# ---------------------------------------------------------------------------
# Locate and load rsa_core shared library
# ---------------------------------------------------------------------------
def _candidate_paths() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    names_win = ["rsa_core.dll", "librsa_core.dll"]
    names_lin = ["librsa_core.so",  "rsa_core.so"]
    names_mac = ["librsa_core.dylib", "rsa_core.dylib"]
    names = (names_win if platform.system() == "Windows"
             else names_mac if platform.system() == "Darwin"
             else names_lin)
    subdir = ("windows" if platform.system() == "Windows"
              else "macos" if platform.system() == "Darwin"
              else "linux")
    roots = [
        here,
        os.path.join(here, ".."),
        os.path.join(here, "..", "bin", subdir),    # CMake default output
        os.path.join(here, "..", "build"),          # legacy
        os.path.join(here, "..", "build", "Release"),
        os.path.join(here, "..", "build", "Debug"),
        os.path.join(here, "..", "out", "build"),
    ]
    return [os.path.join(r, n) for r in roots for n in names]


def load_lib() -> ctypes.CDLL:
    # On Windows, our DLL was built with MinGW so it depends on libstdc++-6.dll
    # and libgcc_s_seh-1.dll from MSYS2. Tell Windows where to find them.
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
        "rsa_core shared library not found. Build the project first "
        "(`cmake --build build`). Searched:\n  " + "\n  ".join(tried))


lib = load_lib()

# Bind signatures
lib.rsa_last_error.restype = c_char_p
lib.rsa_keygen.argtypes  = [c_int, c_char_p, c_char_p];               lib.rsa_keygen.restype  = c_int
lib.rsa_encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p];  lib.rsa_encrypt.restype = c_int
lib.rsa_decrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p];  lib.rsa_decrypt.restype = c_int
lib.rsa_run_kat.argtypes = [c_char_p, POINTER(c_int), POINTER(c_int)]
lib.rsa_run_kat.restype  = c_int
for fn in ("rsa_bench_keygen", "rsa_bench_oaep_enc", "rsa_bench_oaep_dec"):
    f = getattr(lib, fn)
    f.argtypes = [c_int, c_int] + [POINTER(c_double)] * 5
    f.restype  = c_int
lib.rsa_bench_aes_gcm.argtypes = [c_int, c_ulonglong] + [POINTER(c_double)] * 5
lib.rsa_bench_aes_gcm.restype  = c_int


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _err() -> str:
    return lib.rsa_last_error().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
class _FilePicker(QWidget):
    def __init__(self, save: bool = False, parent=None):
        super().__init__(parent)
        self.save = save
        self.edit = QLineEdit()
        btn = QPushButton("…")
        btn.setFixedWidth(28)
        btn.clicked.connect(self._browse)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.edit, 1)
        lay.addWidget(btn)

    def _browse(self):
        if self.save:
            p, _ = QFileDialog.getSaveFileName(self, "Choose file")
        else:
            p, _ = QFileDialog.getOpenFileName(self, "Choose file")
        if p:
            self.edit.setText(p)

    def text(self) -> str:
        return self.edit.text().strip()


# ---------------------------------------------------------------------------
# Tab pages
# ---------------------------------------------------------------------------
class KeygenTab(QWidget):
    def __init__(self):
        super().__init__()
        self.bits = QSpinBox(); self.bits.setRange(3072, 8192)
        self.bits.setSingleStep(1024); self.bits.setValue(3072)
        self.priv = _FilePicker(save=True); self.priv.edit.setText("priv.pem")
        self.pub  = _FilePicker(save=True); self.pub.edit.setText("pub.pem")
        run = QPushButton("Generate")
        run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Bits (>=3072):", self.bits)
        form.addRow("Private PEM:",   self.priv)
        form.addRow("Public PEM:",    self.pub)

        lay = QVBoxLayout(self)
        lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        rc = lib.rsa_keygen(self.bits.value(), _b(self.priv.text()), _b(self.pub.text()))
        self.log.append(f"keygen rc={rc}: " + (_err() or "OK"))


class CryptTab(QWidget):
    def __init__(self):
        super().__init__()
        self.mode = QComboBox(); self.mode.addItems(["Encrypt", "Decrypt"])
        self.key  = _FilePicker(); self.key.edit.setText("pub.pem")
        self.in_  = _FilePicker()
        self.out  = _FilePicker(save=True)
        self.label = QLineEdit()
        run = QPushButton("Run")
        run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Mode:",   self.mode)
        form.addRow("Key PEM:", self.key)
        form.addRow("Input:",  self.in_)
        form.addRow("Output:", self.out)
        form.addRow("Label:",  self.label)

        lay = QVBoxLayout(self)
        lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        if self.mode.currentText() == "Encrypt":
            rc = lib.rsa_encrypt(_b(self.key.text()), _b(self.in_.text()),
                                 _b(self.out.text()), _b(self.label.text()))
        else:
            rc = lib.rsa_decrypt(_b(self.key.text()), _b(self.in_.text()),
                                 _b(self.out.text()), _b(self.label.text()))
        self.log.append(f"{self.mode.currentText()} rc={rc}: " + (_err() or "OK"))


class KatTab(QWidget):
    def __init__(self):
        super().__init__()
        self.path = _FilePicker(); self.path.edit.setText("tests/kat_vectors.json")
        run = QPushButton("Run KAT")
        run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        form = QFormLayout(); form.addRow("Vectors JSON:", self.path)
        lay = QVBoxLayout(self)
        lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        passed = c_int(0); failed = c_int(0)
        rc = lib.rsa_run_kat(_b(self.path.text()), ctypes.byref(passed), ctypes.byref(failed))
        if rc != 0 and not (passed.value or failed.value):
            self.log.append(f"FAIL: {_err()}"); return
        self.log.append(f"Passed: {passed.value}    Failed: {failed.value}")
        if failed.value:
            self.log.append("Note: detailed PASS/FAIL lines are printed on stdout when "
                            "this GUI is launched from a console.")


class BenchTab(QWidget):
    def __init__(self):
        super().__init__()
        self.op = QComboBox(); self.op.addItems(["keygen", "oaep_enc", "oaep_dec", "aes_gcm"])
        self.bits = QSpinBox(); self.bits.setRange(3072, 8192); self.bits.setValue(3072)
        self.n    = QSpinBox(); self.n.setRange(5, 1000); self.n.setValue(30)
        self.size = QSpinBox(); self.size.setRange(1, 100_000_000); self.size.setValue(1024)
        run = QPushButton("Run benchmark")
        run.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Operation:",       self.op)
        form.addRow("RSA bits:",         self.bits)
        form.addRow("Iterations:",       self.n)
        form.addRow("AES msg size (B):", self.size)
        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(run); lay.addWidget(self.log, 1)

    def run(self):
        mean = c_double(); median = c_double(); sd = c_double()
        lo = c_double(); hi = c_double()
        op = self.op.currentText()
        if op == "keygen":
            rc = lib.rsa_bench_keygen(self.bits.value(), self.n.value(),
                                      *map(ctypes.byref, (mean, median, sd, lo, hi)))
        elif op == "oaep_enc":
            rc = lib.rsa_bench_oaep_enc(self.bits.value(), self.n.value(),
                                        *map(ctypes.byref, (mean, median, sd, lo, hi)))
        elif op == "oaep_dec":
            rc = lib.rsa_bench_oaep_dec(self.bits.value(), self.n.value(),
                                        *map(ctypes.byref, (mean, median, sd, lo, hi)))
        else:
            rc = lib.rsa_bench_aes_gcm(self.n.value(), self.size.value(),
                                       *map(ctypes.byref, (mean, median, sd, lo, hi)))
        if rc != 0:
            self.log.append("FAIL: " + _err()); return
        self.log.append(
            f"{op:>10}  n={self.n.value():<4}  "
            f"mean={mean.value:.3f}  median={median.value:.3f}  "
            f"sd={sd.value:.3f}  95%CI=[{lo.value:.3f}, {hi.value:.3f}] ms")


# ---------------------------------------------------------------------------
class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lab 3 — RSA-OAEP + Hybrid (Crypto++)")
        self.resize(720, 520)
        tabs = QTabWidget()
        tabs.addTab(KeygenTab(), "Keygen")
        tabs.addTab(CryptTab(),  "Encrypt / Decrypt")
        tabs.addTab(KatTab(),    "KAT")
        tabs.addTab(BenchTab(),  "Benchmark")
        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    w = Main(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
