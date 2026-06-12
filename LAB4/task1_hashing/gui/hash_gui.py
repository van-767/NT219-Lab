"""
PySide6 GUI cho Lab 4 Task 1 — gọi libhash_core.dll qua ctypes.
"""
from __future__ import annotations

import ctypes
import os
import platform
import sys
from ctypes import c_char_p, c_int, c_double, create_string_buffer, POINTER

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLineEdit, QMainWindow, QPushButton, QSpinBox, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)


# ── load DLL ──────────────────────────────────────────────────────────
def _candidates() -> list[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    subdir = ("windows" if platform.system() == "Windows"
              else "macos" if platform.system() == "Darwin" else "linux")
    names_win = ["libhash_core.dll", "hash_core.dll"]
    names_lin = ["libhash_core.so",  "hash_core.so"]
    names_mac = ["libhash_core.dylib"]
    names = (names_win if platform.system() == "Windows"
             else names_mac if platform.system() == "Darwin" else names_lin)
    roots = [
        here, os.path.join(here, ".."),
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
    for p in _candidates():
        tried.append(p)
        if os.path.isfile(p): return ctypes.CDLL(p)
    raise FileNotFoundError("libhash_core not found. Build trước.\n  " + "\n  ".join(tried))


lib = load_lib()
lib.hash_last_error.restype = c_char_p

lib.hash_text.argtypes = [c_char_p, c_char_p, c_int, c_int, c_char_p, c_int]
lib.hash_text.restype  = c_int

lib.hash_file.argtypes = [c_char_p, c_char_p, c_int, c_char_p, c_int]
lib.hash_file.restype  = c_int

lib.hash_run_kat.argtypes = [c_char_p, POINTER(c_int), POINTER(c_int)]
lib.hash_run_kat.restype  = c_int

lib.hash_bench.argtypes = [c_char_p, c_int, c_int, c_int, c_int] + [POINTER(c_double)] * 6
lib.hash_bench.restype  = c_int


def _b(s: str) -> bytes: return s.encode("utf-8")
def _err() -> str: return lib.hash_last_error().decode("utf-8", errors="replace")


# ── UI helper ─────────────────────────────────────────────────────────
class _FilePicker(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.edit = QLineEdit()
        btn = QPushButton("…"); btn.setFixedWidth(28); btn.clicked.connect(self._browse)
        lay = QHBoxLayout(self); lay.setContentsMargins(0,0,0,0)
        lay.addWidget(self.edit, 1); lay.addWidget(btn)
    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "Choose file")
        if p: self.edit.setText(p)
    def text(self) -> str: return self.edit.text().strip()


ALGOS = ["sha224","sha256","sha384","sha512",
         "sha3-224","sha3-256","sha3-384","sha3-512",
         "shake128","shake256"]


# ── Tabs ──────────────────────────────────────────────────────────────
class DigestTab(QWidget):
    def __init__(self):
        super().__init__()
        self.algo = QComboBox(); self.algo.addItems(ALGOS); self.algo.setCurrentText("sha256")
        self.text = QLineEdit()
        self.file = _FilePicker()
        self.outlen = QSpinBox(); self.outlen.setRange(1, 4096); self.outlen.setValue(32)
        b1 = QPushButton("Hash text");    b1.clicked.connect(self.do_text)
        b2 = QPushButton("Hash file");    b2.clicked.connect(self.do_file)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        form = QFormLayout()
        form.addRow("Algorithm:",   self.algo)
        form.addRow("Text:",        self.text)
        form.addRow("File:",        self.file)
        form.addRow("XOF outlen:",  self.outlen)
        row = QHBoxLayout(); row.addWidget(b1); row.addWidget(b2)
        lay = QVBoxLayout(self); lay.addLayout(form); lay.addLayout(row); lay.addWidget(self.log, 1)

    def do_text(self):
        buf = create_string_buffer(self.outlen.value() * 2 + 32)
        rc = lib.hash_text(_b(self.algo.currentText()), _b(self.text.text()),
                           len(self.text.text().encode("utf-8")),
                           self.outlen.value(), buf, len(buf))
        if rc == 0: self.log.append(f"{self.algo.currentText()}({self.text.text()!r}) = {buf.value.decode()}")
        else: self.log.append(f"ERROR: {_err()}")

    def do_file(self):
        if not self.file.text():
            self.log.append("ERROR: chọn file trước"); return
        buf = create_string_buffer(self.outlen.value() * 2 + 32)
        rc = lib.hash_file(_b(self.algo.currentText()), _b(self.file.text()),
                           self.outlen.value(), buf, len(buf))
        if rc == 0: self.log.append(f"{self.algo.currentText()}({self.file.text()}) = {buf.value.decode()}")
        else: self.log.append(f"ERROR: {_err()}")


class KatTab(QWidget):
    def __init__(self):
        super().__init__()
        self.path = _FilePicker(); self.path.edit.setText("tests/kat_vectors.json")
        b = QPushButton("Run KAT"); b.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        form = QFormLayout(); form.addRow("Vectors JSON:", self.path)
        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(b); lay.addWidget(self.log, 1)

    def run(self):
        passed = c_int(0); failed = c_int(0)
        rc = lib.hash_run_kat(_b(self.path.text()), ctypes.byref(passed), ctypes.byref(failed))
        if rc != 0 and passed.value == 0 and failed.value == 0:
            self.log.append(f"FAIL: {_err()}"); return
        self.log.append(f"Passed: {passed.value}    Failed: {failed.value}")


class BenchTab(QWidget):
    def __init__(self):
        super().__init__()
        self.algo = QComboBox(); self.algo.addItems(ALGOS); self.algo.setCurrentText("sha256")
        self.size = QSpinBox(); self.size.setRange(1, 1_073_741_824); self.size.setValue(1024)
        self.n    = QSpinBox(); self.n.setRange(5, 1000);    self.n.setValue(30)
        self.blk  = QSpinBox(); self.blk.setRange(1, 100000); self.blk.setValue(1000)
        self.outlen = QSpinBox(); self.outlen.setRange(1, 4096); self.outlen.setValue(32)
        b = QPushButton("Run benchmark"); b.clicked.connect(self.run)
        self.log = QTextEdit(); self.log.setReadOnly(True)
        form = QFormLayout()
        form.addRow("Algorithm:",    self.algo)
        form.addRow("Msg size (B):", self.size)
        form.addRow("N blocks:",     self.n)
        form.addRow("Block size:",   self.blk)
        form.addRow("XOF outlen:",   self.outlen)
        lay = QVBoxLayout(self); lay.addLayout(form); lay.addWidget(b); lay.addWidget(self.log, 1)

    def run(self):
        m = c_double(); med = c_double(); s = c_double()
        lo = c_double(); hi = c_double(); tp = c_double()
        rc = lib.hash_bench(_b(self.algo.currentText()), self.size.value(),
                            self.n.value(), self.blk.value(), self.outlen.value(),
                            *map(ctypes.byref, (m, med, s, lo, hi, tp)))
        if rc != 0: self.log.append(f"FAIL: {_err()}"); return
        self.log.append(
            f"{self.algo.currentText():>10} {self.size.value():>9}B  "
            f"mean={m.value:.3f}μs  median={med.value:.3f}μs  "
            f"sd={s.value:.3f}  95%CI=[{lo.value:.3f}, {hi.value:.3f}]μs  "
            f"≈ {tp.value:.1f} MiB/s")


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Lab 4 Task 1 — Hashing (SHA-2 / SHA-3 / SHAKE)")
        self.resize(720, 520)
        tabs = QTabWidget()
        tabs.addTab(DigestTab(), "Digest")
        tabs.addTab(KatTab(),    "KAT")
        tabs.addTab(BenchTab(),  "Benchmark")
        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    w = Main(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
