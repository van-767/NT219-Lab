"""Lab 5 GUI — ECDSA + RSA-PSS qua libsig_core (ctypes).

Phụ thuộc: PySide6.  pip install PySide6

Chạy: python gui/sig_gui.py
"""
from __future__ import annotations

import ctypes as C
import os
import sys
import platform
from pathlib import Path

from PySide6 import QtCore, QtWidgets, QtGui


# ── Locate & load shared library ─────────────────────────────────────────
def _candidate_paths() -> list[Path]:
    here = Path(__file__).resolve().parent
    root = here.parent
    if platform.system() == "Windows":
        names = ["libsig_core.dll", "sig_core.dll"]
        subs  = ["bin/windows", "build", "build/Release", "."]
    elif platform.system() == "Darwin":
        names = ["libsig_core.dylib"]
        subs  = ["bin/macos", "build", "."]
    else:
        names = ["libsig_core.so"]
        subs  = ["bin/linux", "build", "."]
    out: list[Path] = []
    for s in subs:
        for n in names:
            out += [here / n, root / s / n, Path.cwd() / s / n]
    return out


def _add_windows_dll_dirs() -> list[str]:
    """Python 3.8+: PATH không còn được dùng để dò DLL dependency.
    Phải gọi os.add_dll_directory() cho MinGW runtime + OpenSSL trước khi load.
    """
    if platform.system() != "Windows" or not hasattr(os, "add_dll_directory"):
        return []
    candidates = [
        os.environ.get("MINGW_PREFIX", ""),
        r"C:\msys64\mingw64\bin",
        r"C:\msys64\ucrt64\bin",
        r"C:\msys64\clang64\bin",
        r"C:\Program Files\OpenSSL-Win64\bin",
        r"C:\Program Files\OpenSSL\bin",
        r"C:\OpenSSL-Win64\bin",
    ]
    # MINGW_PREFIX là root → thêm /bin
    if candidates[0] and not candidates[0].lower().endswith("bin"):
        candidates[0] = str(Path(candidates[0]) / "bin")
    added: list[str] = []
    for d in candidates:
        if d and Path(d).is_dir():
            try:
                os.add_dll_directory(d)
                added.append(d)
            except (OSError, FileNotFoundError):
                pass
    return added


def _load_lib() -> C.CDLL:
    extra_dirs = _add_windows_dll_dirs()
    tried: list[str] = []
    for p in _candidate_paths():
        if p.exists():
            try:
                return C.CDLL(str(p))
            except OSError as e:
                tried.append(f"{p}: {e}")
    msg = "Không tìm thấy / không load được libsig_core."
    if extra_dirs:
        msg += "\nĐã thêm DLL dirs: " + ", ".join(extra_dirs)
    msg += "\n\nĐã thử các path:\n" + "\n".join(str(p) for p in _candidate_paths())
    if tried:
        msg += "\n\nLỗi cụ thể:\n" + "\n".join(tried)
        msg += ("\n\nGợi ý: nếu báo 'one of its dependencies', mở bin\\windows\\libsig_core.dll "
                "bằng `dumpbin /dependents` hoặc 'Dependencies' GUI để xem DLL nào thiếu.\n"
                "Thường là libgcc_s_seh-1.dll / libstdc++-6.dll / libwinpthread-1.dll "
                "(MinGW) hoặc libcrypto-3-x64.dll (OpenSSL). Thêm thư mục chứa chúng vào "
                "MINGW_PREFIX hoặc copy cạnh libsig_core.dll.")
    raise SystemExit(msg)


LIB = _load_lib()

LIB.sig_last_error.restype = C.c_char_p

LIB.sig_ecdsa_keygen.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p]
LIB.sig_ecdsa_keygen.restype  = C.c_int
LIB.sig_ecdsa_sign.argtypes   = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p,
                                 C.c_char_p, C.POINTER(C.c_size_t)]
LIB.sig_ecdsa_sign.restype    = C.c_int
LIB.sig_ecdsa_verify.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p]
LIB.sig_ecdsa_verify.restype  = C.c_int

LIB.sig_rsapss_keygen.argtypes = [C.c_int, C.c_char_p, C.c_char_p, C.c_char_p]
LIB.sig_rsapss_keygen.restype  = C.c_int
LIB.sig_rsapss_sign.argtypes   = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p,
                                  C.c_int, C.c_char_p, C.POINTER(C.c_size_t)]
LIB.sig_rsapss_sign.restype    = C.c_int
LIB.sig_rsapss_verify.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_char_p,
                                  C.c_int, C.c_char_p]
LIB.sig_rsapss_verify.restype  = C.c_int


def _b(s: str | None) -> bytes | None:
    return s.encode("utf-8") if s is not None else None


def _last_err() -> str:
    e = LIB.sig_last_error()
    return e.decode("utf-8", errors="replace") if e else ""


# ── Helpers UI ───────────────────────────────────────────────────────────
def _pick_save(parent: QtWidgets.QWidget, line: QtWidgets.QLineEdit,
               caption: str, filt: str = "All Files (*)") -> None:
    p, _ = QtWidgets.QFileDialog.getSaveFileName(parent, caption, line.text(), filt)
    if p: line.setText(p)


def _pick_open(parent: QtWidgets.QWidget, line: QtWidgets.QLineEdit,
               caption: str, filt: str = "All Files (*)") -> None:
    p, _ = QtWidgets.QFileDialog.getOpenFileName(parent, caption, line.text(), filt)
    if p: line.setText(p)


def _row(label: str, w: QtWidgets.QWidget) -> QtWidgets.QHBoxLayout:
    h = QtWidgets.QHBoxLayout()
    lab = QtWidgets.QLabel(label); lab.setMinimumWidth(110)
    h.addWidget(lab); h.addWidget(w, 1)
    return h


def _file_row(parent: QtWidgets.QWidget, label: str, save: bool,
              filt: str = "All Files (*)") -> tuple[QtWidgets.QHBoxLayout, QtWidgets.QLineEdit]:
    le = QtWidgets.QLineEdit()
    btn = QtWidgets.QPushButton("…"); btn.setFixedWidth(32)
    if save:
        btn.clicked.connect(lambda: _pick_save(parent, le, label, filt))
    else:
        btn.clicked.connect(lambda: _pick_open(parent, le, label, filt))
    h = QtWidgets.QHBoxLayout()
    lab = QtWidgets.QLabel(label); lab.setMinimumWidth(110)
    h.addWidget(lab); h.addWidget(le, 1); h.addWidget(btn)
    return h, le


# ── ECDSA tab ────────────────────────────────────────────────────────────
class EcdsaTab(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        L = QtWidgets.QVBoxLayout(self)

        gb_k = QtWidgets.QGroupBox("Keygen")
        kl = QtWidgets.QVBoxLayout(gb_k)
        self.cb_curve = QtWidgets.QComboBox(); self.cb_curve.addItems(["ecdsa-p256", "ecdsa-p384"])
        self.cb_fmt   = QtWidgets.QComboBox(); self.cb_fmt.addItems(["pem", "der"])
        kl.addLayout(_row("Curve",  self.cb_curve))
        kl.addLayout(_row("Format", self.cb_fmt))
        r, self.k_priv = _file_row(self, "Priv out", True); kl.addLayout(r)
        r, self.k_pub  = _file_row(self, "Pub out",  True); kl.addLayout(r)
        b_kg = QtWidgets.QPushButton("Generate keypair"); kl.addWidget(b_kg)
        b_kg.clicked.connect(self.do_keygen)
        L.addWidget(gb_k)

        gb_s = QtWidgets.QGroupBox("Sign")
        sl = QtWidgets.QVBoxLayout(gb_s)
        r, self.s_priv = _file_row(self, "Priv key", False, "Keys (*.pem *.der *.key);;All (*)")
        sl.addLayout(r)
        r, self.s_in   = _file_row(self, "Message",  False); sl.addLayout(r)
        r, self.s_out  = _file_row(self, "Sig out",  True,  "Sig (*.sig);;All (*)"); sl.addLayout(r)
        self.cb_s_hash = QtWidgets.QComboBox(); self.cb_s_hash.addItems(["", "sha256", "sha384", "sha512"])
        self.cb_s_enc  = QtWidgets.QComboBox(); self.cb_s_enc.addItems(["der", "raw", "base64"])
        sl.addLayout(_row("Hash",   self.cb_s_hash))
        sl.addLayout(_row("Encode", self.cb_s_enc))
        b_sg = QtWidgets.QPushButton("Sign"); sl.addWidget(b_sg)
        b_sg.clicked.connect(self.do_sign)
        L.addWidget(gb_s)

        gb_v = QtWidgets.QGroupBox("Verify")
        vl = QtWidgets.QVBoxLayout(gb_v)
        r, self.v_pub = _file_row(self, "Pub key", False, "Keys (*.pem *.der *.key);;All (*)")
        vl.addLayout(r)
        r, self.v_in  = _file_row(self, "Message", False); vl.addLayout(r)
        r, self.v_sig = _file_row(self, "Sig",     False, "Sig (*.sig);;All (*)"); vl.addLayout(r)
        self.cb_v_hash = QtWidgets.QComboBox(); self.cb_v_hash.addItems(["", "sha256", "sha384", "sha512"])
        self.cb_v_enc  = QtWidgets.QComboBox(); self.cb_v_enc.addItems(["der", "raw", "base64"])
        vl.addLayout(_row("Hash",   self.cb_v_hash))
        vl.addLayout(_row("Encode", self.cb_v_enc))
        b_vr = QtWidgets.QPushButton("Verify"); vl.addWidget(b_vr)
        b_vr.clicked.connect(self.do_verify)
        L.addWidget(gb_v)

        L.addStretch(1)

    def _info(self, ok: bool, msg: str) -> None:
        (QtWidgets.QMessageBox.information if ok else QtWidgets.QMessageBox.warning)(
            self, "ECDSA", msg)

    def do_keygen(self) -> None:
        r = LIB.sig_ecdsa_keygen(_b(self.cb_curve.currentText()),
                                 _b(self.k_priv.text()), _b(self.k_pub.text()),
                                 _b(self.cb_fmt.currentText()))
        self._info(r == 0, f"Keypair created\nPriv: {self.k_priv.text()}\nPub : {self.k_pub.text()}"
                          if r == 0 else f"Keygen failed: {_last_err()}")

    def do_sign(self) -> None:
        n = C.c_size_t(0)
        r = LIB.sig_ecdsa_sign(_b(self.s_priv.text()), _b(self.s_in.text()),
                               _b(self.s_out.text()), _b(self.cb_s_hash.currentText()),
                               _b(self.cb_s_enc.currentText()), C.byref(n))
        self._info(r == 0, f"Signed ({n.value} bytes) → {self.s_out.text()}"
                           if r == 0 else f"Sign failed: {_last_err()}")

    def do_verify(self) -> None:
        r = LIB.sig_ecdsa_verify(_b(self.v_pub.text()), _b(self.v_in.text()),
                                 _b(self.v_sig.text()), _b(self.cb_v_hash.currentText()),
                                 _b(self.cb_v_enc.currentText()))
        if r == 0:   self._info(True,  "Signature VALID")
        elif r == 1: self._info(False, "Signature INVALID")
        else:        self._info(False, f"Verify error: {_last_err()}")


# ── RSA-PSS tab ──────────────────────────────────────────────────────────
class RsaPssTab(QtWidgets.QWidget):
    def __init__(self) -> None:
        super().__init__()
        L = QtWidgets.QVBoxLayout(self)

        gb_k = QtWidgets.QGroupBox("Keygen")
        kl = QtWidgets.QVBoxLayout(gb_k)
        self.sp_bits = QtWidgets.QSpinBox(); self.sp_bits.setRange(3072, 8192); self.sp_bits.setValue(3072); self.sp_bits.setSingleStep(1024)
        self.cb_fmt  = QtWidgets.QComboBox(); self.cb_fmt.addItems(["pem", "der"])
        kl.addLayout(_row("Bits",   self.sp_bits))
        kl.addLayout(_row("Format", self.cb_fmt))
        r, self.k_priv = _file_row(self, "Priv out", True); kl.addLayout(r)
        r, self.k_pub  = _file_row(self, "Pub out",  True); kl.addLayout(r)
        b_kg = QtWidgets.QPushButton("Generate keypair"); kl.addWidget(b_kg)
        b_kg.clicked.connect(self.do_keygen)
        L.addWidget(gb_k)

        gb_s = QtWidgets.QGroupBox("Sign")
        sl = QtWidgets.QVBoxLayout(gb_s)
        r, self.s_priv = _file_row(self, "Priv key", False); sl.addLayout(r)
        r, self.s_in   = _file_row(self, "Message",  False); sl.addLayout(r)
        r, self.s_out  = _file_row(self, "Sig out",  True);  sl.addLayout(r)
        self.cb_s_hash = QtWidgets.QComboBox(); self.cb_s_hash.addItems(["sha256", "sha384", "sha512"])
        self.cb_s_enc  = QtWidgets.QComboBox(); self.cb_s_enc.addItems(["raw", "base64"])
        self.sp_s_salt = QtWidgets.QSpinBox(); self.sp_s_salt.setRange(-1, 1024); self.sp_s_salt.setValue(-1)
        self.sp_s_salt.setToolTip("-1 = hashLen (mặc định/đúng spec); 0 = không salt")
        sl.addLayout(_row("Hash",     self.cb_s_hash))
        sl.addLayout(_row("Salt-len", self.sp_s_salt))
        sl.addLayout(_row("Encode",   self.cb_s_enc))
        b_sg = QtWidgets.QPushButton("Sign"); sl.addWidget(b_sg)
        b_sg.clicked.connect(self.do_sign)
        L.addWidget(gb_s)

        gb_v = QtWidgets.QGroupBox("Verify")
        vl = QtWidgets.QVBoxLayout(gb_v)
        r, self.v_pub = _file_row(self, "Pub key", False); vl.addLayout(r)
        r, self.v_in  = _file_row(self, "Message", False); vl.addLayout(r)
        r, self.v_sig = _file_row(self, "Sig",     False); vl.addLayout(r)
        self.cb_v_hash = QtWidgets.QComboBox(); self.cb_v_hash.addItems(["sha256", "sha384", "sha512"])
        self.cb_v_enc  = QtWidgets.QComboBox(); self.cb_v_enc.addItems(["raw", "base64"])
        self.sp_v_salt = QtWidgets.QSpinBox(); self.sp_v_salt.setRange(-1, 1024); self.sp_v_salt.setValue(-1)
        vl.addLayout(_row("Hash",     self.cb_v_hash))
        vl.addLayout(_row("Salt-len", self.sp_v_salt))
        vl.addLayout(_row("Encode",   self.cb_v_enc))
        b_vr = QtWidgets.QPushButton("Verify"); vl.addWidget(b_vr)
        b_vr.clicked.connect(self.do_verify)
        L.addWidget(gb_v)

        L.addStretch(1)

    def _info(self, ok: bool, msg: str) -> None:
        (QtWidgets.QMessageBox.information if ok else QtWidgets.QMessageBox.warning)(
            self, "RSA-PSS", msg)

    def do_keygen(self) -> None:
        r = LIB.sig_rsapss_keygen(self.sp_bits.value(),
                                  _b(self.k_priv.text()), _b(self.k_pub.text()),
                                  _b(self.cb_fmt.currentText()))
        self._info(r == 0, f"Keypair created ({self.sp_bits.value()}-bit)"
                          if r == 0 else f"Keygen failed: {_last_err()}")

    def do_sign(self) -> None:
        n = C.c_size_t(0)
        r = LIB.sig_rsapss_sign(_b(self.s_priv.text()), _b(self.s_in.text()),
                                _b(self.s_out.text()), _b(self.cb_s_hash.currentText()),
                                self.sp_s_salt.value(), _b(self.cb_s_enc.currentText()),
                                C.byref(n))
        self._info(r == 0, f"Signed ({n.value} bytes) → {self.s_out.text()}"
                           if r == 0 else f"Sign failed: {_last_err()}")

    def do_verify(self) -> None:
        r = LIB.sig_rsapss_verify(_b(self.v_pub.text()), _b(self.v_in.text()),
                                  _b(self.v_sig.text()), _b(self.cb_v_hash.currentText()),
                                  self.sp_v_salt.value(), _b(self.cb_v_enc.currentText()))
        if r == 0:   self._info(True,  "Signature VALID")
        elif r == 1: self._info(False, "Signature INVALID")
        else:        self._info(False, f"Verify error: {_last_err()}")


# ── Main ─────────────────────────────────────────────────────────────────
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Lab 5 — Digital Signatures (ECDSA + RSA-PSS)")
        self.resize(620, 720)
        tabs = QtWidgets.QTabWidget()
        tabs.addTab(EcdsaTab(),  "ECDSA")
        tabs.addTab(RsaPssTab(), "RSA-PSS")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage(f"libsig_core loaded — {platform.system()} {platform.machine()}")


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow(); w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
