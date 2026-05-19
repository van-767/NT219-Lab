import customtkinter as ctk
from tkinter import filedialog, messagebox
import ctypes
import os
import binascii

# Cấu hình giao diện
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AESGui(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AES-128 CTR Cryptography Tool")
        self.geometry("900x700")

        # Load DLL
        # Tự động chọn file dll (Windows) hoặc so (Linux)
        dll_name = "ctr_mode.dll" if os.name == "nt" else "ctr_mode.so"
        self.dll_path = os.path.join(os.path.dirname(__file__), dll_name)
        
        try:
            self.aes_lib = ctypes.CDLL(self.dll_path)
            # Cấu hình hàm AES_Process: action, key_hex, iv_hex, in_path, out_path
            self.aes_lib.AES_Process.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
            ]
            self.aes_lib.AES_Process.restype = ctypes.c_int
            self.dll_loaded = True
        except Exception as e:
            self.dll_loaded = False
            self.dll_error = str(e)

        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="AES LAB 2\n(Manual CTR)", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(pady=20)

        self.mode_label = ctk.CTkLabel(self.sidebar_frame, text="Mode:")
        self.mode_label.pack(pady=(10, 0))
        
        self.mode_option = ctk.CTkOptionMenu(self.sidebar_frame, values=["CTR"])
        self.mode_option.pack(pady=10)
        self.mode_option.set("CTR")

        self.gen_btn = ctk.CTkButton(self.sidebar_frame, text="GENERATE KEY/IV", fg_color="#d35400", hover_color="#a04000", command=self.generate_key_iv)
        self.gen_btn.pack(pady=20, padx=20)

        self.info_label = ctk.CTkLabel(self.sidebar_frame, text="Student Project\nNT219 - Cryptography", font=ctk.CTkFont(size=12))
        self.info_label.pack(side="bottom", pady=20)

        # Main Frame
        self.main_frame = ctk.CTkScrollableFrame(self, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        if not self.dll_loaded:
            error_lbl = ctk.CTkLabel(self.main_frame, text=f"LỖI: Không thể tải thư viện C++ ({dll_name}).\nVui lòng biên dịch file cbc_mode.cpp thành DLL trước!\nChi tiết: {self.dll_error}", text_color="red", font=ctk.CTkFont(weight="bold"))
            error_lbl.pack(pady=10)

        # Key/IV File Section
        self.key_iv_frame = ctk.CTkFrame(self.main_frame)
        self.key_iv_frame.pack(fill="x", pady=10, padx=10)
        
        self.key_file_path = ctk.StringVar()
        ctk.CTkLabel(self.key_iv_frame, text="Key File (Hex):").grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkEntry(self.key_iv_frame, textvariable=self.key_file_path, width=400).grid(row=0, column=1, padx=10, pady=10)
        ctk.CTkButton(self.key_iv_frame, text="Browse", width=80, command=lambda: self.browse_file(self.key_file_path)).grid(row=0, column=2, padx=10, pady=10)

        self.iv_file_path = ctk.StringVar()
        ctk.CTkLabel(self.key_iv_frame, text="IV File (Hex):").grid(row=1, column=0, padx=10, pady=10)
        ctk.CTkEntry(self.key_iv_frame, textvariable=self.iv_file_path, width=400).grid(row=1, column=1, padx=10, pady=10)
        ctk.CTkButton(self.key_iv_frame, text="Browse", width=80, command=lambda: self.browse_file(self.iv_file_path)).grid(row=1, column=2, padx=10, pady=10)

        # IO Section using Tabview
        self.tabview = ctk.CTkTabview(self.main_frame, height=250)
        self.tabview.pack(fill="x", pady=10, padx=10)
        
        self.tab_file = self.tabview.add("File Mode")
        self.tab_text = self.tabview.add("Text Mode")

        # File Mode
        self.input_file_path = ctk.StringVar()
        ctk.CTkLabel(self.tab_file, text="Input File:").grid(row=0, column=0, padx=10, pady=10)
        ctk.CTkEntry(self.tab_file, textvariable=self.input_file_path, width=400).grid(row=0, column=1, padx=10, pady=10)
        ctk.CTkButton(self.tab_file, text="Browse", width=80, command=lambda: self.browse_file(self.input_file_path)).grid(row=0, column=2, padx=10, pady=10)

        self.output_file_path = ctk.StringVar()
        ctk.CTkLabel(self.tab_file, text="Output File:").grid(row=1, column=0, padx=10, pady=10)
        ctk.CTkEntry(self.tab_file, textvariable=self.output_file_path, width=400).grid(row=1, column=1, padx=10, pady=10)
        ctk.CTkButton(self.tab_file, text="Save As", width=80, command=lambda: self.browse_save(self.output_file_path)).grid(row=1, column=2, padx=10, pady=10)

        # Text Mode
        self.tab_text.grid_columnconfigure(0, weight=1)
        self.tab_text.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(self.tab_text, text="Input Text (Hex required for Decrypt):").grid(row=0, column=0, padx=5, pady=(5,0), sticky="w")
        self.input_textbox = ctk.CTkTextbox(self.tab_text, height=120)
        self.input_textbox.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        ctk.CTkLabel(self.tab_text, text="Output Text (Hex produced for Encrypt):").grid(row=0, column=1, padx=5, pady=(5,0), sticky="w")
        self.output_textbox = ctk.CTkTextbox(self.tab_text, height=120)
        self.output_textbox.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        # Action Buttons
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.btn_frame.pack(pady=30)

        self.encrypt_btn = ctk.CTkButton(self.btn_frame, text="AES ENCRYPT", height=50, width=200, font=ctk.CTkFont(size=15, weight="bold"), 
                                        fg_color="#1f6aa5", hover_color="#144870", command=lambda: self.process("encrypt"))
        self.encrypt_btn.grid(row=0, column=0, padx=20)

        self.decrypt_btn = ctk.CTkButton(self.btn_frame, text="AES DECRYPT", height=50, width=200, font=ctk.CTkFont(size=15, weight="bold"),
                                        fg_color="#2b7a0b", hover_color="#1e5608", command=lambda: self.process("decrypt"))
        self.decrypt_btn.grid(row=0, column=1, padx=20)

        # Status
        self.status_label = ctk.CTkLabel(self, text="Ready", font=ctk.CTkFont(size=12))
        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)

    def browse_file(self, var):
        filename = filedialog.askopenfilename()
        if filename:
            var.set(filename)

    def browse_save(self, var):
        filename = filedialog.asksaveasfilename()
        if filename:
            var.set(filename)

    def generate_key_iv(self):
        key_path = filedialog.asksaveasfilename(title="Save Key File (Hex)", initialfile="key.hex")
        if not key_path: return
        
        iv_path = filedialog.asksaveasfilename(title="Save IV File (Hex)", initialfile="iv.hex")
        if not iv_path: return

        try:
            # Generate 16 bytes Key and IV (AES-128)
            key_bytes = os.urandom(16)
            iv_bytes = os.urandom(16)
            
            with open(key_path, "w") as f:
                f.write(key_bytes.hex().upper())
            self.key_file_path.set(key_path)
            
            with open(iv_path, "w") as f:
                f.write(iv_bytes.hex().upper())
            self.iv_file_path.set(iv_path)
                
            messagebox.showinfo("Success", "Key and IV (16 bytes) generated successfully for AES-128 CTR!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {e}")

    def read_hex_from_file(self, path):
        if not path or not os.path.exists(path): return ""
        with open(path, "r") as f:
            return f.read().strip()

    def process(self, action):
        if not self.dll_loaded:
            messagebox.showerror("Error", "DLL not loaded! Compile C++ code first.")
            return

        key_file = self.key_file_path.get()
        iv_file = self.iv_file_path.get()

        if not key_file or not iv_file:
            messagebox.showwarning("Warning", "Please select both Key File and IV File!")
            return

        key_hex = self.read_hex_from_file(key_file)
        iv_hex = self.read_hex_from_file(iv_file)

        is_text_mode = self.tabview.get() == "Text Mode"
        
        if is_text_mode:
            input_text = self.input_textbox.get("1.0", "end-1c").strip()
            if not input_text:
                messagebox.showwarning("Warning", "Input text is empty!")
                return
            infile = "temp_in.bin"
            outfile = "temp_out.bin"
            
            try:
                if action == "encrypt":
                    with open(infile, "wb") as f:
                        f.write(input_text.encode('utf-8'))
                else:
                    with open(infile, "wb") as f:
                        f.write(bytes.fromhex(input_text))
            except ValueError:
                messagebox.showerror("Error", "Invalid Hex input for decryption!")
                return
        else:
            infile = self.input_file_path.get()
            outfile = self.output_file_path.get()
            if not infile or not outfile:
                messagebox.showwarning("Warning", "Please select Input File and Output File!")
                return

        self.status_label.configure(text=f"🚀 Processing {action.upper()} (CTR)...")
        self.update()

        try:
            res = self.aes_lib.AES_Process(
                action.encode(),
                key_hex.encode(),
                iv_hex.encode(),
                infile.encode(),
                outfile.encode()
            )
            
            if res == 0:
                if is_text_mode:
                    self.output_textbox.delete("1.0", "end")
                    if action == "encrypt":
                        with open(outfile, "rb") as f:
                            out_data = f.read().hex().upper()
                        self.output_textbox.insert("1.0", out_data)
                    else:
                        with open(outfile, "rb") as f:
                            out_data = f.read().decode('utf-8', errors='replace')
                        self.output_textbox.insert("1.0", out_data)
                        
                self.status_label.configure(text=f"✅ {action.upper()} SUCCESSFUL!")
                if not is_text_mode:
                    messagebox.showinfo("Success", f"{action.capitalize()} completed!\n\nFile saved: {outfile}")
            else:
                self.status_label.configure(text="❌ PROCESS FAILED!")
                error_msg = "Unknown error"
                if res == -1: error_msg = "Input file not found"
                elif res == -3: error_msg = "Cannot write output file"
                elif res == -4: error_msg = "Invalid padding or Key/IV length"
                messagebox.showerror("Error", f"DLL returned error code {res}: {error_msg}")
        except Exception as e:
            self.status_label.configure(text="❌ SYSTEM ERROR!")
            messagebox.showerror("Error", f"System Error: {e}")

if __name__ == "__main__":
    app = AESGui()
    app.mainloop()
