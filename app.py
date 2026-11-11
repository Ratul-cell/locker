"""Folder Locker - lock folders behind a password or a 4-digit PIN.

Locking packs the folder contents into one AES-256-GCM encrypted file
(locked.vault), removes the originals and swaps the folder icon for a lock.
Unlocking decrypts everything back so you can copy/cut/paste/delete normally.
Works on Windows, macOS and Linux.
"""
import json
import os
import platform
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PIL import Image, ImageDraw

OS = platform.system()
VAULT, TMP, STAGE = "locked.vault", "locked.vault.tmp", ".folderlocker_stage"
ICON_FILE = ".folderlocker.ico"
SKIP = {VAULT, TMP, STAGE, ICON_FILE, "Icon\r", ".directory"}
MAGIC = b"FLK1"
HDR = 4 + 1 + 16 + 8  # magic, mode, salt, nonce prefix
CHUNK = 1 << 20
CFG = Path.home() / ".folderlocker"
MODES = {"password": b"P", "pin": b"N"}
KDF_N = {b"P": 2 ** 15, b"N": 2 ** 17}  # PIN gets a costlier KDF


# ---------------------------------------------------------------- crypto ----
def valid(mode, secret):
    if mode == "pin":
        return len(secret) == 4 and secret.isdigit()
    return len(secret) >= 6 and any(c.isdigit() for c in secret)


def derive(secret, m, salt):
    return Scrypt(salt=salt, length=32, n=KDF_N[m], r=8, p=1).derive(secret.encode())


class EncWriter:
    """File-like: buffers data, writes authenticated AES-GCM frames."""

    def __init__(self, f, key, nonce):
        self.f, self.aes, self.nonce, self.i, self.buf = f, AESGCM(key), nonce, 0, bytearray()

    def write(self, b):
        self.buf += b
        while len(self.buf) > CHUNK:
            self._emit(bytes(self.buf[:CHUNK]), 0)
            del self.buf[:CHUNK]
        return len(b)

    def _emit(self, data, last):
        ct = self.aes.encrypt(self.nonce + struct.pack(">I", self.i), data, bytes([last]))
        self.f.write(bytes([last]) + struct.pack(">I", len(ct)) + ct)
        self.i += 1

    def close(self):
        self._emit(bytes(self.buf), 1)
        self.buf.clear()


class DecReader:
    def __init__(self, f, key, nonce):
        self.f, self.aes, self.nonce, self.i = f, AESGCM(key), nonce, 0
        self.buf, self.done = b"", False

    def read(self, n=-1):
        while not self.done and (n < 0 or len(self.buf) < n):
            h = self.f.read(5)
            if len(h) < 5:
                raise ValueError("Vault is truncated or corrupted.")
            last, ln = h[0], struct.unpack(">I", h[1:])[0]
            ct = self.f.read(ln)
            self.buf += self.aes.decrypt(self.nonce + struct.pack(">I", self.i), ct, bytes([last]))
            self.i += 1
            self.done = last == 1
        if n < 0:
            n = len(self.buf)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def _rm_error(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove(p):
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, onerror=_rm_error)
    else:
        p.unlink()


def vault_mode(folder):
    v = Path(folder) / VAULT
    if not v.is_file():
        return None
    with open(v, "rb") as f:
        h = f.read(5)
    return {b"P": "password", b"N": "pin"}.get(h[4:5]) if h[:4] == MAGIC else None


def lock(folder, mode, secret):
    folder = Path(folder)
    if (folder / VAULT).exists():
        raise ValueError("Folder is already locked.")
    m = MODES[mode]
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(8)
    key = derive(secret, m, salt)
    items = [p for p in folder.iterdir() if p.name not in SKIP]
    tmp = folder / TMP
    try:
        with open(tmp, "wb") as f:
            f.write(MAGIC + m + salt + nonce)
            w = EncWriter(f, key, nonce)
            with tarfile.open(fileobj=w, mode="w|") as tar:
                for p in items:
                    tar.add(p, arcname=p.name)
            w.close()
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, folder / VAULT)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    for p in items:  # originals are removed only after the vault is safely written
        remove(p)
    set_icon(folder, True)


def unlock(folder, secret):
    folder = Path(folder)
    vault, stage = folder / VAULT, folder / STAGE
    with open(vault, "rb") as f:
        h = f.read(HDR)
        if h[:4] != MAGIC:
            raise ValueError("Not a Folder Locker vault.")
        key = derive(secret, h[4:5], h[5:21])
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir()
        try:
            with tarfile.open(fileobj=DecReader(f, key, h[21:29]), mode="r|") as tar:
                for member in tar:
                    name = os.path.normpath(member.name)
                    if os.path.isabs(name) or name.startswith(".."):
                        raise ValueError("Unsafe path in vault.")
                    if hasattr(tarfile, "data_filter"):
                        tar.extract(member, stage, filter="data")
                    else:
                        tar.extract(member, stage)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
    set_icon(folder, False)
    for p in list(stage.iterdir()):
        shutil.move(str(p), str(folder / p.name))
    stage.rmdir()
    vault.unlink()


# ----------------------------------------------------------------- icons ----
def make_icons():
    CFG.mkdir(exist_ok=True)
    png, ico = CFG / "lock.png", CFG / "lock.ico"
    if png.exists() and ico.exists():
        return png, ico
    im = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((16, 36, 110, 80), 10, fill=(225, 165, 40, 255))
    d.rounded_rectangle((16, 56, 240, 220), 16, fill=(245, 190, 60, 255))
    d.arc((88, 70, 168, 150), 180, 360, fill=(40, 40, 50, 255), width=14)
    d.rectangle((88, 110, 102, 128), fill=(40, 40, 50, 255))
    d.rectangle((154, 110, 168, 128), fill=(40, 40, 50, 255))
    d.rounded_rectangle((78, 120, 178, 200), 12, fill=(40, 40, 50, 255))
    d.ellipse((120, 140, 136, 156), fill=(245, 190, 60, 255))
    d.rectangle((125, 152, 131, 178), fill=(245, 190, 60, 255))
    im.save(png)
    im.save(ico, sizes=[(256, 256), (64, 64), (48, 48), (32, 32), (16, 16)])
    return png, ico


def run(*args):
    try:
        flags = 0x08000000 if OS == "Windows" else 0
        subprocess.run(args, capture_output=True, creationflags=flags)
    except Exception:
        pass


def set_icon(folder, locked):
    """Best effort: a failure here never blocks locking/unlocking."""
    folder = Path(folder)
    try:
        png, ico = make_icons()
        if OS == "Windows":
            import ctypes
            ini, icon = folder / "desktop.ini", folder / ICON_FILE
            if locked:
                shutil.copy(ico, icon)
                ini.write_text("[.ShellClassInfo]\nIconResource=%s,0\n" % ICON_FILE)
                for p in (ini, icon):
                    run("attrib", "+h", "+s", str(p))
                run("attrib", "+s", str(folder))
            else:
                for p in (ini, icon):
                    run("attrib", "-h", "-s", "-r", str(p))
                    p.unlink(missing_ok=True)
                run("attrib", "-s", str(folder))
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        elif OS == "Darwin":
            from AppKit import NSImage, NSWorkspace
            img = NSImage.alloc().initWithContentsOfFile_(str(png)) if locked else None
            NSWorkspace.sharedWorkspace().setIcon_forFile_options_(img, str(folder), 0)
        else:
            d = folder / ".directory"  # KDE / Dolphin
            if locked:
                d.write_text("[Desktop Entry]\nIcon=%s\n" % png)
                run("gio", "set", "-t", "string", str(folder), "metadata::custom-icon", "file://" + str(png))
            else:
                d.unlink(missing_ok=True)
                run("gio", "set", "-t", "unset", str(folder), "metadata::custom-icon")
    except Exception:
        pass


def open_folder(p):
    if OS == "Windows":
        os.startfile(p)
    else:
        subprocess.Popen(["open" if OS == "Darwin" else "xdg-open", p])


# ------------------------------------------------------------------- GUI ----
def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class CredDialog(tk.Toplevel):
        def __init__(self, parent, title, fixed=None, confirm=False):
            super().__init__(parent)
            self.title(title)
            self.resizable(False, False)
            self.result, self.confirm = None, confirm
            self.mode = tk.StringVar(value=fixed or "password")
            pad = dict(padx=14, pady=4)
            if fixed:
                ttk.Label(self, text="Enter your " + ("PIN" if fixed == "pin" else "password")).pack(**pad)
            else:
                ttk.Radiobutton(self, text="Password (6+ characters, with a number)",
                                variable=self.mode, value="password").pack(anchor="w", **pad)
                ttk.Radiobutton(self, text="PIN (exactly 4 digits)",
                                variable=self.mode, value="pin").pack(anchor="w", **pad)
            self.e1 = ttk.Entry(self, show="*", width=32)
            self.e1.pack(**pad)
            self.e2 = None
            if confirm:
                ttk.Label(self, text="Confirm").pack()
                self.e2 = ttk.Entry(self, show="*", width=32)
                self.e2.pack(**pad)
            self.msg = ttk.Label(self, foreground="red")
            self.msg.pack()
            ttk.Button(self, text="OK", command=self.ok).pack(pady=8)
            self.bind("<Return>", lambda e: self.ok())
            self.transient(parent)
            self.grab_set()
            self.e1.focus()
            parent.wait_window(self)

        def ok(self):
            m, s = self.mode.get(), self.e1.get()
            if self.confirm:
                if not valid(m, s):
                    self.msg.config(text="PIN must be 4 digits." if m == "pin"
                                    else "Password needs 6+ characters and a number.")
                    return
                if s != self.e2.get():
                    self.msg.config(text="Entries do not match.")
                    return
            self.result = (m, s)
            self.destroy()

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Folder Locker")
            self.geometry("680x360")
            self.cfg = CFG / "folders.json"
            CFG.mkdir(exist_ok=True)
            try:
                self.folders = json.loads(self.cfg.read_text())
            except Exception:
                self.folders = []
            self.tree = ttk.Treeview(self, columns=("s", "p"), show="headings", selectmode="browse")
            self.tree.heading("s", text="Status")
            self.tree.heading("p", text="Folder")
            self.tree.column("s", width=90, stretch=False)
            self.tree.pack(fill="both", expand=True, padx=10, pady=(10, 4))
            bar = ttk.Frame(self)
            bar.pack(fill="x", padx=10)
            self.btns = []
            for text, cmd in (("Add folder", self.add), ("Lock", self.do_lock), ("Unlock", self.do_unlock),
                              ("Open", self.do_open), ("Remove from list", self.remove_entry)):
                b = ttk.Button(bar, text=text, command=cmd)
                b.pack(side="left", padx=3, pady=6)
                self.btns.append(b)
            self.pb = ttk.Progressbar(self, mode="indeterminate")
            self.status = ttk.Label(self, text="Ready")
            self.status.pack(anchor="w", padx=10, pady=(0, 8))
            self.refresh()

        def refresh(self):
            self.tree.delete(*self.tree.get_children())
            for p in self.folders:
                st = "Missing" if not os.path.isdir(p) else ("Locked" if vault_mode(p) else "Unlocked")
                self.tree.insert("", "end", iid=p, values=(st, p))
            self.cfg.write_text(json.dumps(self.folders))

        def sel(self):
            s = self.tree.selection()
            if not s:
                messagebox.showinfo("Folder Locker", "Select a folder first.")
                return None
            return s[0]

        def add(self):
            p = filedialog.askdirectory(title="Choose a folder")
            if p:
                p = os.path.normpath(p)
                if p not in self.folders:
                    self.folders.append(p)
                self.refresh()

        def do_lock(self):
            p = self.sel()
            if not p:
                return
            if vault_mode(p):
                return messagebox.showinfo("Folder Locker", "Already locked.")
            d = CredDialog(self, "Lock folder", confirm=True)
            if d.result:
                self.bg(lambda: lock(p, *d.result), "Locking...")

        def do_unlock(self):
            p = self.sel()
            if not p:
                return
            mode = vault_mode(p)
            if not mode:
                return messagebox.showinfo("Folder Locker", "This folder is not locked.")
            d = CredDialog(self, "Unlock folder", fixed=mode)
            if d.result:
                self.bg(lambda: unlock(p, d.result[1]), "Unlocking...")

        def do_open(self):
            p = self.sel()
            if p:
                if vault_mode(p):
                    messagebox.showinfo("Folder Locker", "Unlock the folder first.")
                else:
                    open_folder(p)

        def remove_entry(self):
            p = self.sel()
            if p:
                self.folders.remove(p)
                self.refresh()

        def bg(self, fn, msg):
            for b in self.btns:
                b.state(["disabled"])
            self.status.config(text=msg)
            self.pb.pack(fill="x", padx=10, before=self.status)
            self.pb.start(12)

            def work():
                try:
                    fn()
                    err = None
                except InvalidTag:
                    err = "Wrong password or PIN."
                except Exception as e:
                    err = str(e)
                self.after(0, lambda: self.finish(err))

            threading.Thread(target=work, daemon=True).start()

        def finish(self, err):
            self.pb.stop()
            self.pb.pack_forget()
            for b in self.btns:
                b.state(["!disabled"])
            self.status.config(text=err or "Done.")
            self.refresh()
            if err:
                messagebox.showerror("Folder Locker", err)

    App().mainloop()


if __name__ == "__main__":
    main()
