"""Main Phantom Key window."""
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from gui.dashboard import Dashboard
from gui.dialogs import PasswordDialog
from security.encryption import (EXTENSION, AuthenticationError, InvalidFormatError,
                                 protect_file, restore_file)
from security.integrity import sha256_file, verify_against_record, verify_with_password
from security.password import analyze_password, generate_password
from storage.file_manager import file_info
from storage.logger import SecurityLogger
from storage.metadata import MetadataStore

BG, PANEL, FG, ACCENT = "#0d1117", "#161b22", "#c9d1d9", "#00e5a0"


class PhantomKeyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phantom Key - Secure File Protection System")
        self.configure(bg=BG)
        self.geometry("820x640")
        self.minsize(760, 600)

        self.logger = SecurityLogger()
        self.meta = MetadataStore()
        self.selected = None
        self.busy = False

        self._style()
        self._build()
        self.logger.event("Application started")
        self._refresh_all()

    # ---------- UI construction ----------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TButton", padding=8, font=("Consolas", 10, "bold"))
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.configure("Horizontal.TProgressbar", background=ACCENT)

    def _build(self):
        tk.Label(self, text="◈ PHANTOM KEY", bg=BG, fg=ACCENT, font=("Consolas", 22, "bold")).pack(pady=(14, 0))
        tk.Label(self, text="SECURE FILE PROTECTION SYSTEM", bg=BG, fg=FG, font=("Consolas", 10)).pack()
        self.status = tk.Label(self, text="● SYSTEM READY", bg=BG, fg=ACCENT, font=("Consolas", 10, "bold"))
        self.status.pack(pady=6)

        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=16)

        # file selection panel
        left = tk.Frame(top, bg=PANEL, padx=14, pady=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(left, text="SELECT FILE", bg=PANEL, fg=ACCENT, font=("Consolas", 11, "bold")).pack(anchor="w")
        self.file_label = tk.Label(left, text="No file selected", bg=PANEL, fg=FG, justify="left",
                                   anchor="w", wraplength=330, font=("Consolas", 10))
        self.file_label.pack(fill="x", pady=8)
        ttk.Button(left, text="BROWSE FILE", command=self.browse).pack(fill="x", pady=2)
        ttk.Button(left, text="🔐 PROTECT FILE", command=self.protect).pack(fill="x", pady=2)
        ttk.Button(left, text="🔓 RESTORE FILE", command=self.restore).pack(fill="x", pady=2)
        ttk.Button(left, text="✓ VERIFY INTEGRITY", command=self.verify).pack(fill="x", pady=2)
        ttk.Button(left, text="⚿ PASSWORD TOOLS", command=self.password_tools).pack(fill="x", pady=2)

        self.dashboard = Dashboard(top)
        self.dashboard.pack(side="right", fill="y")

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=16, pady=(10, 0))

        tk.Label(self, text="SECURITY LOG", bg=BG, fg=ACCENT, font=("Consolas", 11, "bold")).pack(anchor="w", padx=16, pady=(10, 2))
        self.log_box = tk.Text(self, height=12, bg=PANEL, fg=FG, font=("Consolas", 9), state="disabled",
                               relief="flat", padx=8, pady=8)
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(0, 14))

    # ---------- helpers ----------
    def _refresh_all(self):
        self.dashboard.refresh(self.meta.data)
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", "\n".join(self.logger.recent(60)))
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _set_status(self, text, color=ACCENT):
        self.status.config(text=f"● {text}", fg=color)

    def _need_file(self):
        if not self.selected:
            messagebox.showwarning("Phantom Key", "Please select a file first.")
            return False
        return True

    def _run(self, work, on_done):
        """Run `work` in a background thread so the UI doesn't freeze."""
        if self.busy:
            return
        self.busy = True
        self.progress.start(12)
        self._set_status("WORKING...", "#f1c40f")

        def target():
            try:
                result, error = work(), None
            except Exception as exc:  # noqa: BLE001 - reported to the user
                result, error = None, exc
            self.after(0, lambda: self._finish(on_done, result, error))

        threading.Thread(target=target, daemon=True).start()

    def _finish(self, on_done, result, error):
        self.busy = False
        self.progress.stop()
        self._set_status("SYSTEM READY")
        on_done(result, error)
        self._refresh_all()

    # ---------- actions ----------
    def browse(self):
        path = filedialog.askopenfilename(title="Select a file")
        if not path:
            return
        self.selected = Path(path)
        info = file_info(path)
        self.file_label.config(text=f"{info['name']}\nType: {info['extension']}   Size: {info['size']}\n"
                                    f"Modified: {info['modified']}")
        self.logger.event(f"File selected: {info['name']}")
        self._refresh_all()

    def protect(self):
        if not self._need_file():
            return
        if self.selected.suffix == EXTENSION:
            messagebox.showinfo("Phantom Key", "This file is already protected.")
            return
        password = PasswordDialog(self, "Set Password", confirm=True).ask()
        if not password:
            return
        if analyze_password(password)["label"] == "Weak" and not messagebox.askyesno(
                "Weak password", "This password is WEAK and easy to guess.\nContinue anyway?"):
            return
        src = self.selected

        def work():
            out = protect_file(src, password)
            return out, sha256_file(out)

        def done(result, error):
            if error:
                self.logger.event(f"Protect FAILED for {src.name}: {error}")
                messagebox.showerror("Error", str(error))
                return
            out, digest = result
            self.meta.record_protection(out, digest, src.name)
            self.logger.event(f"File protected: {src.name} -> {out.name}")
            messagebox.showinfo("Protected", f"Created:\n{out}\n\nYour original file was NOT deleted.\n"
                                             "Delete it yourself if you no longer need the plaintext copy.")

        self._run(work, done)

    def restore(self):
        if not self._need_file():
            return
        if self.selected.suffix != EXTENSION:
            messagebox.showwarning("Phantom Key", "Select a .phkey file to restore.")
            return
        password = PasswordDialog(self, "Enter Password").ask()
        if not password:
            return
        src = self.selected

        def done(result, error):
            if isinstance(error, AuthenticationError):
                self.meta.record_failure()
                self.logger.event(f"Authentication failed for {src.name}")
                messagebox.showerror("ACCESS DENIED", "Authentication failed.\nProtected data remains unchanged.")
            elif error:
                self.logger.event(f"Restore FAILED for {src.name}: {error}")
                messagebox.showerror("Error", str(error))
            else:
                self.meta.record_restore()
                self.logger.event(f"File restored: {src.name} -> {result.name}")
                messagebox.showinfo("Restored", f"Restored file:\n{result}")

        self._run(lambda: restore_file(src, password), done)

    def verify(self):
        if not self._need_file():
            return
        if self.selected.suffix != EXTENSION:
            messagebox.showwarning("Phantom Key", "Select a .phkey file to verify.")
            return
        src = self.selected
        password = PasswordDialog(self, "Password (Cancel = quick check)").ask()

        def work():
            if password:
                return "full", verify_with_password(src, password)
            recorded = self.meta.get_hash(src)
            if recorded is None:
                return "none", (False, "No recorded fingerprint for this file. Provide the password for a full check.")
            return "quick", verify_against_record(src, recorded)

        def done(result, error):
            if error:
                messagebox.showerror("Error", str(error))
                return
            mode, (ok, message) = result
            self.meta.record_check()
            self.logger.event(f"Integrity check ({mode}) on {src.name}: {'PASS' if ok else 'FAIL'}")
            if ok:
                messagebox.showinfo("✓ Integrity verified", message)
            else:
                if mode == "full":
                    self.meta.record_failure()
                messagebox.showwarning("⚠ Integrity verification failed", message)

        self._run(work, done)

    def password_tools(self):
        pwd = generate_password(16)
        self.clipboard_clear()
        self.clipboard_append(pwd)
        r = analyze_password(pwd)
        self.logger.event("Password generated")
        self._refresh_all()
        messagebox.showinfo("Phantom Password",
                            f"Generated (copied to clipboard):\n\n{pwd}\n\nStrength: {r['label']}")
