"""Password dialog with live strength meter and generator."""
import tkinter as tk
from tkinter import ttk

from security.password import analyze_password, generate_password

BG, FG, ACCENT = "#0d1117", "#c9d1d9", "#00e5a0"
COLORS = {"Weak": "#ff5555", "Medium": "#f1c40f", "Strong": "#00e5a0"}


class PasswordDialog(tk.Toplevel):
    """Modal dialog. Use ask() -> password string or None if cancelled."""

    def __init__(self, parent, title="Enter Password", confirm=False):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG, padx=20, pady=16)
        self.resizable(False, False)
        self.result = None
        self.confirm = confirm

        tk.Label(self, text=title.upper(), bg=BG, fg=ACCENT, font=("Consolas", 12, "bold")).pack(anchor="w")
        self.pw = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.show = tk.BooleanVar(value=False)

        self.entry = ttk.Entry(self, textvariable=self.pw, show="*", width=34)
        self.entry.pack(pady=(10, 4))
        if confirm:
            tk.Label(self, text="Confirm password", bg=BG, fg=FG).pack(anchor="w")
            self.entry2 = ttk.Entry(self, textvariable=self.pw2, show="*", width=34)
            self.entry2.pack(pady=4)
        ttk.Checkbutton(self, text="Show password", variable=self.show,
                        command=self._toggle).pack(anchor="w")

        if confirm:
            self.strength = tk.Label(self, text="Strength: -", bg=BG, fg=FG, font=("Consolas", 10))
            self.strength.pack(anchor="w", pady=(8, 0))
            self.bar = ttk.Progressbar(self, length=250, maximum=6)
            self.bar.pack(anchor="w")
            self.pw.trace_add("write", lambda *_: self._update_strength())
            ttk.Button(self, text="Generate strong password", command=self._generate).pack(anchor="w", pady=6)

        self.msg = tk.Label(self, text="", bg=BG, fg="#ff5555")
        self.msg.pack(anchor="w")
        row = tk.Frame(self, bg=BG)
        row.pack(anchor="e", pady=(6, 0))
        ttk.Button(row, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(row, text="OK", command=self._ok).pack(side="right")

        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.transient(parent)
        self.grab_set()
        self.entry.focus_set()

    def _toggle(self):
        ch = "" if self.show.get() else "*"
        self.entry.config(show=ch)
        if self.confirm:
            self.entry2.config(show=ch)

    def _update_strength(self):
        r = analyze_password(self.pw.get())
        self.strength.config(text=f"Strength: {r['label'].upper()}", fg=COLORS[r["label"]])
        self.bar["value"] = r["score"]

    def _generate(self):
        pwd = generate_password(16)
        self.pw.set(pwd)
        self.pw2.set(pwd)
        self.show.set(True)
        self._toggle()
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.msg.config(text="Generated & copied to clipboard. Store it safely!", fg=ACCENT)

    def _ok(self):
        if not self.pw.get():
            self.msg.config(text="Password cannot be empty.", fg="#ff5555")
            return
        if self.confirm and self.pw.get() != self.pw2.get():
            self.msg.config(text="Passwords do not match.", fg="#ff5555")
            return
        self.result = self.pw.get()
        self.destroy()

    def ask(self):
        self.wait_window()
        return self.result
