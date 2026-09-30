"""Security dashboard panel."""
import tkinter as tk

BG, FG, ACCENT = "#161b22", "#c9d1d9", "#00e5a0"


class Dashboard(tk.Frame):
    FIELDS = [("Protected Files", "protected_files"), ("Integrity Checks", "integrity_checks"),
              ("Failed Attempts", "failed_attempts"), ("Last Operation", "last_operation")]

    def __init__(self, parent):
        super().__init__(parent, bg=BG, padx=14, pady=10)
        tk.Label(self, text="SECURITY DASHBOARD", bg=BG, fg=ACCENT,
                 font=("Consolas", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.values = {}
        for i, (label, key) in enumerate(self.FIELDS, start=1):
            tk.Label(self, text=label, bg=BG, fg=FG, font=("Consolas", 10)).grid(row=i, column=0, sticky="w", padx=(0, 20))
            v = tk.Label(self, text="-", bg=BG, fg="white", font=("Consolas", 10, "bold"))
            v.grid(row=i, column=1, sticky="e")
            self.values[key] = v
        r = len(self.FIELDS) + 1
        for label, text in [("Algorithm", "Fernet (AES + HMAC)"), ("Key derivation", "PBKDF2-SHA256")]:
            tk.Label(self, text=label, bg=BG, fg=FG, font=("Consolas", 10)).grid(row=r, column=0, sticky="w")
            tk.Label(self, text=text, bg=BG, fg=ACCENT, font=("Consolas", 10)).grid(row=r, column=1, sticky="e")
            r += 1

    def refresh(self, stats: dict) -> None:
        for key, widget in self.values.items():
            widget.config(text=str(stats.get(key, "-")))
