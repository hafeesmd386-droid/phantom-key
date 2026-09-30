"""Security event log (plain text file)."""
import logging
from pathlib import Path

from .file_manager import DATA_DIR


class SecurityLogger:
    def __init__(self, data_dir=None):
        self.path = Path(data_dir or DATA_DIR) / "security.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._log = logging.getLogger(f"phantomkey.{self.path}")
        self._log.setLevel(logging.INFO)
        if not self._log.handlers:
            handler = logging.FileHandler(self.path, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%Y-%m-%d %H:%M:%S"))
            self._log.addHandler(handler)

    def event(self, message: str) -> None:
        self._log.info(message)

    def recent(self, n: int = 50) -> list[str]:
        if not self.path.exists():
            return []
        return self.path.read_text(encoding="utf-8").splitlines()[-n:]
