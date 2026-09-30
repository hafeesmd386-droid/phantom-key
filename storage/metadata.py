"""Local JSON metadata: dashboard statistics + fingerprints of protected files."""
import json
from datetime import datetime
from pathlib import Path

from .file_manager import DATA_DIR

DEFAULT = {"protected_files": 0, "integrity_checks": 0, "failed_attempts": 0,
           "last_operation": "-", "records": {}}


class MetadataStore:
    def __init__(self, data_dir=None):
        self.path = Path(data_dir or DATA_DIR) / "metadata.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict:
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            return {**DEFAULT, **loaded}
        except (OSError, json.JSONDecodeError):
            return dict(DEFAULT, records={})

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def _touch(self, what: str) -> None:
        self.data["last_operation"] = f"{what} @ {datetime.now():%H:%M:%S}"
        self._save()

    def record_protection(self, phkey_path, sha256: str, original_name: str) -> None:
        self.data["protected_files"] += 1
        self.data["records"][str(Path(phkey_path).resolve())] = {
            "sha256": sha256, "original": original_name,
            "created": datetime.now().isoformat(timespec="seconds")}
        self._touch("Protect")

    def get_hash(self, phkey_path):
        rec = self.data["records"].get(str(Path(phkey_path).resolve()))
        return rec["sha256"] if rec else None

    def record_check(self) -> None:
        self.data["integrity_checks"] += 1
        self._touch("Verify")

    def record_failure(self) -> None:
        self.data["failed_attempts"] += 1
        self._touch("Failed attempt")

    def record_restore(self) -> None:
        self._touch("Restore")
