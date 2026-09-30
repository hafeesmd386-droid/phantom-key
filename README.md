# ◈ Phantom Key
A Python/Tkinter desktop app for protecting files with password-derived keys, authenticated encryption and integrity verification.

## Run
```
pip install -r requirements.txt
python main.py
```
Tkinter ships with Python (on Debian/Ubuntu: `sudo apt install python3-tk`).

## Tests
```
python -m unittest discover -s tests -v
```

## How it works
1. Random 16-byte salt (`secrets`).
2. Key = PBKDF2-HMAC-SHA256(password, salt, 600,000 iterations).
3. Fernet (AES + HMAC-SHA256) encrypts the file - confidentiality + integrity.
4. Output: `<name>.phkey` = `MAGIC | iterations | salt | Fernet token`; the original file name is stored inside the encrypted payload.

## Features
Protect / Restore / Verify, password strength analyzer, secure password generator, security dashboard, event log (`data/security.log`), JSON metadata (`data/metadata.json`).

## Verify modes
- **With password:** full authenticated decryption (detects tampering and wrong passwords - Fernet can't tell them apart).
- **Without password (Cancel):** compares SHA-256 to the fingerprint recorded when the file was protected.

## Limitations
Whole file is loaded into memory (fine for files up to a few hundred MB). Does not protect against malware on your PC, leaked passwords, or plaintext copies left behind. Lost password = lost data.

## Ideas for future work
Argon2id (`argon2-cffi`), chunked streaming encryption, `MultiFernet` key rotation, SQLite log, benchmarks (experiments B/C/D from the concept doc).
