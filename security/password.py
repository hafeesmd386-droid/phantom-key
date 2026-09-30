"""Password strength analysis and secure password generation."""
import secrets
import string

SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def analyze_password(password: str) -> dict:
    """Return a dict describing the password's characteristics and score (0-6)."""
    checks = {
        "Length >= 12": len(password) >= 12,
        "Uppercase": any(c.isupper() for c in password),
        "Lowercase": any(c.islower() for c in password),
        "Number": any(c.isdigit() for c in password),
        "Special character": any(not c.isalnum() for c in password),
    }
    score = sum(checks.values())
    if len(password) >= 16:
        score += 1  # bonus for long passwords: length matters most
    common = {"123456", "password", "qwerty", "admin", "letmein", "12345678", "admin123"}
    if password.lower() in common or password.lower().strip("0123456789!") in common:
        score = 0
    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"
    return {"checks": checks, "score": score, "max_score": 6, "label": label}


def generate_password(length: int = 16) -> str:
    """Generate a random password using the `secrets` module (CSPRNG)."""
    length = max(length, 8)
    alphabet = string.ascii_letters + string.digits + SPECIALS
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in SPECIALS for c in pwd)):
            return pwd
