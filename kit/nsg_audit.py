"""Night Shift Guardrails - audit log and secret redaction (standard library only)."""
import json
import os
import re
import time

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}"),
    re.compile(r"\bpypi-AgEI[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[=:]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}"),
)
MAX_FIELD = 400


def redact(text):
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def state_dir(project_dir):
    return os.path.join(project_dir, ".nightshift")


def audit(project_dir, record):
    """Append one JSON line to <project>/.nightshift/audit.jsonl. Never raises; never follows a symbolic link."""
    try:
        directory = state_dir(project_dir)
        if os.path.islink(directory):
            return
        os.makedirs(directory, exist_ok=True)
        clean = {k: (redact(v)[:MAX_FIELD] if isinstance(v, str) else v) for k, v in record.items()}
        clean["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(os.path.join(directory, "audit.jsonl"), flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(clean, ensure_ascii=False) + "\n")
    except OSError:
        pass
