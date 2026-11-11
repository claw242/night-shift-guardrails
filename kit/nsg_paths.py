"""Night Shift Guardrails - path policy: allowed roots, protected files, secrets."""
import fnmatch
import glob
import os
import re
import tempfile

from nsg_shell import UNK

SECRET_BASENAMES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
                    "id_dsa*", ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass",
                    "credentials.json", "service-account*.json", "*.kdbx", "*.keystore", "*.jks")
SECRET_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".pub", ".md")
SECRET_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".config/gh", ".config/gcloud",
               ".terraform.d", "Library/Keychains", ".password-store", ".1password")
SECRET_FILES_HOME = (".claude.json", ".claude/.credentials.json", ".claude/credentials.json")
WELL_KNOWN_SECRET_NAMES = (".env", ".env.local", ".env.production", ".env.development", "id_rsa", "id_ed25519", "id_ecdsa",
                           ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".pgpass", "credentials.json")
SECRET_VAR_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|PRIVATE|AUTH)", re.I)
WRITE_PROTECTED_BASENAMES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
                             ".zlogin", ".gitconfig")
SAFE_DEV = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/urandom",
            "/dev/random")
SYSTEM_BIN_DIRS = ("/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin", "/opt/homebrew/bin")


class PathPolicy:
    def __init__(self, project_dir, home, extra_roots=(), extra_protected=(), guard_dirs=(), allow_temp=True):
        self.home = os.path.realpath(home)
        self.project = os.path.realpath(project_dir)
        roots = [self.project]
        if allow_temp:
            roots += ["/tmp", "/private/tmp", "/var/folders", "/private/var/folders",
                      os.path.realpath(tempfile.gettempdir())]
        roots += [os.path.realpath(os.path.expanduser(r)) for r in extra_roots]
        self.roots = tuple(dict.fromkeys(roots))
        self.extra_protected = tuple(extra_protected)
        self.guard_dirs = tuple(os.path.realpath(d) for d in guard_dirs)

    # -- resolution -------------------------------------------------------------
    def resolve(self, text, cwd):
        """Absolute normalised path of `text`; None when it contains an unresolved value."""
        if UNK in text:
            return None
        if text == "~" or text.startswith("~/"):
            text = self.home + text[1:]
        elif text.startswith("~"):
            return None
        if not os.path.isabs(text):
            if cwd is None:
                return None
            text = os.path.join(cwd, text)
        return os.path.realpath(os.path.normpath(text))

    def inside_roots(self, path):
        return any(path == r or path.startswith(r.rstrip("/") + "/") for r in self.roots)

    def is_ancestor_or_equal_of_project(self, path):
        return self.project == path or self.project.startswith(path.rstrip("/") + "/") or path == "/"

    def is_home_or_parent(self, path):
        return self.home == path or self.home.startswith(path.rstrip("/") + "/")

    # -- classification -----------------------------------------------------------
    def is_secret(self, path):
        base = os.path.basename(path)
        if any(fnmatch.fnmatch(base, p) for p in SECRET_BASENAMES) and not base.endswith(SECRET_SAFE_SUFFIXES):
            return True
        rel_home = path[len(self.home) + 1:] if path.startswith(self.home + "/") else None
        pieces = "/" + path.strip("/") + "/"
        for d in SECRET_DIRS:
            if rel_home is not None and (rel_home == d or rel_home.startswith(d + "/")):
                return True
            if "/" + d + "/" in pieces and d.startswith("."):
                return True
        if rel_home is not None and rel_home in SECRET_FILES_HOME:
            return True
        return path in ("/etc/shadow", "/etc/sudoers", "/proc/self/environ") or path.startswith("/etc/sudoers.d/")

    def is_write_protected(self, path):
        if self.is_secret(path):
            return "secret or credential file"
        for d in self.guard_dirs:
            if path == d or path.startswith(d + "/"):
                return "guardrails own files"
        base = os.path.basename(path)
        parts = path.split("/")
        if ".git" in parts:
            return "git internals"
        if base in WRITE_PROTECTED_BASENAMES and os.path.dirname(path) == self.home:
            return "shell startup file"
        if ".claude" in parts and (base.startswith("settings") or "hooks" in parts or base == "CLAUDE.md"
                                   and os.path.dirname(path) == os.path.join(self.home, ".claude")):
            return "agent settings or hooks"
        if ".nightshift" in parts and base != "queue.jsonl":
            return "guardrails state"
        if any(fnmatch.fnmatch(path, p) for p in self.extra_protected):
            return "protected by configuration"
        return ""

    def check_write(self, path):
        """'' when the path may be written or deleted, otherwise the reason."""
        if path in SAFE_DEV or path.startswith("/dev/fd/"):
            return ""
        if path.startswith("/dev/"):
            return "device file"
        reason = self.is_write_protected(path)
        if reason:
            return reason
        if not self.inside_roots(path):
            return "outside the project and temporary folders"
        return ""

    def glob_hits_secret(self, text, cwd):
        """True when a glob pattern (cat .en[v], ~/.ss?/id_rsa) names a secret file now or could name one."""
        if not re.search(r"[*?\[]", text) or UNK in text:
            return False
        path = text
        if path == "~" or path.startswith("~/"):
            path = self.home + path[1:]
        if not os.path.isabs(path):
            if cwd is None:
                return False
            path = os.path.join(cwd, path)
        try:
            hits = glob.glob(path)[:200]
        except (OSError, re.error):
            hits = []
        if any(self.is_secret(os.path.realpath(h)) for h in hits):
            return True
        pattern = os.path.basename(path)
        if len(re.sub(r"[*?\[\]!]", "", pattern)) < 2:
            return False  # too generic to say anything (a bare * is judged by the files that really exist)
        for name in WELL_KNOWN_SECRET_NAMES:
            if name.startswith(".") and not pattern.startswith("."):
                continue
            if fnmatch.fnmatchcase(name, pattern):
                return True
        return False

    def candidates(self, word):
        """Strings of a word that may name a file: the word, the part after '=', '@' or ':'."""
        found = [word]
        for sep in ("=", "@", ":"):
            if sep in word:
                found.append(word.split(sep, 1)[1])
        return found
