"""Night Shift Guardrails - per-command rules.

Every rule receives the Analyzer `an`, the command name, its arguments (already unquoted and expanded; UNK marks an
unresolved value) and a Ctx. A rule can only REFUSE (an.deny = always, an.soft = only in strict mode).
"""
import os
import re

from nsg_shell import UNK

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"}
INLINE_FLAGS = {"python": ("-c",), "node": ("-e", "-p", "--eval", "--print"), "nodejs": ("-e", "-p", "--eval"),
                "ruby": ("-e",), "perl": ("-e", "-E"), "php": ("-r",), "lua": ("-e",), "osascript": ("-e",),
                "bun": ("-e", "--eval"), "deno": ("eval",), "Rscript": ("-e",), "swift": ("-e",)}
OTHER_INTERPS = {"tclsh", "pwsh", "powershell", "ts-node", "tsx", "awk", "gawk", "mawk"}
NEVER = {"sudo": "privilege escalation", "su": "privilege escalation", "doas": "privilege escalation",
         "pkexec": "privilege escalation", "mkfs": "disk formatting", "fdisk": "disk partitioning",
         "parted": "disk partitioning", "gdisk": "disk partitioning", "wipefs": "disk wiping",
         "newfs": "disk formatting", "mount": "mounting a device", "umount": "unmounting a device",
         "shutdown": "power control", "reboot": "power control", "halt": "power control",
         "poweroff": "power control", "telinit": "power control", "init": "power control",
         "killall": "killing processes by name", "pkill": "killing processes by name",
         "passwd": "account management", "useradd": "account management", "userdel": "account management",
         "usermod": "account management", "dscl": "account management", "sysadminctl": "account management",
         "visudo": "sudoers edition", "chsh": "account management", "csrutil": "system integrity settings",
         "spctl": "system security settings", "nvram": "firmware settings", "pmset": "power settings",
         "scutil": "system network settings", "networksetup": "system network settings", "iptables": "firewall",
         "pfctl": "firewall", "ufw": "firewall", "sysctl": "kernel settings", "losetup": "device setup",
         "at": "scheduled jobs", "batch": "scheduled jobs", "nc": "raw network tool", "ncat": "raw network tool",
         "netcat": "raw network tool", "socat": "raw network tool", "telnet": "raw network tool",
         "ssh": "remote shell", "scp": "remote copy", "sftp": "remote copy", "ftp": "remote copy",
         "tftp": "remote copy", "mosh": "remote shell", "rclone": "remote copy", "ngrok": "public tunnel",
         "cloudflared": "public tunnel", "nmap": "network scan", "masscan": "network scan",
         "history": "shell history", "security": None, "tmutil": None, "diskutil": None, "defaults": None,
         "launchctl": None, "systemctl": None, "service": None, "crontab": None}
READ_ONLY_VERBS = {"list", "ls", "get", "describe", "show", "status", "whoami", "version", "help", "plan", "diff",
                   "logs", "view", "info", "history", "validate", "fmt", "inspect", "config-view", "top",
                   "api-resources", "explain", "current-context", "get-caller-identity", "ps", "images"}
CLOUD_CLIS = {"aws", "gcloud", "az", "doctl", "heroku", "flyctl", "fly", "vercel", "netlify", "wrangler",
              "firebase", "supabase", "railway", "terraform", "tofu", "kubectl", "helm", "pulumi", "ansible",
              "ansible-playbook", "serverless", "sls", "cdk", "eksctl", "oc", "vault"}
PUBLISH = {"npm": {"publish", "unpublish", "deprecate", "token", "login", "adduser", "owner", "access", "dist-tag",
                   "logout", "whoami-token"},
           "cargo": {"publish", "login", "yank", "owner"}, "gem": {"push", "yank", "signin", "owner"},
           "twine": {"upload"}, "docker": {"push", "login", "logout"}, "podman": {"push", "login"},
           "poetry": {"publish"}, "flit": {"publish"}, "hatch": {"publish"}, "uv": {"publish"},
           "brew": {"uninstall", "untap"}, "pip": {"uninstall"}, "pip3": {"uninstall"}}
PUBLISH["yarn"] = PUBLISH["pnpm"] = PUBLISH["bun"] = PUBLISH["npm"]
SQL_BAD = re.compile(r"\b(drop\s+(table|database|schema|index|view|user|role|collection)|truncate\b|"
                     r"delete\s+from\s+[\w.\"`\[\]]+\s*(;|$|\"|')|alter\s+table\s+\S+\s+drop|flushall|flushdb|"
                     r"dropdatabase|\.drop\(|deletemany\(\s*\{\s*\}\s*\))", re.I)
DB_BAD = re.compile(r"(db:drop|db:reset|db:wipe|db:schema:load|migrate:fresh|migrate reset|--force-reset|"
                    r"\bsqlflush\b|manage\.py\s+flush|downgrade\s+base|migrate:rollback\s+--all|db:setup)", re.I)
RISKY_CODE = re.compile(
    r"(os\.system|subprocess|popen|\bpty\b|shutil\.|os\.(remove|unlink|rmdir|removedirs|rename|chmod|chown|kill|"
    r"exec|spawn|walk|environ|putenv|getenv)|\bsocket\b|urllib|requests|http\.client|httpx|ftplib|smtplib|"
    r"__import__|importlib|\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\bopen\s*\(|pathlib|\.unlink|rmtree|write_text|"
    r"write_bytes|child_process|\bfs\b|require\s*\(|\bimport\s*\(|process\.|\bfetch\s*\(|Deno\.|Bun\.|"
    r"base64|b64decode|codecs|\bchr\s*\(|\\x[0-9a-fA-F]{2}|fromCharCode|atob|getattr|globals|builtins|"
    r"\bsystem\s*\(|\bexec\b|File\.|FileUtils|IO\.|%x|`|\bunlink\b|\bglob\s*\(|\bdo shell script|"
    r"\.ssh|\.aws|\.env\b|id_rsa|\.gnupg|credentials|keychain)", re.I)
DANGEROUS_CODE_PATHS = re.compile(r"(\.ssh|\.aws|\.gnupg|id_rsa|id_ed25519|\.env\b|\.netrc|keychain|\.npmrc)", re.I)


class Ctx:
    def __init__(self, piped_in=False, piped_out=False, stdin_text=None, procsub=False):
        self.piped_in, self.piped_out, self.stdin_text, self.procsub = piped_in, piped_out, stdin_text, procsub


def split_args(args, value_opts=()):
    """-> (flags, operands, values). Short flags are split into letters; --long keeps its name (without value)."""
    flags, operands, values, i, only_operands = set(), [], {}, 0, False
    while i < len(args):
        a = args[i]
        i += 1
        if only_operands or a == "-" or not a.startswith("-") or a == UNK:
            operands.append(a)
        elif a == "--":
            only_operands = True
        elif a.startswith("--"):
            name, _, val = a[2:].partition("=")
            flags.add(name)
            if val:
                values[name] = val
            elif "--" + name in value_opts and i < len(args):
                values[name] = args[i]
                i += 1
        else:
            for k, ch in enumerate(a[1:]):
                flags.add(ch)
                if "-" + ch in value_opts:
                    rest = a[2 + k:]
                    if rest:
                        values[ch] = rest
                    elif i < len(args):
                        values[ch] = args[i]
                        i += 1
                    break
    return flags, operands, values


def base_name(word):
    name = os.path.basename(word.rstrip("/")) if word else word
    return name


def interp_family(name):
    if re.fullmatch(r"python[0-9.]*", name):
        return "python"
    return name


# -- filesystem rules ---------------------------------------------------------------------------------------------

def rule_rm(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    if "no-preserve-root" in flags:
        an.deny("rm-root", "--no-preserve-root is never allowed")
    for target in ops:
        an.delete_target(target)


def rule_writer_last(an, name, args, ctx):
    """cp, install, ln, rsync: the destination is written."""
    flags, ops, values = split_args(args, ("-t", "--target-directory", "-T"))
    dest = values.get("t") or values.get("target-directory")
    targets = [dest] if dest else ops[-1:]
    for target in targets:
        an.write_target(target, name + " destination")
    if name == "rsync":
        for op in ops:
            if re.match(r"^[^/.~][^/]*:", op) or op.startswith("rsync://"):
                an.deny("remote-copy", "rsync to or from a remote host")
        if flags & {"delete", "delete-before", "delete-after", "delete-during", "delete-excluded", "remove-source-files"}:
            for op in ops[-1:]:
                an.write_target(op, "rsync --delete destination")


def rule_mv(an, name, args, ctx):
    flags, ops, values = split_args(args, ("-t", "--target-directory"))
    for target in ops:
        an.write_target(target, "mv path")
    if values.get("t") or values.get("target-directory"):
        an.write_target(values.get("t") or values.get("target-directory"), "mv destination")


def rule_all_written(an, name, args, ctx):
    """tee, touch, mkdir, truncate, chmod/chown targets..."""
    flags, ops, _ = split_args(args)
    if name in ("chmod", "chown", "chgrp"):
        if ops:
            mode, ops = ops[0], ops[1:]
            if name == "chmod" and (re.search(r"[+]?s", mode) and re.fullmatch(r"[ugoa]*[+=][rwxXst]*s[rwxXst]*", mode)
                                    or re.fullmatch(r"[0-7]?[4-7][0-7]{3}", mode)):
                an.deny("setuid", "setuid or setgid bit")
            if name == "chmod" and flags & {"R", "recursive"} and re.search(r"(777|a\+[rwx]*w|o\+[rwx]*w)", mode):
                an.deny("chmod-recursive", "recursive world-writable permissions")
    for target in ops:
        an.write_target(target, name + " target")


def rule_sed(an, name, args, ctx):
    flags, ops, values = split_args(args, ("-e", "-f", "--expression", "--file"))
    in_place = "i" in flags or "in-place" in flags or any(a.startswith("-i") or a.startswith("--in-place") for a in args)
    scripts = "e" in values or "expression" in values or "f" in values or "e" in flags
    files = ops if scripts else ops[1:]
    if re.search(r"(^|[;{}\s])[0-9,$]*[ew]\s+\S", " ".join(ops[:1])) and not scripts and name == "sed":
        an.soft("sed-exec", "sed script uses the e or w command")
    if in_place:
        for target in files:
            an.write_target(target, "sed -i file")


def rule_perl(an, name, args, ctx):
    rule_interpreter(an, name, args, ctx)
    if any(re.match(r"^-[a-zA-Z]*i", a) for a in args if a.startswith("-") and not a.startswith("--")):
        flags, ops, _ = split_args(args, ("-e", "-E"))
        for target in ops:
            an.write_target(target, "perl -i file")


def rule_archive(an, name, args, ctx):
    """tar, unzip, make, npm...: a -C / -d / --directory option moves the work to another folder."""
    if name == "tar" and args and re.fullmatch(r"[A-Za-z]+", args[0]):
        args = ["-" + args[0]] + list(args[1:])  # old style: tar czf archive.tgz dir
    dir_opts = ("-C", "--directory", "-f", "--file") + (("-d",) if name in ("unzip", "zip") else ())
    flags, ops, values = split_args(args, dir_opts)
    for key in ("C", "directory", "d"):
        if values.get(key):
            an.write_target(values[key], name + " target folder")
    creating = name == "tar" and bool(flags & {"c", "create", "r", "u"})
    if creating and (values.get("f") or values.get("file")):
        an.write_target(values.get("f") or values.get("file"), "tar archive")


def rule_dd(an, name, args, ctx):
    for a in args:
        if a.startswith("of="):
            an.write_target(a[3:], "dd output")


def rule_find(an, name, args, ctx):
    roots, i = [], 0
    while i < len(args) and (not args[i].startswith("-") or args[i] in ("-H", "-L", "-P")) and args[i] not in ("(", "!"):
        if not args[i].startswith("-"):
            roots.append(args[i])
        i += 1
    rest = args[i:]
    roots = roots or ["."]
    selective = any(a in ("-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-newer", "-mtime", "-mmin",
                          "-atime", "-size", "-empty", "-user", "-perm", "-lname", "-wholename") for a in rest)
    deleting = "-delete" in rest
    for root in roots:
        resolved = an.resolve(root)
        if resolved is None:
            an.soft("unresolved-path", "find starts from a path that cannot be resolved")
        elif deleting and an.policy.check_write(resolved):
            an.deny("find-delete", "find -delete outside the project: " + an.policy.check_write(resolved))
    if deleting and not selective:
        an.deny("find-delete", "find -delete without -name/-path/-mtime... would remove everything below the start")
    for k, a in enumerate(rest):
        if a in ("-exec", "-execdir", "-ok", "-okdir"):
            end = k + 1
            while end < len(rest) and rest[end] not in (";", "+", "\\;"):
                end += 1
            inner = rest[k + 1:end]
            found = os.path.join(an.resolve(roots[0]) or "/__unknown__", "__found__")
            inner = [found if x == "{}" else x for x in inner]
            if inner and base_name(inner[0]) in ("rm", "rmdir", "unlink", "shred") and not selective:
                an.deny("find-delete", "find -exec rm without a selective predicate")
            if inner:
                an.run_argv(inner, Ctx())


def rule_xargs(an, name, args, ctx):
    i = 0
    take = {"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "-i"}
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        i += 2 if args[i] in take else 1
    if i < len(args) and args[i] == "--":
        i += 1
    inner = args[i:]
    if inner:
        an.run_argv(inner + [UNK], Ctx())


# -- interpreters -----------------------------------------------------------------------------------------

def check_inline_code(an, code, what):
    if UNK in code:
        an.soft("dynamic-code", what + " runs code that is built at run time")
        return
    if DANGEROUS_CODE_PATHS.search(code):
        an.deny("secret-access", what + " touches a secret or credential path")
        return
    if RISKY_CODE.search(code):
        an.soft("inline-code", what + " uses file, process or network features; it cannot be analysed (write it to a script file)")


def rule_shell(an, name, args, ctx):
    flags, ops, values = split_args(args, ("-o", "-O", "--rcfile", "--init-file"))
    if "c" in flags:
        if not ops:
            an.soft("shell-c", name + " -c without code")
            return
        if any(UNK in o for o in ops[:1]):
            an.soft("dynamic-code", name + " -c with code built at run time")
            return
        an.analyze_text(ops[0])
        return
    if ops:
        an.analyze_file(ops[0], name + " script")
        return
    if ctx.stdin_text is not None:
        an.analyze_text(ctx.stdin_text)
    elif ctx.piped_in or ctx.procsub:
        an.deny("pipe-to-shell", "input piped into " + name + " cannot be checked")


def rule_source(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    if ctx.procsub or (ops and UNK in ops[0]):
        an.deny("pipe-to-shell" if ctx.procsub else "dynamic-code", name + " of a generated script")
    elif ops:
        an.analyze_file(ops[0], "sourced script")


def rule_interpreter(an, name, args, ctx):
    fam = interp_family(name)
    inline = INLINE_FLAGS.get(fam, ())
    if fam in ("deno",) and args[:1] == ["eval"]:
        check_inline_code(an, " ".join(args[1:]), name + " eval")
        return
    i = 0
    while i < len(args):
        a = args[i]
        short = a.startswith("-") and not a.startswith("--") and len(a) > 2 and fam in ("python", "perl", "ruby")
        if a in inline or (short and any(("-" + c) in inline for c in a[1:])):
            code = args[i + 1] if i + 1 < len(args) else ""
            check_inline_code(an, code, name + " " + a)
            return
        if fam == "python" and a in ("-m",):
            return
        if not a.startswith("-"):
            return  # a script file or module: its content is not analysed (documented limit)
        i += 1
    if ctx.stdin_text is not None:
        check_inline_code(an, ctx.stdin_text, name + " reading its program from stdin")
    elif ctx.piped_in or ctx.procsub:
        an.deny("pipe-to-shell", "input piped into " + name + " cannot be checked")


# -- network ---------------------------------------------------------------------------------------------------

LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def host_of(url):
    m = re.match(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


def rule_curl(an, name, args, ctx):
    flags, ops, values = split_args(args, ("-o", "--output", "-O", "-X", "--request", "-H", "--header", "-u", "-A",
                                           "-e", "-w", "-m", "-d", "--data", "--output-dir", "-T", "-F", "--form",
                                           "--retry", "--connect-timeout", "--max-time", "--proxy", "-x", "-b", "-c"))
    method = (values.get("X") or values.get("request") or "").upper()
    uploads = flags & {"d", "T", "F", "json", "form", "upload-file", "data", "data-raw", "data-binary",
                       "data-urlencode", "data-ascii"} or any(a.startswith("-d") and len(a) > 2 for a in args)
    if name in ("wget",):
        uploads = flags & {"post-data", "post-file", "body-data", "body-file"} or values.get("method", "GET").upper() not in ("GET", "HEAD")
    elif method not in ("", "GET", "HEAD"):
        uploads = True
    hosts = [host_of(o) for o in ops if "." in o or "/" in o or o in LOOPBACK]
    allowed = set(an.cfg.get("network_write_hosts", [])) | LOOPBACK
    if uploads and (not hosts or not all(h in allowed for h in hosts if h)):
        an.deny("network-upload", name + " sends data to a remote host (POST/PUT/upload)")
    out = values.get("o") or values.get("output") or values.get("O") if name == "wget" else values.get("o") or values.get("output")
    if out and out != "-":
        an.write_target(out, name + " output file")
    if "O" in flags and name == "curl":
        an.write_target(os.path.join(an.cwd or "/__unknown__", "__download__"), "curl -O output")
    for opt in ("output-dir", "P", "directory-prefix"):
        if values.get(opt):
            an.write_target(values[opt], name + " output folder")
    if "K" in flags or "config" in flags:
        an.soft("curl-config", name + " reads options from a config file")


def rule_gh(an, name, args, ctx):
    flags, ops, values = split_args(args, ("-X", "--method", "-f", "-F", "-H", "--jq", "-q", "--repo", "-R"))
    group = ops[0] if ops else ""
    if group == "api":
        method = (values.get("X") or values.get("method") or "GET").upper()
        if method != "GET" or flags & {"f", "F", "field", "raw-field", "input"}:
            an.deny("outward-action", "gh api call that changes remote state")
        return
    mutating = {"create", "delete", "merge", "close", "reopen", "edit", "comment", "review", "release", "publish",
                "transfer", "archive", "rename", "fork", "sync", "upload", "set", "remove", "add", "run", "rerun",
                "cancel", "disable", "enable", "deploy", "login", "logout", "token", "install", "ready", "lock",
                "unlock", "pin", "unpin", "develop", "import", "refresh", "setup-git"}
    if group in ("secret", "ssh-key", "gpg-key", "auth", "codespace", "ruleset", "variable", "extension", "alias"):
        an.deny("outward-action", "gh " + group + " manages credentials or account settings")
    elif set(ops[1:3]) & mutating or group in mutating:
        an.deny("outward-action", "gh command that publishes or changes remote state: " + " ".join(ops[:3]))


def rule_publish(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    banned = PUBLISH.get(name, set())
    if ops and ops[0] in banned or (name in ("npm", "pnpm", "yarn") and ops[:2] in (["config", "set"], ["config", "delete"])):
        an.deny("outward-action", name + " " + " ".join(ops[:2]) + " publishes, logs in or changes credentials")
    if name in ("docker", "podman") and ops:
        joined = " ".join(args)
        if ops[0] in ("system", "volume", "network", "image", "container") and re.search(r"\b(prune|rm|remove)\b", joined):
            an.deny("docker-prune", name + " prune/remove can destroy images, volumes or containers")
        if ops[0] == "run" and re.search(r"(--privileged|\s-v\s*/(:|\s)|--volume[= ]/(:|\s)|\s-v\s*~?/?:|--pid[= ]host|"
                                         r"--net(work)?[= ]host|docker\.sock)", " " + joined + " "):
            an.deny("docker-privileged", "docker run with host-level access")


def rule_cloud(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    words = [w for w in ops[:4]]
    if name in ("terraform", "tofu"):
        if words[:1] in (["plan"], ["validate"], ["fmt"], ["show"], ["version"], ["init"], ["output"]) or not words:
            return
    elif any(w in READ_ONLY_VERBS or w.startswith(("list-", "get-", "describe-")) for w in words):
        if not any(re.search(r"(delete|destroy|remove|terminate|drop|apply|deploy|publish|put|update|create|run|exec|stop|"
                             r"rm|push|patch|scale|rollback|restart)", w) for w in words):
            return
    an.deny("outward-action", name + " " + " ".join(words) + ": cloud or cluster change (read-only verbs are allowed)")


def rule_database(an, name, args, ctx):
    text = " ".join(args) + " " + (ctx.stdin_text or "")
    if SQL_BAD.search(text) or DB_BAD.search(text):
        an.deny("database-destruction", name + " statement that drops, truncates or deletes without WHERE")
    if ctx.piped_in and ctx.stdin_text is None:
        an.soft("database-stdin", name + " reads statements piped from another command")


# -- git ------------------------------------------------------------------------------------------------------

def rule_git(an, name, args, ctx):
    i, cfg_flags = 0, []
    while i < len(args) and args[i].startswith("-"):
        a = args[i]
        if a == "-C" or a == "--namespace" or a == "--exec-path":
            if a == "-C" and i + 1 < len(args):
                an.note_git_dir(args[i + 1])
            i += 2
        elif a == "-c":
            cfg_flags.append(args[i + 1] if i + 1 < len(args) else "")
            i += 2
        elif a.startswith("-c") and len(a) > 2:
            cfg_flags.append(a[2:])
            i += 1
        elif a.startswith("--config-env"):
            if "=" in a:
                cfg_flags.append(a.split("=", 1)[1])
                i += 1
            else:
                cfg_flags.append(args[i + 1] if i + 1 < len(args) else "")
                i += 2
        else:
            if a.startswith("--git-dir=") or a.startswith("--work-tree="):
                an.soft("git-dir", "git run against another git directory or work tree")
            i += 1
    for c in cfg_flags:
        if re.match(r"(alias\.|core\.(hookspath|sshcommand|fsmonitor|pager|editor)|protocol\.|credential\.|"
                    r"url\.|http\.|diff\..*\.(command|textconv))", c, re.I):
            an.deny("git-config-exec", "git -c " + c.split("=")[0] + " can run arbitrary programs")
    rest = args[i:]
    if not rest:
        return
    sub, subargs = rest[0], rest[1:]
    if UNK in sub:
        an.soft("git-dynamic", "the git subcommand is built at run time")
        return
    flags, ops, values = split_args(subargs, ("-m", "-b", "-B", "--format", "-n", "--author", "--date"))
    joined = " ".join(subargs)
    if sub in ("commit", "push", "merge", "rebase", "am", "cherry-pick") and ("no-verify" in flags or "n" in flags and sub == "commit"):
        an.deny("git-no-verify", "git " + sub + " --no-verify skips the hooks")
    if sub == "push":
        refspecs = [o for o in ops[1:]]
        forced = flags & {"f", "force", "force-with-lease", "mirror", "delete", "d", "prune", "force-if-includes"} \
            or any(r.startswith(("+", ":")) for r in refspecs) or re.search(r"--force-with-lease=", joined)
        if forced:
            an.deny("git-force-push", "force push, delete or mirror push can destroy remote history")
        elif not an.cfg.get("allow_git_push"):
            an.deny("git-push", "git push publishes work; set allow_git_push in the configuration to allow it")
    elif sub == "reset" and flags & {"hard", "merge", "keep"}:
        an.deny("git-reset-hard", "git reset --hard discards uncommitted work")
    elif sub == "clean" and flags & {"f", "force"}:
        an.deny("git-clean", "git clean -f deletes untracked files for good")
    elif sub == "checkout" and (flags & {"f", "force"} or {".", ":/", "*", ":(top)"} & set(ops)):
        an.deny("git-discard", "git checkout that discards the whole working tree")
    elif sub == "restore" and not flags & {"staged", "S"} and {".", ":/", "*", ":(top)"} & set(ops):
        an.deny("git-discard", "git restore of the whole working tree")
    elif sub == "switch" and flags & {"f", "force", "discard-changes"}:
        an.deny("git-discard", "git switch --discard-changes drops local work")
    elif sub == "branch" and (flags & {"D"} or ("d" in flags and "f" in flags) or ("delete" in flags and "force" in flags)):
        an.deny("git-branch-delete", "forced branch deletion")
    elif sub == "stash" and ops[:1] and ops[0] in ("drop", "clear"):
        an.deny("git-stash-drop", "git stash drop/clear loses saved work")
    elif sub in ("filter-branch", "filter-repo", "replace", "update-ref") and (sub != "update-ref" or "d" in flags):
        an.deny("git-rewrite", "git " + sub + " rewrites or deletes history")
    elif sub == "reflog" and ops[:1] and ops[0] in ("expire", "delete"):
        an.deny("git-rewrite", "git reflog " + ops[0] + " removes the safety net")
    elif sub in ("gc", "prune") and re.search(r"prune(=now|=all)?|now", joined):
        an.deny("git-rewrite", "git " + sub + " --prune=now removes unreachable objects")
    elif sub == "rm" and flags & {"r", "f"} and {".", "*", ":/"} & set(ops):
        an.deny("git-rm-all", "git rm of the whole tree")
    elif sub == "worktree" and ops[:1] == ["remove"] and flags & {"f", "force"}:
        an.deny("git-discard", "forced worktree removal")
    elif sub == "config" and (flags & {"global", "system"} or re.search(r"(hookspath|credential|sshcommand)", joined, re.I)):
        if not flags & {"get", "list", "l", "get-all", "get-regexp"}:
            an.deny("git-config", "git config that changes global settings, credentials or hooks")
    elif sub == "clone" and len(ops) >= 2:
        an.write_target(ops[-1], "git clone destination")
    elif sub == "submodule" and ops[:1] == ["deinit"]:
        an.deny("git-discard", "git submodule deinit")
    elif sub in ("hash-object", "fast-import") and "w" in flags:
        an.soft("git-plumbing", "git plumbing writes objects directly")


# -- misc ---------------------------------------------------------------------------------------------------

def rule_system(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    first = ops[0] if ops else ""
    joined = " ".join(args)
    if name == "security":
        if first in ("find-generic-password", "find-internet-password", "dump-keychain", "export", "import",
                     "delete-generic-password", "delete-internet-password", "add-generic-password", "unlock-keychain",
                     "find-certificate", "find-identity", "set-key-partition-list", "delete-keychain"):
            an.deny("keychain", "macOS keychain access")
    elif name == "diskutil":
        if first in ("list", "info", "") or first.startswith("apfs") and ops[1:2] == ["list"]:
            return
        an.deny("disk-admin", "diskutil " + first + " can erase or modify volumes")
    elif name == "defaults":
        if first in ("write", "delete", "import", "rename"):
            an.deny("system-settings", "defaults " + first + " changes system or application settings")
    elif name == "tmutil":
        if first in ("delete", "deletelocalsnapshots", "disable", "disablelocal", "removedestination", "thinlocalsnapshots"):
            an.deny("backup-destruction", "tmutil " + first + " removes backups")
    elif name in ("launchctl", "systemctl", "service"):
        if first not in ("list", "status", "print", "show", "is-active", "is-enabled", "list-units", "blame", "version"):
            an.deny("services", name + " " + first + " starts, stops or installs system services")
    elif name == "crontab":
        if "l" not in flags:
            an.deny("scheduled-jobs", "crontab edits scheduled jobs")
    elif name == "kill":
        if re.search(r"(^|\s)-?(1|0)(\s|$)", " ".join(ops)) and flags & {"9", "KILL", "s", "TERM"} or "-1" in args:
            an.deny("kill-all", "kill of init or of all processes")
    elif name == "chmod":
        pass


def rule_env_dump(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    if name in ("env", "printenv"):
        ops = [o for o in ops if "=" not in o] if name == "env" else ops
        if not ops:
            an.deny("env-dump", name + " without a command dumps every environment variable (secrets included); "
                    "use printenv NAME or echo $NAME for a variable that is not a secret")
            return
        if name == "printenv" and any(re.search(r"(KEY|TOKEN|SECRET|PASS|CRED|PRIVATE)", o, re.I) for o in ops):
            an.deny("env-dump", "printenv of a secret-looking variable")
    elif name in ("export", "declare", "typeset", "readonly", "local"):
        if flags & {"p", "x"} and not any("=" in o for o in ops) and not ops:
            an.deny("env-dump", name + " -p dumps the environment")
    elif name in ("set", "compgen") and not args:
        an.deny("env-dump", name + " without arguments dumps shell variables")


def rule_cd(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    target = ops[0] if ops else "~"
    if name != "cd":
        an.cwd = None
        return
    an.cwd = None if target == "-" else an.resolve(target) if an.resolve(target) else None


def rule_eval(an, name, args, ctx):
    joined = " ".join(args)
    if UNK in joined:
        an.soft("dynamic-code", "eval of code built at run time")
    else:
        an.analyze_text(joined)


def rule_python_pip(an, name, args, ctx):
    flags, ops, _ = split_args(args)
    if ops[:1] == ["uninstall"] or ops[:2] == ["config", "set"]:
        an.deny("outward-action", name + " " + " ".join(ops[:2]))


def rule_open(an, name, args, ctx):
    if name == "open" and any(re.match(r"^[a-z]+://", a) and host_of(a) not in LOOPBACK for a in args):
        an.soft("open-url", "open launches an external URL")
    if name == "open" and any(a.endswith((".command", ".sh", ".app", ".pkg", ".dmg", ".terminal")) for a in args):
        an.deny("open-executable", "open of an executable or installer")


RULES = {
    "rm": rule_rm, "rmdir": rule_rm, "unlink": rule_rm, "shred": rule_rm,
    "cp": rule_writer_last, "install": rule_writer_last, "ln": rule_writer_last, "rsync": rule_writer_last,
    "mv": rule_mv,
    "tee": rule_all_written, "touch": rule_all_written, "mkdir": rule_all_written, "truncate": rule_all_written,
    "chmod": rule_all_written, "chown": rule_all_written, "chgrp": rule_all_written, "mkfifo": rule_all_written,
    "sed": rule_sed, "gsed": rule_sed, "dd": rule_dd, "find": rule_find, "gfind": rule_find,
    "xargs": rule_xargs, "curl": rule_curl, "wget": rule_curl, "gh": rule_gh, "git": rule_git,
    "source": rule_source, ".": rule_source, "eval": rule_eval, "cd": rule_cd, "pushd": rule_cd, "popd": rule_cd,
    "env": rule_env_dump, "printenv": rule_env_dump, "export": rule_env_dump, "declare": rule_env_dump,
    "typeset": rule_env_dump, "set": rule_env_dump, "compgen": rule_env_dump,
    "security": rule_system, "diskutil": rule_system, "defaults": rule_system, "tmutil": rule_system,
    "launchctl": rule_system, "systemctl": rule_system, "service": rule_system, "crontab": rule_system,
    "kill": rule_system, "open": rule_open,
    "psql": rule_database, "mysql": rule_database, "mariadb": rule_database, "sqlite3": rule_database,
    "mongosh": rule_database, "mongo": rule_database, "redis-cli": rule_database, "duckdb": rule_database,
    "clickhouse-client": rule_database, "dropdb": rule_database, "dropuser": rule_database,
    "mysqladmin": rule_database, "prisma": rule_database, "rails": rule_database, "rake": rule_database,
    "alembic": rule_database, "knex": rule_database, "sequelize": rule_database, "flask": rule_database,
    "perl": rule_perl, "tar": rule_archive, "unzip": rule_archive, "make": rule_archive, "gmake": rule_archive,
    "ditto": rule_writer_last, "zip": rule_archive,
}
for _n in SHELLS:
    RULES[_n] = rule_shell
for _n in list(INLINE_FLAGS) + list(OTHER_INTERPS):
    RULES.setdefault(_n, rule_interpreter)
for _n in PUBLISH:
    RULES.setdefault(_n, rule_publish)
for _n in CLOUD_CLIS:
    RULES[_n] = rule_cloud
for _n in ("pip", "pip3"):
    RULES[_n] = rule_python_pip

READERS = {"cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed", "gsed", "xxd",
           "hexdump", "od", "base64", "strings", "tac", "nl", "cut", "sort", "uniq", "wc", "file", "cp", "mv", "scp",
           "tar", "zip", "gzip", "gunzip", "bzip2", "xz", "source", ".", "diff", "cmp", "jq", "yq", "tee", "bat", "open",
           "ditto", "rsync", "install", "ln", "openssl", "gpg", "paste", "column", "fold", "rev", "split", "shasum",
           "md5", "md5sum", "sha256sum", "xargs"}
READ_ONLY_PATH_COMMANDS = {"echo", "printf", "ls", "stat", "test", "[", "[[", "which", "type", "basename", "dirname",
                           "realpath", "true", "false", "sleep", "cd", "pwd", "command"}
