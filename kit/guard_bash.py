#!/usr/bin/env python3
"""Night Shift Guardrails - guard_bash.py

PreToolUse hook for unattended AI coding agents (agent CLIs with PreToolUse hooks). It reads the hook JSON on stdin and
can only REFUSE a tool call (exit code 2 + reason on stderr). It never grants a permission and never executes the command
it inspects. Anything it cannot analyse is refused in `strict` mode (default); `permissive` mode only allows the
"cannot analyse" cases. It fails closed: a crash, an invalid input or a timeout all produce a refusal.

A protection layer, not a sandbox: see README.md for the limits.
"""
import json
import os
import re
import signal
import sys
from collections import namedtuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nsg_audit  # noqa: E402
import nsg_rules  # noqa: E402
from nsg_paths import SECRET_VAR_RE, SYSTEM_BIN_DIRS, PathPolicy  # noqa: E402
from nsg_shell import UNK, Unparseable, expand_word, extract_subs, parse  # noqa: E402

VERSION = "1.0.0"
Finding = namedtuple("Finding", "rule reason soft")
_UNSET = object()
DEFAULTS = {"mode": "strict", "deadline_seconds": 8, "allow_git_push": False, "extra_allowed_roots": [],
            "extra_protected": [], "allow_temp_dirs": True, "network_write_hosts": [], "audit": True, "max_command_chars": 200_000}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!"}
UNSUPPORTED = {"case", "esac", "function", "coproc", "select"}
WRITE_REDIRS = {">", ">>", ">|", "&>", "&>>", "<>"}
ENV_INJECTION = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "BASH_ENV", "ENV",
                 "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "PYTHONSTARTUP", "NODE_OPTIONS",
                 "PYTHONPATH", "GIT_ASKPASS", "SSH_ASKPASS"}
GIT_ENV_RE = re.compile(r"^GIT_(CONFIG|SSH|PROXY|EXTERNAL|ASKPASS|ALLOW|EXEC|TEMPLATE|PAGER|EDITOR|SEQUENCE|DIR$|WORK_TREE)",
                        re.I)
ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)(\+?)=")
MAX_DEPTH = 4
MAX_SCRIPT_BYTES = 64_000
WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{.*:\s*\|\s*:")


class Analyzer:
    def __init__(self, cfg, policy, cwd, findings=None, variables=None, depth=0, written=None):
        self.cfg, self.policy, self.cwd, self.depth = cfg, policy, cwd, depth
        self.findings = findings if findings is not None else []
        self.vars = dict(variables or {})
        self.written = written if written is not None else {}
        self._cwd_before_wrapper = _UNSET

    # -- findings -------------------------------------------------------------
    def deny(self, rule, reason):
        self.findings.append(Finding(rule, reason, False))

    def soft(self, rule, reason):
        self.findings.append(Finding(rule, reason, True))

    # -- paths ---------------------------------------------------------------------
    def resolve(self, text):
        return self.policy.resolve(text, self.cwd)

    def write_target(self, text, what):
        path = self.resolve(text)
        if path is None:
            self.soft("unresolved-path", "%s: the path cannot be resolved (%s)" % (what, text.replace(UNK, "?")))
            return
        reason = self.policy.check_write(path)
        if reason:
            self.deny("protected-path", "%s %s: %s" % (what, path, reason))

    def delete_target(self, text):
        path = self.resolve(text)
        if path is None:
            self.soft("unresolved-path", "deletion target cannot be resolved (%s)" % text.replace(UNK, "?"))
            return
        base = os.path.basename(text.rstrip("/"))
        parent = os.path.dirname(path)
        if base and re.fullmatch(r"[*?.]+", base) and base not in (".", "..") and (
                self.policy.is_ancestor_or_equal_of_project(parent) or not self.policy.inside_roots(parent)):
            self.deny("rm-wildcard", "bare wildcard %s would delete everything in %s" % (base, parent))
            return
        if self.policy.is_ancestor_or_equal_of_project(path) or self.policy.is_home_or_parent(path):
            self.deny("rm-project", "%s is the project folder, one of its parents or the home folder" % path)
            return
        self.write_target(text, "deletion of")

    def note_git_dir(self, arg):
        path = self.resolve(arg)
        if path is None or not self.policy.inside_roots(path):
            self.soft("git-dir", "git -C points outside the project")

    # -- variables -----------------------------------------------------------------------
    def lookup(self, name):
        if name in self.vars:
            return self.vars[name]
        known = {"IFS": " \t\n", "HOME": self.policy.home, "PWD": self.cwd, "USER": os.environ.get("USER"),
                 "TMPDIR": os.environ.get("TMPDIR", "/tmp"), "CLAUDE_PROJECT_DIR": self.policy.project}
        return known.get(name)

    def set_var(self, name, value):
        if name in self.vars and self.vars[name] != value:
            self.vars[name] = UNK
        else:
            self.vars[name] = value

    # -- recursion -------------------------------------------------------------------------
    def child(self):
        return Analyzer(self.cfg, self.policy, self.cwd, self.findings, self.vars, self.depth + 1, self.written)

    def analyze_text(self, text):
        if self.depth >= MAX_DEPTH:
            self.soft("too-deep", "nested shell code is too deep to analyse")
            return
        self.child().run(text)

    def analyze_file(self, word, what):
        path = self.resolve(word)
        if path is None:
            self.soft("dynamic-code", "%s %s cannot be located" % (what, word.replace(UNK, "?")))
            return
        text = self.written.get(path)
        if text is None:
            try:
                if not os.path.isfile(path) or os.path.getsize(path) > MAX_SCRIPT_BYTES:
                    return
                with open(path, "rb") as fh:
                    data = fh.read()
                if b"\0" in data:
                    return
                text = data.decode("utf-8", "replace")
            except OSError:
                return
        self.analyze_text(text)

    def analyze_executable(self, word):
        path = self.resolve(word)
        if path is None:
            self.soft("dynamic-command", "program path cannot be resolved: %s" % word.replace(UNK, "?"))
            return
        text = self.written.get(path)
        if text is None and os.path.isfile(path) and os.path.getsize(path) <= MAX_SCRIPT_BYTES:
            try:
                with open(path, "rb") as fh:
                    head = fh.read(MAX_SCRIPT_BYTES)
                first = head.split(b"\n", 1)[0]
                if first.startswith(b"#!") and re.search(rb"(ba|z|da|k)?sh\b", first):
                    text = head.decode("utf-8", "replace")
            except OSError:
                return
        if text is not None:
            self.analyze_text(text)

    # -- execution of one parsed line ----------------------------------------------------------------
    def run(self, text):
        if FORK_BOMB.search(text):
            self.deny("fork-bomb", "fork bomb pattern")
            return
        try:
            cmds = parse(text)
        except Unparseable as err:
            self.soft("unparseable", "cannot analyse this command (%s)" % err)
            return
        for cmd in cmds:
            try:
                self.exec_cmd(cmd)
            except Unparseable as err:
                self.soft("unparseable", "cannot analyse this command (%s)" % err)

    def exec_cmd(self, cmd):
        words = list(cmd.words)
        for w in words + [r["target"] for r in cmd.redirs if r["target"]]:
            for sub in w.subs:
                self.analyze_text(sub)
        for r in cmd.redirs:
            if r["body"] and not r["qdelim"] and r["op"] in ("<<", "<<-"):
                for sub in extract_subs(r["body"]):
                    self.analyze_text(sub)
        while words and not words[0].quoted and words[0].raw in KEYWORDS:
            words.pop(0)
        if words and not words[0].quoted and words[0].raw in UNSUPPORTED:
            self.soft("unsupported-syntax", "%s constructs are not analysed" % words[0].raw)
            return
        if words and not words[0].quoted and words[0].raw == "for":
            if len(words) > 1:
                self.vars[words[1].raw] = UNK
            return
        assignments = []
        while words and ASSIGN_RE.match(words[0].raw) and not words[0].parts[0][1]:
            assignments.append(words.pop(0))
        stdin_text = self.redirects(cmd)
        argv, refs = [], []
        for w in words:
            outs, found = expand_word(w, self.lookup)
            argv.extend(outs)
            refs.extend(found)
        if not argv:
            for a in assignments:
                m = ASSIGN_RE.match(a.raw)
                outs, _ = expand_word(_strip_assignment(a), self.lookup)
                self.set_var(m.group(1), " ".join(outs))
            return
        for a in assignments:
            name = ASSIGN_RE.match(a.raw).group(1)
            if name in ENV_INJECTION or GIT_ENV_RE.match(name):
                self.deny("env-injection", "%s changes how programs load or run" % name)
        ctx = nsg_rules.Ctx(cmd.op_before in ("|", "|&"), cmd.op_after in ("|", "|&"), stdin_text,
                            any(w.procsub for w in cmd.words))
        if argv[0].split("/")[-1] in ("echo", "printf", "cat", "tee", "print") and any(
                SECRET_VAR_RE.search(r) for r in refs):
            self.deny("secret-env", "prints a variable that looks like a secret: %s" % ", ".join(
                r for r in refs if SECRET_VAR_RE.search(r)))
        if argv[0].split("/")[-1] in ("export", "declare", "local", "readonly", "typeset"):
            for a in argv[1:]:
                if ASSIGN_RE.match(a):
                    name, _, value = a.partition("=")
                    self.set_var(name.rstrip("+"), value)
        self.record_written(cmd, argv, stdin_text)
        self.run_argv(argv, ctx)

    def redirects(self, cmd):
        stdin_text = None
        for r in cmd.redirs:
            target = r["target"]
            outs = expand_word(target, self.lookup)[0] if target is not None else []
            text = " ".join(outs)
            if r["op"] == "<<<":
                stdin_text = text
            elif r["op"] in ("<<", "<<-"):
                stdin_text = r["body"] or ""
            elif r["op"] in WRITE_REDIRS or r["op"] == ">&":
                if r["op"] == ">&" and (text.isdigit() or text == "-"):
                    continue
                if target is None or not outs:
                    continue
                self.write_target(text, "redirection to")
            elif r["op"] == "<" and target is not None and outs:
                path = self.resolve(text)
                if path and self.policy.is_secret(path):
                    self.deny("secret-access", "reads %s, which looks like a secret or credential file" % path)
        return stdin_text

    def record_written(self, cmd, argv, stdin_text):
        for r in cmd.redirs:
            if r["op"] in (">", ">>", ">|") and r["target"] is not None:
                path = self.resolve(" ".join(expand_word(r["target"], self.lookup)[0]))
                name = argv[0].split("/")[-1]
                content = stdin_text if stdin_text is not None else " ".join(argv[1:]) if name in ("echo", "printf") else None
                if path and content is not None:
                    self.written[path] = (self.written.get(path, "") + "\n" if r["op"] == ">>" else "") + content

    def run_argv(self, argv, ctx):
        try:
            self._run_argv(argv, ctx)
        finally:
            if self._cwd_before_wrapper is not _UNSET:
                self.cwd, self._cwd_before_wrapper = self._cwd_before_wrapper, _UNSET

    def _run_argv(self, argv, ctx):
        for _ in range(12):
            if not argv:
                return
            word = argv[0]
            if UNK in word:
                self.soft("dynamic-command", "the command name is built at run time")
                return
            directory = os.path.dirname(word)
            if directory and directory not in SYSTEM_BIN_DIRS:
                self.analyze_executable(word)
                self.check_secret_args(os.path.basename(word), argv[1:])
                return
            name = os.path.basename(word)
            inner = self.unwrap(name, argv[1:])
            if inner is False:
                return
            if inner is not None:
                argv = inner
                continue
            break
        else:
            self.soft("too-deep", "too many command wrappers")
            return
        name = os.path.basename(argv[0])
        args = argv[1:]
        if name.startswith(("mkfs", "newfs")):
            self.deny("disk-admin", "disk formatting")
            return
        reason = nsg_rules.NEVER.get(name)
        if reason:
            self.deny("never-allowed", "%s (%s)" % (name, reason))
            return
        self.check_secret_args(name, args)
        rule = nsg_rules.RULES.get(nsg_rules.interp_family(name))
        if rule is not None:
            rule(self, name, args, ctx)

    def check_secret_args(self, name, args):
        if name in nsg_rules.READ_ONLY_PATH_COMMANDS or (name == "git" and "check-ignore" in args):
            return
        for arg in args:
            if arg.startswith("-") and "=" not in arg:
                continue
            if UNK in arg and name in nsg_rules.READERS and not arg.startswith("-"):
                self.soft("unresolved-path", "%s reads a path that is built at run time" % name)
            for cand in self.policy.candidates(arg):
                path = self.resolve(cand) if cand and UNK not in cand else None
                if path and self.policy.is_secret(path):
                    self.deny("secret-access", "%s touches %s, which looks like a secret or credential file" % (name, path))
                    return
                if cand and self.policy.glob_hits_secret(cand, self.cwd):
                    self.deny("secret-access", "%s: the pattern %s can match a secret or credential file" % (name, cand))
                    return

    def change_dir_for_wrapper(self, target):
        if self._cwd_before_wrapper is _UNSET:
            self._cwd_before_wrapper = self.cwd
        self.cwd = self.resolve(target)

    def unwrap(self, name, args):
        """Remove a wrapper command. Returns the inner argv, None if `name` is not a wrapper, False when nothing runs."""
        skip_value = {"env": {"-u", "-C", "-S", "--unset", "--chdir"}, "nice": {"-n"}, "ionice": {"-c", "-n", "-p"},
                      "stdbuf": {"-i", "-o", "-e"}, "caffeinate": {"-t", "-w"}, "timeout": {"-s", "-k", "--signal",
                                                                                      "--kill-after"},
                      "exec": {"-a"}, "watch": {"-n", "-d"}, "setsid": set(), "time": {"-f", "-o"}}
        if name not in ("env", "nice", "ionice", "nohup", "time", "setsid", "stdbuf", "caffeinate", "timeout", "command",
                        "builtin", "exec", "unbuffer", "watch", "busybox", "chronic", "sandbox-exec"):
            return None
        if name == "sandbox-exec":
            self.deny("never-allowed", "sandbox-exec runs a program under a custom profile")
            return False
        i, values = 0, skip_value.get(name, set())
        while i < len(args):
            a = args[i]
            if a == "--":
                i += 1
                break
            if name == "env" and ASSIGN_RE.match(a):
                if a.split("=")[0] in ENV_INJECTION or GIT_ENV_RE.match(a.split("=")[0]):
                    self.deny("env-injection", "%s changes how programs load or run" % a.split("=")[0])
                i += 1
            elif a.startswith("-") and len(a) > 1:
                if name == "env" and a in ("-C", "--chdir") and i + 1 < len(args):
                    self.change_dir_for_wrapper(args[i + 1])
                elif name == "env" and a.startswith("--chdir="):
                    self.change_dir_for_wrapper(a.split("=", 1)[1])
                if name == "command" and ("v" in a or "V" in a):
                    return False
                if name == "nice" and re.fullmatch(r"-\d+", a):
                    i += 1
                    continue
                i += 2 if a in values else 1
            else:
                break
        rest = args[i:]
        if name == "timeout" and rest:
            rest = rest[1:]
        if name == "env" and not rest:
            nsg_rules.rule_env_dump(self, "env", [], nsg_rules.Ctx())
            return False
        return rest or False


def _strip_assignment(word):
    """Word NAME=value -> Word with only the value (keeps quoting information)."""
    from nsg_shell import Word
    out, skip = Word(), len(ASSIGN_RE.match(word.raw).group(0))
    out.subs, out.touched = word.subs, word.touched
    for text, quoted in word.parts:
        if skip >= len(text):
            skip -= len(text)
            continue
        out.add(text[skip:], quoted)
        skip = 0
    return out


# -- hook entry -----------------------------------------------------------------------------------------------

def load_config(script_dir, project_dir, env):
    cfg = dict(DEFAULTS)
    for path in (os.path.join(script_dir, "guardrails.json"), os.path.join(project_dir, ".nightshift", "guardrails.json"),
                 env.get("NSG_CONFIG", "")):
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            cfg.update({k: v for k, v in data.items() if k in DEFAULTS})
    if cfg["mode"] not in ("strict", "permissive"):
        raise ValueError("mode must be 'strict' or 'permissive'")
    return cfg


def stop_file(script_dir, project_dir, home, env):
    candidates = [env.get("NSG_STOP_FILE", ""), os.path.join(script_dir, "STOP"),
                  os.path.join(project_dir, "STOP"), os.path.join(project_dir, ".nightshift", "STOP"),
                  os.path.join(home, ".nightshift", "STOP")]
    return next((p for p in candidates if p and os.path.lexists(p)), "")


def check_command(command, cfg, policy, cwd):
    if len(command) > cfg["max_command_chars"]:
        return [Finding("too-long", "command is longer than %d characters" % cfg["max_command_chars"], False)]
    analyzer = Analyzer(cfg, policy, cwd)
    analyzer.run(command)
    return [f for f in analyzer.findings if not (f.soft and cfg["mode"] == "permissive")]


def check_file_tool(tool, path_text, policy, cwd):
    path = policy.resolve(path_text, cwd)
    if path is None:
        return [Finding("unresolved-path", "path cannot be resolved: %s" % path_text, True)]
    if tool == "Read":
        return [Finding("secret-access", "reading %s (secret or credential file)" % path, False)] if policy.is_secret(path) else []
    reason = policy.check_write(path)
    return [Finding("protected-path", "%s on %s: %s" % (tool, path, reason), False)] if reason else []


def evaluate(payload, cfg, policy, script_dir, home, env):
    tool, tin = payload.get("tool_name", ""), payload.get("tool_input") or {}
    cwd = payload.get("cwd") or policy.project
    if tool == "Bash":
        command = tin.get("command")
        if not isinstance(command, str) or not command.strip():
            return [Finding("invalid-input", "Bash call without a command string", False)]
        return check_command(command, cfg, policy, cwd)
    if tool in WRITE_TOOLS:
        target = tin.get(WRITE_TOOLS[tool])
        if not isinstance(target, str):
            return [Finding("invalid-input", "%s call without a path" % tool, False)]
        return check_file_tool(tool, target, policy, cwd)
    if tool == "Read" and isinstance(tin.get("file_path"), str):
        return check_file_tool("Read", tin["file_path"], policy, cwd)
    return []


def format_block(tool, findings, script_dir):
    lines = ["Night Shift Guardrails blocked this %s call; nothing was run." % tool]
    for f in findings[:5]:
        lines.append("- [%s] %s" % (f.rule, f.reason))
    lines.append("Do not retry it in another form. Choose a safer way, or leave the task for the human.")
    if os.path.exists(os.path.join(script_dir, "approval_queue.py")):
        lines.append('To ask the human in the morning: python3 "%s" request "<what and why>"'
                     % os.path.join(script_dir, "approval_queue.py"))
    return "\n".join(lines)


class _Deadline(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Deadline()


def main(stdin_text=None, env=None, analyze=evaluate):
    """Returns (exit_code, stdout_text, stderr_text)."""
    env = os.environ if env is None else env
    script_dir = os.path.dirname(os.path.abspath(__file__))
    home = env.get("HOME") or os.path.expanduser("~")
    project = env.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    old_handler = None
    try:
        raw = sys.stdin.read() if stdin_text is None else stdin_text
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("not an object")
        except ValueError:
            return 2, "", "Night Shift Guardrails: invalid hook input (not a JSON object); refusing (fail closed)."
        project = env.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or project
        cfg = load_config(script_dir, project, env)
        stop = stop_file(script_dir, project, home, env)
        if stop:
            reason = "STOP file present (%s): the human stopped this session. Do nothing; wait for the human." % stop
            nsg_audit.audit(project, {"event": "stop", "tool": payload.get("tool_name", ""), "reason": reason})
            out = {"continue": False, "stopReason": reason,
                   "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}}
            return 0, json.dumps(out), reason
        policy = PathPolicy(project, home, cfg["extra_allowed_roots"], cfg["extra_protected"],
                            guard_dirs=(script_dir, os.path.join(project, ".nightshift")),
                            allow_temp=cfg["allow_temp_dirs"])
        if hasattr(signal, "SIGALRM") and cfg["deadline_seconds"] > 0:
            old_handler = signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, float(cfg["deadline_seconds"]))
        findings = analyze(payload, cfg, policy, script_dir, home, env)
    except _Deadline:
        return 2, "", "Night Shift Guardrails: analysis took too long; refusing (fail closed)."
    except BaseException as err:  # noqa: BLE001 - fail closed on any failure
        return 2, "", "Night Shift Guardrails: internal error (%s); refusing (fail closed)." % type(err).__name__
    finally:
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
        if old_handler is not None:
            signal.signal(signal.SIGALRM, old_handler)
    if not findings:
        return 0, "", ""
    tool = payload.get("tool_name", "tool")
    if cfg["audit"]:
        detail = (payload.get("tool_input") or {})
        shown = str(detail.get("command") or detail.get("file_path") or "")
        first = findings[0]
        event = {"event": "block", "tool": tool, "rule": first.rule, "reason": first.reason, "input": shown}
        nsg_audit.audit(project, event)
    return 2, "", format_block(tool, findings, script_dir)


if __name__ == "__main__":
    code, out, err = main()
    if out:
        sys.stdout.write(out + "\n")
    if err:
        sys.stderr.write(err + "\n")
    sys.exit(code)
