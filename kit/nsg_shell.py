"""Night Shift Guardrails - minimal shell parser (standard library only).

It turns a shell command line into simple commands whose words are already unquoted and expanded as far as it is
safe to do so. Anything it cannot resolve becomes the marker UNK so that the rules can refuse instead of guessing.
It never executes anything.
"""
import re

UNK = "\ufffc"  # value we could not resolve (variable, command substitution...), U+FFFC as an escape
DOLLAR = "\ue000"  # a literal "$" (inside single quotes or escaped), private-use char as an escape
MAX_BRACE = 256

REDIR_OPS = ("<<<", "<<-", "<<", "<&", "<>", "<", ">>", ">&", ">|", ">")
VAR_RE = re.compile(r"\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*)|([0-9@*#?$!\-]))")
ANSI_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
               "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


class Unparseable(Exception):
    """The command uses a construct this parser does not understand."""


class Word:
    __slots__ = ("parts", "subs", "procsub", "touched")

    def __init__(self):
        self.parts = []      # [text, quoted]
        self.subs = []       # command strings found in $(...), backticks, <(...)
        self.procsub = False
        self.touched = False  # a quote was seen (so an empty word still counts)

    def add(self, text, quoted):
        if not text:
            return
        if self.parts and self.parts[-1][1] == quoted:
            self.parts[-1][0] += text
        else:
            self.parts.append([text, quoted])

    @property
    def raw(self):
        return "".join(p[0] for p in self.parts)

    @property
    def quoted(self):
        return self.touched or any(p[1] for p in self.parts)


class Cmd:
    def __init__(self):
        self.words = []
        self.redirs = []       # {"op", "fd", "target": Word|None, "body", "qdelim"}
        self.op_before = ""
        self.op_after = ""

    def empty(self):
        return not self.words and not self.redirs


def decode_ansi(text):
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c != "\\" or i + 1 >= len(text):
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in ANSI_SIMPLE:
            out.append(ANSI_SIMPLE[nxt])
            i += 2
        elif nxt == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", text[i + 2:])
            out.append(chr(int(m.group(), 16)) if m else "\\x")
            i += 2 + (len(m.group()) if m else 0)
        elif nxt in "01234567":
            m = re.match(r"[0-7]{1,3}", text[i + 1:])
            out.append(chr(int(m.group(), 8)))
            i += 1 + len(m.group())
        elif nxt in "uU":
            width = 4 if nxt == "u" else 8
            m = re.match(r"[0-9a-fA-F]{1,%d}" % width, text[i + 2:])
            out.append(chr(int(m.group(), 16)) if m else "\\" + nxt)
            i += 2 + (len(m.group()) if m else 0)
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out)


def read_balanced(s, i):
    """s[i] is just after '('. Returns (inner, index after the closing ')')."""
    depth, j, n = 1, i, len(s)
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = s.find("'", j + 1)
            if k < 0:
                break
            j = k + 1
            continue
        if c == '"':
            j += 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[i:j], j + 1
        j += 1
    raise Unparseable("unbalanced parenthesis")


def read_braced(s, i):
    """s[i] is just after '${'. Returns (inner, index after '}')."""
    depth, j, n = 1, i, len(s)
    while j < n:
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                return s[i:j], j + 1
        j += 1
    raise Unparseable("unbalanced ${")


def read_backtick(s, i):
    j, n, buf = i, len(s), []
    while j < n:
        if s[j] == "\\" and j + 1 < n and s[j + 1] in "`\\$":
            buf.append(s[j + 1])
            j += 2
            continue
        if s[j] == "`":
            return "".join(buf), j + 1
        buf.append(s[j])
        j += 1
    raise Unparseable("unclosed backtick")


def extract_subs(text):
    """Command substitutions found in free text (heredoc bodies): $(...) and backticks."""
    found, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text.startswith("$((", i):
            _, i = read_balanced(text, i + 2)
        elif text.startswith("$(", i):
            inner, i = read_balanced(text, i + 2)
            found.append(inner)
        elif text[i] == "`":
            inner, i = read_backtick(text, i + 1)
            found.append(inner)
        else:
            i += 1
    return found


class _Tokenizer:
    def __init__(self, s):
        self.s, self.n, self.i = s, len(s), 0
        self.items, self.cur = [], None
        self.want_delim, self.queue = None, []

    # -- word helpers -------------------------------------------------
    def word(self):
        if self.cur is None:
            self.cur = Word()
        return self.cur

    def flush(self):
        if self.cur is None:
            return
        word, self.cur = self.cur, None
        if self.want_delim is not None:
            self.queue.append((self.want_delim, word.raw, word.quoted))
            self.want_delim = None
        self.items.append({"k": "word", "w": word})

    def op(self, value):
        self.flush()
        self.items.append({"k": "op", "v": value})

    # -- bodies of here-documents -------------------------------------
    def read_bodies(self):
        for item, delim, quoted in self.queue:
            strip = item["v"] == "<<-"
            lines = []
            while self.i < self.n:
                j = self.s.find("\n", self.i)
                j = self.n if j < 0 else j
                line = self.s[self.i:j]
                self.i = min(j + 1, self.n)
                probe = line.rstrip("\r")
                if (probe.lstrip("\t") if strip else probe) == delim:
                    break
                lines.append(line)
            item["body"] = "\n".join(lines)
            item["qdelim"] = quoted
        self.queue = []

    # -- quoted pieces --------------------------------------------------
    def read_dq(self):
        w, s, j = self.word(), self.s, self.i + 1
        w.touched = True
        buf = []

        def put(text):
            w.add(text, True)

        while True:
            if j >= self.n:
                raise Unparseable("unclosed double quote")
            c = s[j]
            if c == '"':
                break
            if c == "\\" and j + 1 < self.n:
                nxt = s[j + 1]
                if nxt in '$`"\\':
                    buf.append(DOLLAR if nxt == "$" else nxt)
                    j += 2
                elif nxt == "\n":
                    j += 2
                else:
                    buf.append("\\")
                    j += 1
                continue
            if c == "`":
                put("".join(buf))
                buf = []
                inner, j = read_backtick(s, j + 1)
                w.subs.append(inner)
                put(UNK)
                continue
            if c == "$" and s.startswith("$((", j):
                put("".join(buf))
                buf = []
                _, j = read_balanced(s, j + 2)
                put(UNK)
                continue
            if c == "$" and s.startswith("$(", j):
                put("".join(buf))
                buf = []
                inner, j = read_balanced(s, j + 2)
                w.subs.append(inner)
                put(UNK)
                continue
            if c == "$" and s.startswith("${", j):
                inner, k = read_braced(s, j + 2)
                w.subs.extend(extract_subs(inner))
                buf.append("${" + inner + "}")
                j = k
                continue
            buf.append(c)
            j += 1
        put("".join(buf))
        self.i = j + 1

    def read_dollar(self):
        s, i, w = self.s, self.i, self.word()
        nxt = s[i + 1] if i + 1 < self.n else ""
        if nxt == "'":
            j = i + 2
            while j < self.n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            if j >= self.n:
                raise Unparseable("unclosed $'")
            w.touched = True
            w.add(decode_ansi(s[i + 2:j]).replace("$", DOLLAR), True)
            self.i = j + 1
        elif nxt == '"':
            self.i = i + 1
            self.read_dq()
        elif s.startswith("$((", i):
            _, self.i = read_balanced(s, i + 3)
            w.add(UNK, False)
        elif nxt == "(":
            inner, self.i = read_balanced(s, i + 2)
            w.subs.append(inner)
            w.add(UNK, False)
        elif nxt == "{":
            inner, self.i = read_braced(s, i + 2)
            w.subs.extend(extract_subs(inner))
            w.add("${" + inner + "}", False)
        else:
            w.add("$", False)
            self.i = i + 1

    # -- operators --------------------------------------------------------
    def read_redirect(self, ch):
        s, i = self.s, self.i
        if s.startswith("(", i + 1):  # process substitution <(...) >(...)
            inner, self.i = read_balanced(s, i + 2)
            w = self.word()
            w.subs.append(inner)
            w.procsub = True
            w.add(UNK, False)
            return
        fd = ""
        if self.cur is not None and self.cur.raw.isdigit() and not self.cur.quoted:
            fd, self.cur = self.cur.raw, None
        else:
            self.flush()
        op = next(o for o in REDIR_OPS if s.startswith(o, i) and o[0] == ch)
        item = {"k": "redir", "v": op, "fd": fd, "body": None, "qdelim": False}
        self.items.append(item)
        if op in ("<<", "<<-"):
            self.want_delim = item
        self.i = i + len(op)

    def read_amp(self):
        s, i = self.s, self.i
        for op in ("&>>", "&>"):
            if s.startswith(op, i):
                self.flush()
                self.items.append({"k": "redir", "v": op, "fd": "", "body": None, "qdelim": False})
                self.i = i + len(op)
                return
        two = s[i:i + 2]
        self.op("&&" if two == "&&" else "&")
        self.i = i + len(self.items[-1]["v"])

    def run(self):
        s = self.s
        while self.i < self.n:
            ch = s[self.i]
            if ch in " \t\r":
                self.flush()
                self.i += 1
            elif ch == "\n":
                self.op("\n")
                self.i += 1
                if self.queue:
                    self.read_bodies()
            elif ch == "\\":
                if self.i + 1 < self.n and s[self.i + 1] == "\n":
                    self.i += 2
                    continue
                w = self.word()
                if self.i + 1 < self.n:
                    c = s[self.i + 1]
                    w.add(DOLLAR if c == "$" else c, True)
                self.i += 2
            elif ch == "#" and self.cur is None:
                while self.i < self.n and s[self.i] != "\n":
                    self.i += 1
            elif ch == "'":
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise Unparseable("unclosed single quote")
                w = self.word()
                w.touched = True
                w.add(s[self.i + 1:j].replace("$", DOLLAR), True)
                self.i = j + 1
            elif ch == '"':
                self.read_dq()
            elif ch == "$":
                self.read_dollar()
            elif ch == "`":
                inner, self.i = read_backtick(s, self.i + 1)
                w = self.word()
                w.subs.append(inner)
                w.add(UNK, False)
            elif ch == ";":
                self.op(";")
                self.i += 1
                if self.i < self.n and s[self.i] in ";&":
                    self.i += 1
            elif ch == "&":
                self.read_amp()
            elif ch == "|":
                two = s[self.i:self.i + 2]
                value = two if two in ("||", "|&") else "|"
                self.op(value)
                self.i += len(value)
            elif ch in "<>":
                self.read_redirect(ch)
            elif ch == "(":
                if self.cur is not None:
                    raise Unparseable("function definition or extended glob")
                self.op("(")
                self.i += 1
            elif ch == ")":
                self.op(")")
                self.i += 1
            else:
                self.word().add(ch, False)
                self.i += 1
        self.flush()
        for item, _, quoted in self.queue:
            item["body"], item["qdelim"] = "", quoted
        return self.items


def tokenize(s):
    return _Tokenizer(s).run()


def parse(s):
    """Command line -> list of Cmd. Raises Unparseable."""
    cmds, cur, pending, depth, op = [], Cmd(), None, 0, ""

    def push(next_op):
        nonlocal cur, op
        if not cur.empty():
            cur.op_before, cur.op_after = op, next_op
            cmds.append(cur)
        cur = Cmd()
        op = next_op

    for item in tokenize(s):
        kind = item["k"]
        if kind == "word":
            if pending is not None:
                pending["target"] = item["w"]
                pending = None
            else:
                cur.words.append(item["w"])
        elif kind == "redir":
            pending = {"op": item["v"], "fd": item["fd"], "target": None, "body": item["body"],
                       "qdelim": item["qdelim"], "item": item}
            cur.redirs.append(pending)
        else:
            value = item["v"]
            if value == "(":
                depth += 1
            elif value == ")":
                depth -= 1
                if depth < 0:
                    raise Unparseable("unmatched )")
            push(value)
    push("")
    if depth:
        raise Unparseable("unmatched (")
    for c in cmds:  # here-doc bodies are filled when the newline is read: copy them in
        for r in c.redirs:
            r["body"], r["qdelim"] = r["item"]["body"], r["item"]["qdelim"]
    return cmds


# -- expansion ------------------------------------------------------------------------------------------

def brace_expand(text, limit=MAX_BRACE):
    start = text.find("{")
    while start >= 0:
        depth, j, commas = 0, start, []
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif text[j] == "," and depth == 1:
                commas.append(j)
            j += 1
        if depth == 0 and j < len(text):
            body = text[start + 1:j]
            pre, post = text[:start], text[j + 1:]
            if commas:
                cuts = [start] + commas + [j]
                options = [text[cuts[k] + 1:cuts[k + 1]] for k in range(len(cuts) - 1)]
            else:
                m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)", body)
                if not m:
                    start = text.find("{", start + 1)
                    continue
                a, b = int(m.group(1)), int(m.group(2))
                step = 1 if b >= a else -1
                if abs(b - a) + 1 > limit:
                    raise Unparseable("brace range larger than %d items" % limit)
                options = [str(v) for v in range(a, b + step, step)]
            if len(options) > limit:
                raise Unparseable("brace expansion larger than %d items" % limit)
            out = []
            for opt in options:
                out.extend(brace_expand(pre + opt + post, limit))
                if len(out) > limit:
                    raise Unparseable("brace expansion larger than %d items" % limit)
            return out
        start = text.find("{", start + 1)
    return [text]


def _value_of(inner, lookup, refs):
    """Value of ${...}; None when unknown."""
    m = re.fullmatch(r"([A-Za-z_]\w*)(?::?[-=](.*))?", inner, re.S)
    if not m:
        return None
    refs.append(m.group(1))
    value = lookup(m.group(1))
    if value:
        return value
    if m.group(2) is not None:
        return m.group(2) if value is None or value == "" else value
    return value


def expand_word(word, lookup):
    """Word -> (list of strings, names of the variables referenced). Unknown values become UNK."""
    outs, refs = [""], []

    def literal(text):
        outs[-1] += text

    def value(v, quoted):
        if quoted or not re.search(r"\s", v):
            outs[-1] += v
            return
        pieces = re.split(r"\s+", v)
        outs[-1] += pieces[0]
        outs.extend(pieces[1:])

    for text, quoted in word.parts:
        pos = 0
        for m in VAR_RE.finditer(text):
            literal(text[pos:m.start()])
            pos = m.end()
            if m.group(1) is not None:
                v = _value_of(m.group(1), lookup, refs)
            elif m.group(2) is not None:
                refs.append(m.group(2))
                v = lookup(m.group(2))
            else:
                v = None
            value(UNK if v is None else v, quoted)
        literal(text[pos:])
    if any(not q and "{" in t and ("," in t or ".." in t) for t, q in word.parts):
        expanded = []
        for w in outs:
            expanded.extend(brace_expand(w))
        outs = expanded
    keep = word.quoted
    result = [w.replace(DOLLAR, "$") for w in outs if w or keep]
    return result, refs
