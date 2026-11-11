"""Shared test helpers. The tests only call the analyzer: no command is ever executed, and every file lives in a
throw-away folder (never in a real ~/.claude)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

KIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kit")
sys.path.insert(0, KIT)

import guard_bash  # noqa: E402


class GuardCase(unittest.TestCase):
    """A fresh project folder and home folder per test (home is outside the allowed roots, like a real one)."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="nsg-test-"))
        self.project = os.path.join(self.root, "proj")
        self.home = os.path.join(self.root, "home")
        os.makedirs(self.project)
        self.scratch = os.path.join(self.root, "scratch")
        os.makedirs(self.home)
        os.makedirs(self.scratch)
        self.addCleanup(shutil.rmtree, self.root, True)
        # only the project and the scratch folder are allowed roots, so the home folder counts as "outside" wherever
        # the temporary folder of this machine is
        self.write_file(".nightshift/guardrails.json", json.dumps({"allow_temp_dirs": False,
                                                                   "extra_allowed_roots": [self.scratch]}))

    def env(self, **extra):
        values = {"HOME": self.home, "CLAUDE_PROJECT_DIR": self.project}
        values.update(extra)
        return values

    def payload(self, command, tool="Bash", **tool_input):
        data = dict(tool_input)
        if tool == "Bash":
            data["command"] = command
        return json.dumps({"tool_name": tool, "tool_input": data, "cwd": self.project, "hook_event_name": "PreToolUse"})

    def guard(self, command, tool="Bash", env=None, **tool_input):
        command = command.replace("{tmp}", self.scratch)
        return guard_bash.main(self.payload(command, tool, **tool_input), env or self.env())

    def blocked(self, command, **kw):
        code, _, err = self.guard(command, **kw)
        return code == 2, err

    def write_file(self, relative, text, base=None):
        path = os.path.join(base or self.project, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path
