# Night Shift Guardrails - free guard

`guard_bash.py`: a PreToolUse hook for unattended AI coding agents (agent CLIs with PreToolUse hooks). It reads each shell
command **before it runs** and refuses the dangerous ones: wrong deletions, secret files, force pushes, pipes into a
shell, uploads, system administration, database destruction, and the usual tricks (quoting, `${IFS}`, brace expansion,
wrappers, `eval`, command substitution, scripts written then run). It also checks Write / Edit / Read paths and has an
emergency **STOP** file.

> **An extra layer of protection, not a sandbox.** It parses commands, it never runs them, and it cannot see inside a
> program the agent writes and then executes. Read the limits in the full README before relying on it.

Pure Python standard library, Python 3.9 or later. This release is verified on Python 3.13.1; other versions
are not revalidated for this archive. No network, no telemetry. Developed and tested on macOS (Linux not tested).
Made with the help of AI (créé avec l'aide de l'IA) by Loupe & Lettres. Independent, not affiliated with or endorsed by any AI vendor.

## Use it

1. Copy `kit/guard_bash.py` and the four `kit/nsg_*.py` files into a folder of your project, for example
   `.claude/nightshift/`.
2. Add a PreToolUse hook to your settings that runs it (matcher `Bash|Write|Edit|MultiEdit|NotebookEdit|Read`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/nightshift/guard_bash.py\" || exit 2",
            "timeout": 10,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

(`onFailure` needs host version 2.1.295 or later; the `|| exit 2` fallback covers a crashed or missing script, but not a host-side timeout on older versions.)

3. Emergency stop: `touch STOP` in the project (or `~/.nightshift/STOP` for all configured projects).
   It takes effect on the next matched call (`Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Read`),
   and does not interrupt an already running process or cover tools outside that matcher. Remove the file to resume.

The hook only ever refuses (normally exit code 2 with the reason on stderr; STOP returns a stop/deny JSON decision).
With the supported host and configuration above, invalid input, a crash, a bad configuration or a timeout refuse
matched calls. Configuration (`strict` / `permissive`, extra roots, protected patterns) is
read from `guardrails.json` next to the script or from `<project>/.nightshift/guardrails.json`.

## Test it

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

120 dangerous and 102 normal commands are fixed in `tests/corpus.py`. They are analysed as strings, never executed.
Tests also run our Python hook and a harmless shell exit-status fallback in disposable folders.

## Limits of the free core

- Interpreter programs written to a file and then run are not inspected. Inline interpreter code uses heuristics.
- Recursive searches can read unnamed secret files. Only explicit paths and supported patterns are checked.
- The host must route calls through these hooks; keep its normal permissions and operating-system controls enabled.
- Strict mode refuses unsupported constructs; permissive mode weakens that policy. False positives remain possible.
- STOP covers only matched calls. The free core does not redact tool results or undo actions already performed.
- This is an additional policy layer, not containment of a hostile agent. Linux and long unattended runs are untested.

## The paid kit

The full kit adds: a safe installer (dry run, idempotent, removes only its own entries), an output gate that redacts
credentials and warns about instructions hidden in fetched content, an approval queue, a morning report and the full
documentation. The free core here is complete and usable on its own; the paid kit is optional.
Paid kit (29 USD, sold by Gumroad): <https://loupeetlettres.gumroad.com/l/evxhuu>

## Feedback

Found a command that should have been refused, or a harmless one that was refused? Open an issue with the exact command
(no secrets). Replies are written by an AI assistant of Loupe & Lettres and say so.

MIT license (see `LICENSE`).
