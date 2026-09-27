#!/usr/bin/env python3
"""Drives the sv container image over MCP the way an AI coding tool would, and says whether it works.

    python3 tools/image_smoke.py securevibe/sv                      # the image as built
    python3 tools/image_smoke.py securevibe/sv --native target/release/sv   # and compare with sv itself
    python3 tools/image_smoke.py securevibe/sv --no-git              # an image built without git

It makes a small app in a temporary folder, a copy of `examples/tested-notes` with a `.env` committed
to git, and starts the image the way `.mcp.json` would (`docker run -i --rm --network none -v
<folder>:<folder> <image> mcp --root <folder>`). Then, over MCP:

- the six tools are offered, and `securevibe_spec` answers;
- `securevibe_check` ran the committed-secrets check and found the `.env`. **This is asserted before
  anything is compared.** The first local test compared the image with the native `sv` on an app with
  no securevibe.toml: neither ran the check, "no answer" matched "no answer", and the control passed
  while proving nothing;
- the same, run as root against a folder root does not own, which is what `safe.directory` is for:
  git refuses such a repository, and the check would then quietly be not assessed;
- `securevibe_notes_file` writes into the owner's folder, as a file the owner owns;
- the container really has no network.

With `--native`, the image's findings must be the native `sv`'s, once both are known to have run.
With `--no-git`, for an image built where packages could not be installed, the committed-secrets
check must instead be reported as not assessed, never as passed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
EXAMPLE = ROOT / "examples" / "tested-notes"
TOOLS = [
    "securevibe_check",
    "securevibe_write_report",
    "securevibe_explain",
    "securevibe_questions",
    "securevibe_notes_file",
    "securevibe_spec",
]
FAILURES = []


def check(ok, what):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILURES.append(what)


def make_app(root: Path) -> Path:
    app = root / "app"
    shutil.copytree(EXAMPLE, app, ignore=shutil.ignore_patterns("__pycache__", "securevibe-report"))
    (app / ".env").write_text("API_KEY=not-a-real-key\n")
    git = ["git", "-C", str(app), "-c", "user.name=smoke", "-c", "user.email=smoke@example.invalid"]
    subprocess.run(git[:3] + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "an app with its .env committed"], check=True)
    return app


def session(command, calls):
    """One MCP session: initialize, then each (method, params); the replies, in order."""
    lines = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize",
         "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                    "clientInfo": {"name": "image-smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    for i, (method, params) in enumerate(calls, 1):
        lines.append({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
    run = subprocess.run(command, input="".join(json.dumps(m) + "\n" for m in lines),
                         capture_output=True, text=True, timeout=600)
    replies = [json.loads(line) for line in run.stdout.splitlines() if line.strip()]
    if len(replies) != len(calls) + 1:
        sys.exit(f"expected {len(calls) + 1} replies, got {len(replies)}:\n{run.stdout}\n{run.stderr}")
    return replies[1:]


def docker(image, root, user=None):
    cmd = ["docker", "run", "-i", "--rm", "--network", "none", "-v", f"{root}:{root}"]
    if user:
        cmd += ["--user", user]
    return cmd + [image, "mcp", "--root", str(root)]


def findings(reply):
    return sorted(f["rule_id"] for f in reply["result"]["structuredContent"]["findings"])


def gaps(reply):
    return " ".join(g["what"] + " " + g["why"] for g in reply["result"]["structuredContent"]["notExamined"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image")
    parser.add_argument("--native", help="an sv built on this machine, to compare the image with")
    parser.add_argument("--no-git", action="store_true", help="the image was built without git")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix="sv-image-smoke-")).resolve()
    try:
        app = make_app(root)
        me = f"{os.getuid()}:{os.getgid()}"
        check_call = ("tools/call", {"name": "securevibe_check", "arguments": {"path": "app"}})
        replies = session(docker(args.image, root, me), [
            ("tools/list", {}),
            ("tools/call", {"name": "securevibe_spec", "arguments": {}}),
            check_call,
            ("tools/call", {"name": "securevibe_notes_file", "arguments": {"path": "app"}}),
        ])
        names = [t["name"] for t in replies[0]["result"]["tools"]]
        check(names == TOOLS, f"six tools offered: {names}")
        spec = replies[1]["result"]["content"][0]["text"]
        check("[capabilities]" in spec, "securevibe_spec answers with the manifest spec")

        image_check = replies[2]
        if image_check["result"]["isError"] is not False:
            check(False, "securevibe_check answers: " + image_check["result"]["content"][0]["text"])
            sys.exit("the image cannot check an app, so nothing else is worth asking")
        check(True, "securevibe_check answers")
        committed = "config.secrets-file-committed" in findings(image_check)
        if args.no_git:
            check(not committed and "git" in gaps(image_check).lower(),
                  "without git, the committed .env is not assessed, and says so")
        else:
            check(committed, "the committed .env is found (the check ran)")

        notes = app / "security-notes.md"
        check(notes.exists(), "security-notes.md is written into the owner's folder")
        if notes.exists():
            check(notes.stat().st_uid == os.getuid(), "and the owner owns it")

        if not args.no_git and os.getuid() != 0:
            # Run as root, over a repository root does not own: git refuses it unless the image
            # trusts it, and the check would then be not assessed rather than run.
            as_root = session(docker(args.image, root), [check_call])[0]
            check("config.secrets-file-committed" in findings(as_root),
                  "as another user than the folder's owner, the check still runs (safe.directory)")

        no_net = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", args.image, "-c",
             "cat /sys/class/net/*/operstate 2>/dev/null; ls /sys/class/net"],
            capture_output=True, text=True, timeout=120)
        check(no_net.stdout.split() == ["unknown", "lo"] or no_net.stdout.split() == ["lo"],
              f"--network none leaves only the loopback interface: {no_net.stdout.split()}")

        if args.native:
            if not (committed or args.no_git):
                check(False, "not compared with the native sv: the image's check did not run")
            else:
                native = session([args.native, "mcp", "--root", str(root)], [check_call])[0]
                native_ran = "config.secrets-file-committed" in findings(native)
                check(native_ran or args.no_git, "the native sv ran the check too")
                if args.no_git:
                    ours = [f for f in findings(image_check) if f != "config.secrets-file-committed"]
                    theirs = [f for f in findings(native) if f != "config.secrets-file-committed"]
                else:
                    ours, theirs = findings(image_check), findings(native)
                check(ours == theirs, f"the image finds what the native sv finds: {ours} / {theirs}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if FAILURES:
        sys.exit(f"{len(FAILURES)} failed")
    print("the image works")


if __name__ == "__main__":
    main()
