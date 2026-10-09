#!/usr/bin/env python3
"""Drives the sv container image over MCP the way an AI coding tool would, and says whether it works.

    python3 tools/image_smoke.py securevibe/sv                      # the image as built
    python3 tools/image_smoke.py securevibe/sv --native target/release/sv   # and compare with sv itself
    python3 tools/image_smoke.py securevibe/sv --no-git              # an image built without git
    python3 tools/image_smoke.py securevibe/sv --commit <sha>        # and built from this commit

It makes a small app in a temporary folder, a copy of `examples/tested-notes` with a `.env` committed
to git, and starts the image the way `.mcp.json` would (`docker run -i --rm --network none -v
<folder>:<folder> <image> mcp --root <folder>`). Then, over MCP:

- the thirteen tools are offered, and `stackvet_spec` answers;
- `stackvet_prompts` gives the prompt library, each marked, so the prompts file is in the image;
- `stackvet_guidance` gives the coding rules with their credit and license, so the rules file is in the image;
- `stackvet_check` ran the committed-secrets check and found the `.env`. **This is asserted before
  anything is compared.** The first local test compared the image with the native `sv` on an app with
  no stackvet.toml: neither ran the check, "no answer" matched "no answer", and the control passed
  while proving nothing;
- the same, run as root against a folder root does not own, which is what `safe.directory` is for:
  git refuses such a repository, and the check would then quietly be not assessed;
- `stackvet_notes_file` writes into the owner's folder, as a file the owner owns;
- `stackvet_bundle` writes a zip beside the app, as a file the owner owns, and the committed `.env` is not in it;
- the container really has no network.

With `--native`, the image's findings must be the native `sv`'s, once both are known to have run.
With `--no-git`, for an image built where packages could not be installed, the committed-secrets
check must instead be reported as not assessed, never as passed. With `--commit`, `sv --version` in the
image must name that commit: the build context has no `.git`, so the image only knows it when the build
is given it (`--build-arg SV_GIT_COMMIT`), and its reports name the `sv` that made them.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
EXAMPLE = ROOT / "examples" / "tested-notes"
TOOLS = [
    "stackvet_check",
    "stackvet_write_report",
    "stackvet_bundle",
    "stackvet_explain",
    "stackvet_questions",
    "stackvet_notes_file",
    "stackvet_record_answer",
    "stackvet_guidance",
    "stackvet_prompts",
    "stackvet_spec",
    "stackvet_plan",
    "stackvet_preflight",
    "stackvet_before",
]
FAILURES = []


def check(ok, what):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILURES.append(what)


def make_app(root: Path) -> Path:
    app = root / "app"
    shutil.copytree(EXAMPLE, app, ignore=shutil.ignore_patterns("__pycache__", "stackvet-report"))
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
    parser.add_argument("--commit", help="the commit the image was built from, which `sv --version` must name")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix="sv-image-smoke-")).resolve()
    try:
        app = make_app(root)
        me = f"{os.getuid()}:{os.getgid()}"
        check_call = ("tools/call", {"name": "stackvet_check", "arguments": {"path": "app"}})
        replies = session(docker(args.image, root, me), [
            ("tools/list", {}),
            ("tools/call", {"name": "stackvet_spec", "arguments": {}}),
            check_call,
            ("tools/call", {"name": "stackvet_notes_file", "arguments": {"path": "app"}}),
            ("tools/call", {"name": "stackvet_bundle", "arguments": {"path": "app"}}),
            ("tools/call", {"name": "stackvet_guidance", "arguments": {"path": "app"}}),
            ("tools/call", {"name": "stackvet_prompts", "arguments": {}}),
        ])
        names = [t["name"] for t in replies[0]["result"]["tools"]]
        check(names == TOOLS, f"thirteen tools offered: {names}")
        prompts = replies[6]["result"]
        prompts_text = prompts["content"][0]["text"]
        check(prompts["isError"] is False and "**Shown to work, on " in prompts_text
              and "**Tried, not shown to work.**" in prompts_text,
              "stackvet_prompts gives the prompt library, each prompt marked")
        guidance = replies[5]["result"]
        rules_text = guidance["content"][0]["text"]
        check(guidance["isError"] is False and "CC BY-SA 4.0" in rules_text and "OWASP AISVS" in rules_text,
              "stackvet_guidance gives the coding rules, credited, with their license")
        spec = replies[1]["result"]["content"][0]["text"]
        check("[capabilities]" in spec, "stackvet_spec answers with the manifest spec")

        image_check = replies[2]
        if image_check["result"]["isError"] is not False:
            check(False, "stackvet_check answers: " + image_check["result"]["content"][0]["text"])
            sys.exit("the image cannot check an app, so nothing else is worth asking")
        check(True, "stackvet_check answers")
        # Starting the app cannot work from the container, so what the tool is told to have the
        # person run names `sv` on the computer itself, never the container's own path.
        told = gaps(image_check)
        check("installed on the computer itself" in told and "/usr/local/bin/sv" not in told,
              "the command to start the app is for sv on the computer, not in the container")
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

        bundle_reply = replies[4]["result"]
        check(bundle_reply["isError"] is False, "stackvet_bundle answers: " + bundle_reply["content"][0]["text"][:120])
        bundle = root / "app-stackvet-bundle.zip"
        check(bundle.exists(), "the bundle is written beside the app, not inside it")
        if bundle.exists():
            check(bundle.stat().st_uid == os.getuid(), "the owner owns the bundle")
            with zipfile.ZipFile(bundle) as z:
                members = z.namelist()
                check(z.testzip() is None, "every entry in the bundle passes its CRC")
                check("app/report/report.html" in members and "app/BUNDLE.json" in members, "the bundle holds the report and its listing")
                check(not any(m.endswith("/.env") for m in members), "the committed .env is not in the bundle")
                leaked = [m for m in members if b"not-a-real-key" in z.read(m)]
                check(not leaked, f"and what it held is in no entry, whatever the entry is called: {leaked}")

        who = subprocess.run(["docker", "run", "--rm", "--entrypoint", "id", args.image, "-u"],
                             capture_output=True, text=True, timeout=120)
        check(who.returncode == 0 and who.stdout.strip() not in ("", "0"),
              f"the image runs as a user of its own, not root: {who.stdout.strip() or who.stderr.strip()}")

        if not args.no_git and os.getuid() != 0:
            # Run as root, over a repository root does not own: git refuses it unless the image
            # trusts it, and the check would then be not assessed rather than run. Root by name,
            # since the image's own user is not root and could not read this folder at all.
            as_root = session(docker(args.image, root, "0:0"), [check_call])[0]
            check("config.secrets-file-committed" in findings(as_root),
                  "as another user than the folder's owner, the check still runs (safe.directory)")

        no_net = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", args.image, "-c",
             "cat /sys/class/net/*/operstate 2>/dev/null; ls /sys/class/net"],
            capture_output=True, text=True, timeout=120)
        check(no_net.stdout.split() == ["unknown", "lo"] or no_net.stdout.split() == ["lo"],
              f"--network none leaves only the loopback interface: {no_net.stdout.split()}")

        if args.commit:
            version = subprocess.run(["docker", "run", "--rm", "--network", "none", args.image, "--version"],
                                     capture_output=True, text=True, timeout=120)
            check(f"(commit {args.commit})" in version.stdout,
                  f"sv --version in the image names the commit it was built from: {version.stdout.strip()}")

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
