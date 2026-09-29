#!/usr/bin/env python3
"""Records which queries each CodeQL suite the adapters run, so a mapped query is known to run.

    python3 tools/codeql_suites.py                  # resolve each suite the adapters use, record it
    python3 tools/codeql_suites.py --codeql PATH    # with that `codeql` rather than the one on PATH

`data/adapters.json` maps CodeQL queries to requirements, and each CodeQL adapter runs one suite
(`python-security-extended.qls`, `javascript-security-extended.qls`). Whether a mapped query is in its
suite was not written down anywhere, as `data/semgrep-packs.json` does for semgrep, so a query proposed
for a requirement could not be told apart from one that never runs. This asks CodeQL itself:
`codeql resolve queries` lists the files a suite selects, and each file's `@id` is its rule id in the
SARIF `sv` reads. `crates/sv-check/tests/adapters.rs` fails when an adapter runs a suite not recorded
here, or maps a query that is not in its suite.

A suite is the query pack's and changes with CodeQL's releases, so the file carries the date and the
CodeQL version of each measurement. Resolving needs the CodeQL bundle (the command-line tool and its
query packs) and no network. This is maintenance of the repository's own data, run by whoever runs it;
`sv` itself reads the file as committed and runs nothing from it.
"""

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SUITES = ROOT / "data" / "codeql-suites.json"
ADAPTERS = ROOT / "data" / "adapters.json"


def adapter_suites() -> dict:
    """Suite -> the CodeQL adapter that runs it, from each adapter's `database analyze` arguments."""
    out = {}
    for adapter in json.loads(ADAPTERS.read_text())["adapters"]:
        if not adapter["id"].startswith("codeql"):
            continue
        for arg in adapter["run"]["args"]:
            if arg.endswith(".qls"):
                out[arg] = adapter["id"]
    return out


def version(codeql: str) -> str:
    text = subprocess.run([codeql, "version", "--format=terse"], capture_output=True, text=True,
                          check=True).stdout
    return text.strip()


def query_ids(codeql: str, suite: str) -> list:
    """The `@id` of every query the suite selects, as `codeql resolve queries` resolves it."""
    listed = subprocess.run([codeql, "resolve", "queries", "--format=json", suite],
                            capture_output=True, text=True, check=True).stdout
    ids = []
    for path in json.loads(listed):
        found = re.search(r"@id\s+(\S+)", Path(path).read_text())
        if not found:
            sys.exit(f"{path}, selected by {suite}, has no @id")
        ids.append(found.group(1))
    return sorted(set(ids))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--codeql", default="codeql", help="the codeql command (default: on PATH)")
    args = parser.parse_args()
    measured = version(args.codeql)
    today = datetime.date.today().isoformat()
    current = json.loads(SUITES.read_text()) if SUITES.exists() else {}
    suites = current.get("suites", {})
    for suite in sorted(adapter_suites()):
        rules = query_ids(args.codeql, suite)
        suites[suite] = {"measured": today, "codeql": measured, "rules": rules}
        print(f"{suite}: {len(rules)} queries")
    SUITES.write_text(json.dumps({
        "_comment": current.get("_comment", ""),
        "suites": dict(sorted(suites.items())),
    }, indent=2) + "\n")
    print(f"wrote {SUITES.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
