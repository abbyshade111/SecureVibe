#!/usr/bin/env python3
"""Records which rules each semgrep registry pack loads, so the coverage count is only what runs.

    python3 tools/semgrep_packs.py                       # run each pack the adapter uses, record it
    python3 tools/semgrep_packs.py --from-sarif FILE p/security-audit   # record a run already made

`data/adapters.json` maps about a thousand semgrep rules to requirements, but the adapter runs
registry packs, and a pack loads only some of them: `p/security-audit` loaded 225 on 26 September 2026.
`tools/coverage.py` counts semgrep only through mapped rules in a pack the adapter runs, and reads
which rules those are from `data/semgrep-packs.json`, written here. A report was never overstated
this way: `sv` credits a clean run only with the rules its own SARIF lists. The coverage document was.

A pack is the registry's and changes without `sv` changing, so the file carries the date and the
semgrep version of each measurement. Running a pack needs semgrep and a connection to semgrep.dev:
the fixture app is scanned, and every rule the SARIF lists as loaded is kept, whether it fired or not.

This is maintenance of the repository's own data, run by whoever runs it; `sv` itself reads the file
as committed and fetches nothing.
"""

import argparse
import datetime
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGNOSTIC = HERE.parent
PACKS = AGNOSTIC / "data" / "semgrep-packs.json"
ADAPTERS = AGNOSTIC / "data" / "adapters.json"
FIXTURE_APP = AGNOSTIC / "crates" / "sv-check" / "tests" / "fixtures" / "semgrep" / "app"


def adapter_packs() -> list:
    """The registry packs the semgrep adapter runs, from its `--config` arguments."""
    semgrep = next(a for a in json.loads(ADAPTERS.read_text())["adapters"] if a["id"] == "semgrep")
    args = semgrep["run"]["args"]
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--config"]


def loaded(sarif: dict) -> tuple:
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    ids = sorted({r["id"] for r in driver.get("rules", [])})
    if not ids:
        sys.exit("the SARIF lists no loaded rules, so it cannot say what a pack holds")
    return ids, driver.get("semanticVersion", "unknown")


def measure(pack: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "run.sarif"
        subprocess.run(
            ["semgrep", "scan", "--config", pack, "--metrics=off", "--disable-version-check",
             "--sarif", "--output", str(out), "--quiet", "."],
            cwd=FIXTURE_APP, check=True,
        )
        return json.loads(out.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from-sarif", nargs=2, metavar=("FILE", "PACK"),
                        help="record a run already made, of PACK, rather than running semgrep")
    parser.add_argument("--date", help="the date the run was made, YYYY-MM-DD (default: today)")
    args = parser.parse_args()
    today = args.date or datetime.date.today().isoformat()
    packs = json.loads(PACKS.read_text()) if PACKS.exists() else {"packs": {}}
    if args.from_sarif:
        path, pack = args.from_sarif
        runs = {pack: (json.loads(Path(path).read_text()), str(Path(path).resolve().relative_to(AGNOSTIC)))}
    else:
        runs = {pack: (measure(pack), "a run over crates/sv-check/tests/fixtures/semgrep/app")
                for pack in adapter_packs()}
    for pack, (sarif, source) in runs.items():
        ids, version = loaded(sarif)
        packs["packs"][pack] = {"measured": today, "semgrep": version, "from": source, "rules": ids}
        print(f"{pack}: {len(ids)} rules loaded (semgrep {version}, {today})")
    packs["_comment"] = (
        "Which rules each semgrep registry pack loads, as measured, written by tools/semgrep_packs.py. "
        "tools/coverage.py counts semgrep only through mapped rules in a pack the adapter runs. A pack "
        "is the registry's and changes without sv changing, so re-measure when the map is regenerated."
    )
    PACKS.write_text(json.dumps({"_comment": packs["_comment"], "packs": packs["packs"]}, indent=2) + "\n")
    print(f"wrote {PACKS.relative_to(AGNOSTIC)}")


if __name__ == "__main__":
    main()
