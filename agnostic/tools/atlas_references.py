#!/usr/bin/env python3
"""Keeps the MITRE ATLAS references on the threat model true to an ATLAS release.

    python3 tools/atlas_references.py                    # re-read the pinned release, rewrite names
    python3 tools/atlas_references.py --release 2026.10  # move to a newer release, if nothing broke

`data/atlas-references.json` cites ATLAS techniques by ID on the threats about AI. ATLAS renames
techniques often and keeps their IDs, so the names are never written by hand: this script reads them
from the release file and writes them into `techniques`. Moving to a newer release names every cited
technique that was renamed, and refuses when one is gone, so a reference is never kept to something
ATLAS no longer lists.

This is maintenance of the repository's own data, run by whoever runs it: `sv` itself fetches
nothing, and reads the file as it was committed. Only the public release file is fetched.

The release is YAML and this uses Python's standard library alone, so it reads just what it needs:
each technique's ID and name, from the lines that open its entry. `--check-against-pyyaml` compares
that with a full parse, where PyYAML is installed.

MITRE ATLAS (TM) data, Copyright 2021-2026 The MITRE Corporation, from
https://github.com/mitre-atlas/atlas-data, licensed under the Apache License 2.0.
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGNOSTIC = HERE.parent
REFERENCES = AGNOSTIC / "data" / "atlas-references.json"
RELEASE_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-{}.yaml"


def fetch(release: str) -> str:
    assert re.fullmatch(r"\d{4}\.\d{2}(\.\d+)?", release), release
    request = urllib.request.Request(
        RELEASE_URL.format(release),
        headers={"User-Agent": "SecureVibe-sv-repository-maintenance"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return json.loads(value)
    return value


def technique_names(text: str) -> dict:
    """Each technique's ID and name, from the `techniques:` section of a format-6 release."""
    names = {}
    section = False
    current = None
    for line in text.splitlines():
        if re.match(r"^[a-z-]+:", line):
            section = line.startswith("techniques:")
            current = None
            continue
        if not section:
            continue
        opened = re.match(r"^  (AML\.T\d{4}(?:\.\d{3})?):\s*$", line)
        if opened:
            current = opened.group(1)
            continue
        named = re.match(r"^    name: (.+)$", line)
        if current and named and current not in names:
            names[current] = unquote(named.group(1))
    if len(names) < 100:
        sys.exit(f"read only {len(names)} techniques: the release's layout is not the one expected")
    return names


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", help="an ATLAS content release, such as 2026.10")
    parser.add_argument(
        "--check-against-pyyaml",
        action="store_true",
        help="also parse the release fully with PyYAML and compare",
    )
    args = parser.parse_args()
    refs = json.loads(REFERENCES.read_text())
    release = args.release or refs["release"]
    text = fetch(release)
    names = technique_names(text)

    if args.check_against_pyyaml:
        import yaml  # noqa: PLC0415 - only for the comparison

        full = {k: v["name"] for k, v in yaml.safe_load(text)["techniques"].items()}
        if full != names:
            sys.exit("the line reading and a full parse disagree; nothing written")
        print(f"the line reading agrees with a full parse: {len(names)} techniques")

    cited = sorted({c["id"] for cs in refs["threats"].values() for c in cs})
    gone = [i for i in cited if i not in names]
    if gone:
        sys.exit(
            f"ATLAS {release} no longer lists {', '.join(gone)}. Nothing was written: choose what "
            "those threats should cite now."
        )
    for i in cited:
        was = refs["techniques"].get(i)
        if was and was != names[i]:
            print(f"{i}: renamed from {was!r} to {names[i]!r}")
    refs["release"] = release
    refs["source"] = RELEASE_URL.format(release)
    refs["techniques"] = {i: names[i] for i in cited}
    REFERENCES.write_text(json.dumps(refs, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(cited)} techniques read from ATLAS {release}; wrote {REFERENCES.relative_to(AGNOSTIC)}")


if __name__ == "__main__":
    main()
