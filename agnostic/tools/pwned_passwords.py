#!/usr/bin/env python3
"""Keeps the repository's breached-password evidence current through the Pwned Passwords API.

    python3 tools/pwned_passwords.py             # re-check the V6.2.12 password, rewrite its evidence
    python3 tools/pwned_passwords.py --sample    # also sample data/knowledge/common-passwords.txt

This is maintenance of the repository's own data, run by whoever runs it: `sv` itself fetches
nothing, and reads `data/breached-password-evidence.json` as it was committed.

Only the first five characters of a password's SHA-1 hash are ever sent. Pwned Passwords answers
with every hash in that range and how often each was seen, and the match is found here, so neither
the password nor its full hash leaves the machine. `Add-Padding: true` asks for the answer to be
padded with made-up entries (seen 0 times, and ignored here), so its size says nothing about the
range either.

The default run re-checks the password `sv` tries at sign-up for V6.2.12 (`BREACHED` in
`crates/sv-check/src/signed_in.rs`, read from there so the two cannot drift) and rewrites
`data/breached-password-evidence.json` with the count and today's date. The report's V6.2.12 wording
is built from that file, so it follows without an edit. If the password is no longer in the data,
nothing is written and the script fails: the finding would then call a password breached with no
evidence that it is.

`--sample` looks up 300 entries of `../data/knowledge/common-passwords.txt`, 50 from each of six
bands of rank, evenly spaced within each, and writes `data/common-passwords-breach-sample.json`. The
list's source is recorded nowhere in the repository; this shows how much of it is breach data. The
list is shared with v1 and is only read here, never changed.

Data: Have I Been Pwned, Pwned Passwords, https://haveibeenpwned.com/Passwords, licensed CC BY 4.0.
"""

import argparse
import datetime
import hashlib
import http.client
import json
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGNOSTIC = HERE.parent
ROOT = AGNOSTIC.parent
SIGNED_IN = AGNOSTIC / "crates" / "sv-check" / "src" / "signed_in.rs"
EVIDENCE = AGNOSTIC / "data" / "breached-password-evidence.json"
COMMON = ROOT / "data" / "knowledge" / "common-passwords.txt"
SAMPLE_OUT = AGNOSTIC / "data" / "common-passwords-breach-sample.json"

API = "https://api.pwnedpasswords.com/range/"
ATTRIBUTION = (
    "Data: Have I Been Pwned, Pwned Passwords, https://haveibeenpwned.com/Passwords, "
    "licensed CC BY 4.0."
)

# The sample's bands of rank (line numbers in the list, inclusive) and how many from each.
BANDS = [(1, 1000), (1001, 3000), (3001, 10000), (10001, 30000), (30001, 60000), (60001, None)]
PER_BAND = 50


def sha1_hex(password: bytes) -> str:
    return hashlib.sha1(password).hexdigest().upper()


def fetch_range(prefix: str) -> dict:
    """Every suffix in the range and how often it was seen, without the padding entries."""
    assert re.fullmatch(r"[0-9A-F]{5}", prefix), prefix
    request = urllib.request.Request(
        API + prefix,
        headers={"Add-Padding": "true", "User-Agent": "SecureVibe-sv-repository-maintenance"},
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode("ascii")
            break
        except (OSError, http.client.HTTPException) as error:
            # A dropped connection mid-answer happens now and then; a refusal (HTTP 4xx) does not
            # go away by asking again, so it stops the run.
            if isinstance(error, urllib.error.HTTPError) and error.code < 500 or attempt == 3:
                raise
            time.sleep(2**attempt)
    seen = {}
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix and int(count) > 0:
            seen[suffix.upper()] = int(count)
    return seen


def breached_constant() -> str:
    found = re.findall(r'^const BREACHED: &str = "([^"\\]+)";$', SIGNED_IN.read_text(), re.M)
    if len(found) != 1:
        sys.exit(f"could not find the one `const BREACHED` in {SIGNED_IN.relative_to(AGNOSTIC)}")
    return found[0]


def refresh(today: str) -> None:
    password = breached_constant()
    digest = sha1_hex(password.encode("utf-8"))
    seen = fetch_range(digest[:5]).get(digest[5:])
    if not seen:
        sys.exit(
            f"Pwned Passwords no longer lists {password!r}. Nothing was written: choose another "
            "password for V6.2.12 before the finding calls this one breached."
        )
    old = json.loads(EVIDENCE.read_text())
    new = {
        "_comment": (
            "Why the V6.2.12 sign-up probe may call its password breached. `password` is BREACHED "
            "in crates/sv-check/src/signed_in.rs, and a test there fails if the two differ, so the "
            "password cannot be changed without new evidence. `sha1` is the password's SHA-1; "
            "Pwned Passwords is asked for the range of its first five characters and answers with "
            "every suffix in that range and how often each was seen, so the password itself is "
            "never sent. `line` is the one in that range whose suffix is the rest of `sha1`. "
            "Written by tools/pwned_passwords.py on the date in `checked`; the report's wording is "
            "built from this file. " + ATTRIBUTION
        ),
        "password": password,
        "sha1": digest,
        "range": API + digest[:5],
        "line": f"{digest[5:]}:{seen}",
        "seen": seen,
        "checked": today,
        "checkedBy": "tools/pwned_passwords.py",
    }
    EVIDENCE.write_text(json.dumps(new, indent=2) + "\n")
    was = old.get("seen")
    change = "unchanged" if was == seen else f"was {was:,}" if isinstance(was, int) else "new"
    print(f"{password}: seen {seen:,} times ({change}), checked {today}")
    print(f"wrote {EVIDENCE.relative_to(AGNOSTIC)}")


def sample_ranks(total: int) -> list:
    ranks = []
    for low, high in BANDS:
        high = min(high or total, total)
        if high < low:
            continue
        count = min(PER_BAND, high - low + 1)
        step = (high - low) / max(count - 1, 1)
        ranks += sorted({round(low + i * step) for i in range(count)})
    return ranks


def sample(today: str) -> None:
    lines = COMMON.read_bytes().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    ranges = {}
    rows = []
    for rank in sample_ranks(len(lines)):
        password = lines[rank - 1]
        digest = sha1_hex(password)
        if digest[:5] not in ranges:
            ranges[digest[:5]] = fetch_range(digest[:5])
            time.sleep(0.05)
        rows.append(
            {
                "rank": rank,
                "password": password.decode("utf-8"),
                "seen": ranges[digest[:5]].get(digest[5:], 0),
            }
        )

    def summary(chosen):
        counts = [r["seen"] for r in chosen if r["seen"]]
        return {
            "sampled": len(chosen),
            "found": len(counts),
            "fewestTimesSeen": min(counts, default=0),
            "medianTimesSeen": int(statistics.median(counts)) if counts else 0,
            "mostTimesSeen": max(counts, default=0),
        }

    bands = []
    for low, high in BANDS:
        chosen = [r for r in rows if r["rank"] >= low and (high is None or r["rank"] <= high)]
        bands.append({"ranks": f"{low}-{high or len(lines)}", **summary(chosen)})
    out = {
        "_comment": (
            "How much of data/knowledge/common-passwords.txt is breach data, from a sample: 50 "
            "entries from each band of rank, evenly spaced, each looked up in Pwned Passwords by "
            "the first five characters of its SHA-1 hash. `seen` is how often it has been seen in "
            "breaches; 0 means not found. Written by tools/pwned_passwords.py --sample. "
            + ATTRIBUTION
        ),
        "list": "data/knowledge/common-passwords.txt",
        "listLength": len(lines),
        "checked": today,
        **summary(rows),
        "bands": bands,
        "entries": rows,
    }
    SAMPLE_OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"sampled {len(rows)} of {len(lines):,} entries; {out['found']} are in breach data")
    for band in bands:
        print(
            f"  ranks {band['ranks']:>13}: {band['found']:>2} of {band['sampled']} found, "
            f"seen {band['fewestTimesSeen']:,} to {band['mostTimesSeen']:,} times "
            f"(median {band['medianTimesSeen']:,})"
        )
    print(f"wrote {SAMPLE_OUT.relative_to(AGNOSTIC)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--sample",
        action="store_true",
        help="also sample data/knowledge/common-passwords.txt against the same data",
    )
    args = parser.parse_args()
    today = datetime.date.today().isoformat()
    refresh(today)
    if args.sample:
        sample(today)


if __name__ == "__main__":
    main()
