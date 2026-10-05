#!/usr/bin/env python3
"""How much of a build `sv run` could test: for the testability arms of the third prompts trial.

Reads TRIAL_DIR/runs/<build>-out/report.json (written by tools/prompt_trial.py) and the build's own
securevibe.toml, and prints, per build: whether the app was started, how many requirements a check
of the running app (`probe.*`) credited, how many running-app findings it raised, and which of the
settings `sv run` reads the build gave.
"""
import json, os, sys, tomllib

HERE = os.path.abspath(sys.argv[1])
SETTINGS = [('stack.run', k) for k in ('image', 'start', 'health', 'test')] + \
           [('stack.run.users', k) for k in ('seed', 'login', 'logout', 'private', 'owned', 'admin', 'once')] + \
           [('stack.run.ai', 'chat')]


def given(manifest, table, key):
    node = manifest
    for part in table.split('.'):
        node = node.get(part, {}) if isinstance(node, dict) else {}
    return key in node


def row(build):
    out = os.path.join(HERE, 'runs', build + '-out', 'report.json')
    try:
        manifest = tomllib.load(open(os.path.join(HERE, build, 'securevibe.toml'), 'rb'))
    except (OSError, tomllib.TOMLDecodeError) as e:
        manifest = {}
        bad = f'securevibe.toml unreadable: {e}'
    else:
        bad = ''
    gave = [f'{t.split(".")[-1]}.{k}' for t, k in SETTINGS if given(manifest, t, k)]
    if not os.path.exists(out):
        return {'build': build, 'ran': 'no report', 'probe_credited': 0, 'probe_findings': 0,
                'gave': gave, 'note': bad}
    report = json.load(open(out))
    credited = {r['id'] for r in report['requirements']
                for c in r['checked_by'] if c['check_id'].startswith('probe.')}
    findings = [f for f in report['findings'] if f['rule_id'].startswith('probe.')]
    return {'build': build, 'ran': (report.get('run_status') or {}).get('state'),
            'probe_credited': len(credited), 'probe_findings': len(findings), 'gave': gave, 'note': bad}


if __name__ == '__main__':
    rows = [row(b) for b in sys.argv[2:]]
    for r in rows:
        print(f"{r['build']:24} ran={r['ran']:12} probe-credited={r['probe_credited']:3} "
              f"probe-findings={r['probe_findings']:3} gave={len(r['gave']):2}/{len(SETTINGS)} {r['note']}")
    json.dump(rows, open(os.path.join(HERE, 'testability.json'), 'w'), indent=1)
