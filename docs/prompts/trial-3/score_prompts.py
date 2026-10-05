#!/usr/bin/env python3
"""Scores the prompt arms of the third prompts trial, by the library's rule.

A prompt is *shown to work* for a check, for one model, only when every build made with it that
started was credited by that check, and every build made without any prompt that started was not.
A build that did not start says nothing either way and is left out, and the table says how many were.
Reads TRIAL_DIR/runs/<build>-out/report.json, as tools/prompt_trial.py writes them.
"""
import json, os, sys

HERE = os.path.abspath(sys.argv[1])
TARGETS = {
    'p1': ['probe.private-page-anonymous', 'probe.admin-page-ordinary-user',
           'probe.admin-action-ordinary-user', 'probe.other-users-data'],
    'p3': ['probe.create-rate-unlimited', 'probe.failed-sign-ins-unlimited'],
    'p4': ['probe.error-detail-leak', 'probe.ai-service-failure-handled', 'probe.ai-service-error-shown'],
    'p6': ['probe.log-line-metadata', 'probe.log-timestamp-zoned', 'probe.authorization-failure-logged'],
    'p7': ['probe.session-idle-timeout', 'probe.session-lifetime', 'probe.logout-keeps-session',
           'probe.app-token-signature-not-checked', 'probe.app-token-alg-none', 'probe.app-token-expired-accepted'],
}


def load(build):
    path = os.path.join(HERE, 'runs', build + '-out', 'report.json')
    return json.load(open(path)) if os.path.exists(path) else None


def state(report, rule):
    """'found', 'credited', or '-' (the check neither found nor credited)."""
    if any(f['rule_id'] == rule for f in report['findings']):
        return 'found'
    if any(o['rule_id'] == rule for o in report.get('out_of_scope', [])):
        return 'found'
    if any(c['check_id'] == rule for r in report['requirements'] for c in r['checked_by']):
        return 'credited'
    return '-'


def started(report):
    """Started, and signed in: a build `sv` could not sign in to says nothing about checks that need a
    signed-in user, which every targeted check but two does, so it is left out like one that did not start."""
    if report is None or (report.get('run_status') or {}).get('state') != 'started':
        return False
    return not any(g['why'].startswith('Signing in as the first test user did not open') for g in report['gaps'])


rows, verdicts = [], []
for model in ('sonnet', 'haiku'):
    # Haiku's two builds without a prompt could not start: the first brief said `seed.py` runs before
    # the app, and `sv` runs it after. They were rebuilt with that sentence corrected (`baseC`).
    base = [load(f'{model}-base{"C" if model == "haiku" else ""}-{n}') for n in (1, 2)]
    base_ok = [r for r in base if started(r)]
    for arm, rules in TARGETS.items():
        if arm == 'p7':
            # The session-time checks run only with --slow, as the prompt-7 builds were; so the builds
            # without a prompt were run again with --slow for this prompt (`baseS`, copies of the same builds).
            base = [load(f'{model}-baseS-{n}') for n in (1, 2)]
            base_ok = [r for r in base if started(r)]
        with_ = [load(f'{model}-{arm}-{n}') for n in (1, 2)]
        if model == 'haiku' and arm == 'p1':  # p1-2 could not start, for the same reason; rebuilt as p1C-2
            with_[1] = load('haiku-p1C-2')
        with_ok = [r for r in with_ if started(r)]
        for rule in rules:
            w = [state(r, rule) for r in with_ok]
            b = [state(r, rule) for r in base_ok]
            if not w or not b:
                verdict = 'no reading'
            elif all(s == 'credited' for s in w) and all(s != 'credited' for s in b):
                verdict = 'SHOWN'
            elif all(s == 'credited' for s in w) and all(s == 'credited' for s in b):
                verdict = 'no difference (both credited)'
            else:
                verdict = 'not shown'
            rows.append((model, arm, rule, w, len(with_) - len(with_ok), b, len(base) - len(base_ok), verdict))
            verdicts.append({'model': model, 'prompt': arm, 'rule': rule, 'with': w, 'without': b,
                             'with_not_started': len(with_) - len(with_ok),
                             'without_not_started': len(base) - len(base_ok), 'verdict': verdict})

for model, arm, rule, w, wmiss, b, bmiss, verdict in rows:
    print(f"{model:6} {arm} {rule:40} with={'/'.join(w) or '—':22}(+{wmiss} unusable) "
          f"without={'/'.join(b) or '—':22}(+{bmiss} unusable) {verdict}")
json.dump(verdicts, open(os.path.join(HERE, 'prompt-verdicts.json'), 'w'), indent=1)
