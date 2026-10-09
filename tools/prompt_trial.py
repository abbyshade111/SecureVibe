#!/usr/bin/env python3
"""Runs `sv report --run` on builds of the design-time prompts' test app and prints what each prompt's checks said.

    python3 tools/prompt_trial.py TRIAL_DIR BUILD[:slow] ...

TRIAL_DIR holds one folder per build (an app.py, seed.py, and stackvet.toml a helper agent wrote from
docs/prompts/trial/brief.md, with or without one prompt from data/design-prompts.json) and a policy.toml
(docs/prompts/trial/policy.toml): the numbers standing in for the owner's, added to a build's [policy] only where
it wrote none of its own. Each build is copied to TRIAL_DIR/runs/, made a git repository, and run behind the
fence, so it needs Docker or Colima; `:slow` adds `--slow` for the session timeouts. Used for docs/prompts/design-time.md.
"""
import json, os, shutil, subprocess, sys
HERE = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.getcwd()
SV = os.environ.get('SV', 'sv')
TARGETS = {
    'p1': ['probe.private-page-anonymous', 'probe.admin-page-ordinary-user',
           'probe.admin-action-ordinary-user', 'probe.other-users-data'],
    'p2': ['probe.action-done-twice'],
    'p3': ['probe.create-rate-unlimited', 'probe.failed-sign-ins-unlimited'],
    'p4': ['probe.error-detail-leak', 'probe.ai-service-failure-handled', 'probe.ai-service-error-shown'],
    'p6': ['probe.log-line-metadata', 'probe.log-timestamp-zoned', 'probe.authorization-failure-logged'],
    'p7': ['probe.session-idle-timeout', 'probe.session-lifetime', 'probe.logout-keeps-session',
           'probe.app-token-signature-not-checked', 'probe.app-token-alg-none', 'probe.app-token-expired-accepted'],
}
REQS = {'p1': ['V8.2.1', 'V8.2.2', 'V8.3.1'], 'p2': ['V2.3.4'], 'p3': ['V2.4.1', 'V6.3.1'],
        'p4': ['V16.5.1', 'V16.5.2'], 'p6': ['V16.2.1', 'V16.2.2', 'V16.3.2'],
        'p7': ['V7.3.1', 'V7.3.2', 'V7.4.1', 'V9.1.1', 'V9.1.2', 'V9.2.1']}

def merge_policy(path):
    """Adds the tester's [policy] numbers the build did not set itself, and says which were whose."""
    import tomllib
    tester = tomllib.load(open(os.path.join(HERE, 'policy.toml'), 'rb')).get('policy', {}) \
        if os.path.exists(os.path.join(HERE, 'policy.toml')) else {}
    # A build with no stackvet.toml, or one that does not parse, is checked as it is: what `sv`
    # makes of it is the outcome (loop-protocol.md, "What makes a build unusable").
    if not os.path.exists(path):
        print('  no stackvet.toml: checked as it is', flush=True)
        return
    text = open(path, encoding="utf-8").read()
    try:
        own = tomllib.loads(text).get('policy', {})
    except tomllib.TOMLDecodeError as e:
        print(f'  stackvet.toml does not parse ({e}): checked as it is', flush=True)
        return
    missing = {k: v for k, v in tester.items() if k not in own}
    print(f'  policy the build set itself: {own}; added by the tester: {missing}', flush=True)
    if not missing:
        return
    lines = '\n'.join(f'{k} = {v}' for k, v in missing.items())
    if 'policy' in tomllib.loads(text):
        text = text.replace('[policy]\n', '[policy]\n' + lines + '\n', 1)
    else:
        text = text.rstrip() + '\n\n[policy]\n' + lines + '\n'
    tomllib.loads(text)
    open(path, 'w', encoding='utf-8', newline='\n').write(text)

def run(build, slow):
    src = os.path.join(HERE, build)
    dst = os.path.join(HERE, 'runs', build)
    out = dst + '-out'
    shutil.rmtree(dst, ignore_errors=True); shutil.rmtree(out, ignore_errors=True)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns('*.db', '__pycache__', 'OWNER-REQUEST.md'))
    merge_policy(os.path.join(dst, 'stackvet.toml'))
    # --allow-empty: a build that wrote nothing is checked as it is (it has no report), not a crash of the run.
    subprocess.run('git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm build --allow-empty',
                   shell=True, cwd=dst, check=True)
    cmd = [SV, 'report', dst, '--run', '--out', out] + (['--slow'] if slow else [])
    with open(dst + '.log', 'w', encoding='utf-8', newline='\n') as log:
        code = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=3600).returncode
    path = os.path.join(out, 'report.json')
    return code, (json.load(open(path, encoding="utf-8")) if os.path.exists(path) else None)

def summary(report):
    lines = []
    for p, rules in TARGETS.items():
        lines.append(f'  {p}:')
        for rule in rules:
            found = [f['title'] for f in report['findings'] if f['rule_id'] == rule]
            found += [o['rule_id'] + ' (above level)' for o in report.get('out_of_scope', []) if o['rule_id'] == rule]
            credited = [c['scope'] for r in report['requirements'] for c in r['checked_by'] if c['check_id'] == rule]
            state = 'FOUND' if found else ('credited' if credited else '-')
            lines.append(f'    {rule}: {state}')
        for req in REQS[p]:
            gaps = [g['why'][:160] for g in report['gaps'] if req in g['what'].split(',')[0].split()[0:1] or g['what'].startswith(req)]
            for g in gaps:
                lines.append(f'      gap {req}: {g}')
    return '\n'.join(lines)

if __name__ == '__main__':
    import time
    builds = sys.argv[2:]
    for i, arg in enumerate(builds, 1):
        build, _, flag = arg.partition(':')
        began = time.time()
        code, report = run(build, flag == 'slow')
        # One line a build on stderr, so a run whose summaries go elsewhere still shows how far it has got.
        state = (report.get('run_status') or {}).get('state', 'not run') if report else 'no report'
        print(f'[{i}/{len(builds)}] {build}: {state}, {time.time() - began:.0f}s', file=sys.stderr, flush=True)
        if report is None:
            said = open(os.path.join(HERE, 'runs', build + '.log'), encoding="utf-8").read().strip().splitlines()[-3:]
            text = f'== {build} (exit {code}, no report: ' + ' / '.join(said) + ')'
        else:
            text = f'== {build} (exit {code}, run {report.get("run_status")})\n' + summary(report)
        print(text, flush=True)
        open(os.path.join(HERE, 'runs', build + '.summary'), 'w', encoding='utf-8', newline='\n').write(text + '\n')
