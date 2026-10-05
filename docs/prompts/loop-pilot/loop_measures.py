#!/usr/bin/env python3
"""The loop trials' measures (docs/prompts/loop-protocol.md), from each build's transcript and report.

    python3 loop_measures.py OUT BUILD... [--json FILE]

Reads OUT/<build>.jsonl (the stream-json transcript) and OUT/runs/<build>-out/report.json (tools/prompt_trial.py's
`run`). Prints one line per build and writes OUT/loop-measures.json.
"""
import json, os, sys

OUT = os.path.abspath(os.path.expanduser(sys.argv[1]))
APP_FILES = ('app.py', 'seed.py')


def transcript(build):
    """Every tool call in order (name, input), the result message, and each sv check's text result."""
    calls, results, final = [], {}, None
    for line in open(os.path.join(OUT, build + '.jsonl')):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get('type')
        if kind == 'assistant':
            for block in event.get('message', {}).get('content', []):
                if block.get('type') == 'tool_use':
                    calls.append((block['id'], block['name'], block.get('input', {})))
        elif kind == 'user':
            for block in event.get('message', {}).get('content', []):
                if isinstance(block, dict) and block.get('type') == 'tool_result':
                    content = block.get('content')
                    text = content if isinstance(content, str) else ' '.join(
                        c.get('text', '') for c in content or [] if isinstance(c, dict))
                    results[block['tool_use_id']] = text
        elif kind == 'result':
            final = event
    return calls, results, final


def use(calls, results):
    sv = [(i, name.split('__')[-1]) for i, (_, name, _) in enumerate(calls) if name.startswith('mcp__securevibe__')]
    writes = [i for i, (_, name, args) in enumerate(calls)
              if name in ('Write', 'Edit') and os.path.basename(args.get('file_path', '')) in APP_FILES]
    first_write = writes[0] if writes else None
    before = {n for i, n in sv if first_write is None or i < first_write}
    checks = [(cid, name) for cid, name, _ in calls if name == 'mcp__securevibe__securevibe_check']
    attention = []
    for cid, _ in checks:
        # The check answers in JSON: how many requirements need attention, and the findings.
        try:
            answer = json.loads(results.get(cid, ''))
            attention.append({'needs_attention': answer.get('needsAttention'),
                              'findings': [f"{f.get('rule_id')}:{f.get('severity')}" for f in answer.get('findings', [])]})
        except (json.JSONDecodeError, AttributeError):
            attention.append(None)
    return {
        'sv_calls': [n for _, n in sv],
        'spec_before_code': 'securevibe_spec' in before,
        'plan_before_code': 'securevibe_plan' in before,
        'checks': len(checks),
        'attention_per_check': attention,
    }


def report(build):
    path = os.path.join(OUT, 'runs', build + '-out', 'report.json')
    if not os.path.exists(path):
        return {'started': False, 'signed_in': False, 'answered': 0, 'running_findings': 0, 'own_high': 0}
    r = json.load(open(path))
    started = (r.get('run_status') or {}).get('state') == 'started'
    signed_in = started and not any(
        g['why'].startswith('Signing in as the first test user did not open') for g in r['gaps'])
    credited = {c['check_id'] for q in r['requirements'] for c in q['checked_by'] if c['check_id'].startswith('probe.')}
    found = {f['rule_id'] for f in r['findings'] if f['rule_id'].startswith('probe.')}
    own_high = sum(1 for f in r['findings'] if not f['rule_id'].startswith('probe.')
                   and f.get('severity') in ('critical', 'high'))
    return {'started': started, 'signed_in': signed_in, 'answered': len(credited | found),
            'running_findings': len([f for f in r['findings'] if f['rule_id'].startswith('probe.')]),
            'own_high': own_high}


rows = []
for build in [a for i, a in enumerate(sys.argv[2:], 2) if a != '--json' and sys.argv[i - 1] != '--json']:
    calls, results, final = transcript(build)
    row = {'build': build, **use(calls, results), **report(build),
           'cost_usd': (final or {}).get('total_cost_usd'), 'seconds': ((final or {}).get('duration_ms') or 0) / 1000,
           'turns': (final or {}).get('num_turns'), 'stopped': (final or {}).get('subtype')}
    rows.append(row)
    print(f"{build:22} sv={','.join(row['sv_calls']) or '-'} spec-first={row['spec_before_code']} "
          f"plan-first={row['plan_before_code']} checks={row['checks']} attention={row['attention_per_check']} "
          f"started={row['started']} signed-in={row['signed_in']} answered={row['answered']} "
          f"cost=${row['cost_usd']} {row['seconds']:.0f}s {row['stopped']}")
json.dump(rows, open(sys.argv[sys.argv.index('--json') + 1] if '--json' in sys.argv else os.path.join(OUT, 'loop-measures.json'), 'w'), indent=1)
