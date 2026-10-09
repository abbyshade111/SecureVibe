#!/usr/bin/env python3
"""The blind tester of docs/prompts/loop-compare/protocol.md ("The tester").

    python3 blind_tester.py OUT BLIND

For every build folder in OUT (`<model>-<arm>-<n>`): a copy in BLIND named by a code drawn at random, with everything
that shows the arm removed (the protocol's list); the code-to-build table written to OUT/blind-map.json, which nothing
reads until scoring. Then one headless tester per copy, which may write `securevibe.toml` and `sv_seed.py` and nothing
else: every file's SHA-256 is taken before and after, and a copy where anything else changed is restored and tried
once more, then left out. The tester's transcript goes to BLIND/<code>.tester.jsonl, beside the copy, not in it.
"""
import hashlib, json, os, random, re, shutil, subprocess, sys

CLAUDE = os.environ['CLAUDE_BIN']
SV = os.environ['SV']
KEY_HELPER = os.environ['KEY_HELPER']
REMOVE = ['securevibe.toml', 'securevibe-report', 'security-notes.md', 'design-decisions.md', '.mcp.json', '.git',
          '.claude']
ALLOWED = {'securevibe.toml', 'sv_seed.py'}
REQUEST = ("The app in this folder is finished. Write `securevibe.toml` for it, describing the code that is there, so "
           "SecureVibe can start it and sign in to it as the specification says: set `install = true` for its "
           "packages. If the app has no way to make the test accounts the specification describes, you may also "
           "write `sv_seed.py` to make them. Change no other file.")


def scrub(folder):
    for name in REMOVE:
        path = os.path.join(folder, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        elif os.path.lexists(path):
            os.remove(path)
    agents = os.path.join(folder, 'AGENTS.md')
    if os.path.isfile(agents):
        text = open(agents).read()
        # `sv rules` writes between its own two markers; everything else in the file is the builder's.
        text = re.sub(r'<!-- securevibe:coding-rules:begin -->.*?<!-- securevibe:coding-rules:end -->\n?', '',
                      text, flags=re.S)
        if text.strip():
            open(agents, 'w').write(text)
        else:
            os.remove(agents)


def hashes(folder):
    out = {}
    for root, dirs, files in os.walk(folder):
        for f in files:
            p = os.path.join(root, f)
            if os.path.islink(p):
                out[os.path.relpath(p, folder)] = 'link:' + os.readlink(p)
            else:
                out[os.path.relpath(p, folder)] = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    return out


def tester(folder, transcript, spec):
    request = ("This is SecureVibe's specification for the securevibe.toml my apps need:\n\n" + spec
               + "\n\n---\n\n" + REQUEST + "\n")
    cmd = [CLAUDE, '-p', request, '--model', 'claude-haiku-5-5', '--restricted', '--strict-mcp-config',
           '--tools', 'Read,Write,Edit,Glob,Grep', '--allowedTools', 'Read Write Edit Glob Grep',
           '--permission-mode', 'dontAsk', '--no-session-persistence', '--output-format', 'stream-json',
           '--verbose', '--max-budget-usd', '0.5', '--settings', json.dumps({'apiKeyHelper': KEY_HELPER})]
    env = {k: v for k, v in os.environ.items() if k not in ('ANTHROPIC_API_KEY', 'KEY_HELPER')}
    with open(transcript, 'w') as t:
        return subprocess.run(cmd, cwd=folder, stdout=t, stderr=subprocess.STDOUT, env=env, timeout=1800).returncode


def main():
    out, blind = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(blind, exist_ok=False)
    builds = sorted(d for d in os.listdir(out) if os.path.isdir(os.path.join(out, d)) and re.match(r'^[a-z0-9]+-\w+-\d+$', d))
    rng = random.SystemRandom()
    codes = {}
    for b in builds:
        code = 'app' + ''.join(rng.choice('0123456789abcdef') for _ in range(6))
        while code in codes.values():
            code = 'app' + ''.join(rng.choice('0123456789abcdef') for _ in range(6))
        codes[b] = code
    json.dump(codes, open(os.path.join(out, 'blind-map.json'), 'w'), indent=1)
    spec = subprocess.run([SV, 'init'], capture_output=True, text=True, timeout=60, check=True).stdout
    order = list(codes.items())
    rng.shuffle(order)  # nor does the order the tester sees them in follow the arms
    left_out = []
    for build, code in order:
        copy = os.path.join(blind, code)
        shutil.copytree(os.path.join(out, build), copy, symlinks=True)
        scrub(copy)
        pristine = os.path.join(blind, '.pristine-' + code)
        shutil.copytree(copy, pristine, symlinks=True)
        before = hashes(copy)
        for attempt in (1, 2):
            code_ = tester(copy, os.path.join(blind, f'{code}.tester{attempt}.jsonl'), spec)
            after = hashes(copy)
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k) and k not in ALLOWED)
            if not changed:
                print(f'{code}: tester exit {code_}, attempt {attempt}, wrote '
                      f'{sorted(k for k in ALLOWED if k in after)}', flush=True)
                break
            print(f'{code}: attempt {attempt} changed {changed[:5]}; restored', flush=True)
            shutil.rmtree(copy)
            shutil.copytree(pristine, copy, symlinks=True)
        else:
            left_out.append(code)
        shutil.rmtree(pristine)
    json.dump({'left_out': left_out}, open(os.path.join(blind, 'left-out.json'), 'w'))
    print('TESTER DONE; left out:', left_out)


if __name__ == '__main__':
    main()
