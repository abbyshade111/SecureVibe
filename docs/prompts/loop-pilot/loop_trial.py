#!/usr/bin/env python3
"""Builds the club app with a headless AI coding tool, one build per call, for the loop trials.

    python3 loop_trial.py OUT ARM MODEL N [--budget USD]

Follows docs/prompts/loop-protocol.md. OUT is a folder under the home folder (Colima shares only that). Each build
gets a fresh folder OUT/<model>-<arm>-<n>, the request (docs/prompts/trial-3/plain-brief.md) as its prompt, and,
in the arms with the server, `sv mcp --root <that folder>` attached for this run only. Nothing in the person's
settings is read or changed: --restricted ignores the settings files and confines the file tools to the build's
folder, --strict-mcp-config uses no MCP server but this one, and --no-session-persistence keeps the run out of the
session list. The transcript (stream-json) is written beside the folder, not in it, so `sv` does not read it.
"""
import json, os, subprocess, sys, time

CLAUDE = os.environ['CLAUDE_BIN']      # the Claude Code program to run, by its full path
SV = os.environ['SV']                  # the sv release build every build is checked and helped by
REPO = os.environ['SV_REPO']           # a checkout of SecureVibe at that build's commit

ARMS = {
    # arm: (attach the server, the server's tools it may use, put the instructions in the request)
    'none': (False, [], False),
    'loop': (True, ['mcp__securevibe'], False),
    'instructions': (False, [], True),
    'check': (True, ['mcp__securevibe__securevibe_spec', 'mcp__securevibe__securevibe_check'], False),
    'plan': (True, ['mcp__securevibe__securevibe_spec', 'mcp__securevibe__securevibe_plan'], False),
}
FILE_TOOLS = ['Read', 'Write', 'Edit', 'Glob', 'Grep']
SHELL = 'Bash(python3:*)'


def instructions(folder):
    """The MCP server's opening instructions, as it gives them, for the arm that has them in the request."""
    hello = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                        'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                                   'clientInfo': {'name': 'loop-trial', 'version': '0'}}})
    out = subprocess.run([SV, 'mcp', '--root', folder], input=hello + '\n', capture_output=True, text=True,
                         timeout=60).stdout
    return json.loads(out.splitlines()[0])['result']['instructions']


def build(out, arm, model, n, budget):
    attach, sv_tools, with_instructions = ARMS[arm]
    name = f'{model}-{arm}-{n}'
    folder = os.path.join(out, name)
    os.makedirs(folder, exist_ok=False)
    request = open(os.path.join(REPO, 'docs/prompts/trial-3/plain-brief.md')).read()
    if with_instructions:
        request = ('These are the instructions SecureVibe gives an AI coding tool; follow them:\n\n'
                   + instructions(folder) + '\n\n---\n\n' + request)
    cmd = [CLAUDE, '-p', request, '--model', model, '--restricted', '--strict-mcp-config',
           '--tools', ','.join(FILE_TOOLS + ['Bash']),
           '--allowedTools', ' '.join(FILE_TOOLS + [SHELL] + sv_tools),
           '--permission-mode', 'dontAsk', '--no-session-persistence',
           '--output-format', 'stream-json', '--verbose', '--max-budget-usd', str(budget)]
    if attach:
        config = {'mcpServers': {'securevibe': {'command': SV, 'args': ['mcp', '--root', folder]}}}
        cfg = os.path.join(out, name + '.mcp.json')
        json.dump(config, open(cfg, 'w'))
        cmd += ['--mcp-config', cfg]
    started = time.time()
    with open(os.path.join(out, name + '.jsonl'), 'w') as transcript:
        code = subprocess.run(cmd, cwd=folder, stdout=transcript, stderr=subprocess.STDOUT,
                              timeout=3600).returncode
    print(f'{name}: exit {code}, {time.time() - started:.0f}s', flush=True)


if __name__ == '__main__':
    out, arm, model, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    budget = float(sys.argv[sys.argv.index('--budget') + 1]) if '--budget' in sys.argv else 3.0
    build(os.path.abspath(os.path.expanduser(out)), arm, model, n, budget)
