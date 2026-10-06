#!/bin/sh
# The prompt-library trial: 90 builds (protocol in docs/prompts/library-trial/protocol.md), ten at a time, no MCP
# server, the specification in every request; then sv report --run on each, one at a time.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export SV=/tmp/claude-502/sv-ptrial-target/release/sv SV_REPO=/tmp/claude-502/ptr-run KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-prompts
mkdir -p $O && cp /tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml $O/
b() { python3 $T $O none $1 $2 --budget 1.5 --api --with-spec $3; }
for m in haiku; do
  for p in "" password-hashing secrets-in-the-environment security-headers design-limits sessions-hard-to-steal private-pages-no-store; do
    for n in 1 2 3 4 5 6 7 8 9 10; do if [ -z "$p" ]; then b $m $n "" & else b $m $n "--prompt $p" & fi; done; wait
    # The protocol's cost guard: if the first ten builds average more than $0.60, stop before spending more.
    if [ -z "$p" ]; then
      avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/haiku-none-*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))")
      echo "first ten builds average \$$avg"
      python3 -c "import sys; sys.exit(0 if $avg <= 0.60 else 1)" || { echo "STOPPED: over the cost guard"; exit 1; }
    fi
  done
done
for p in "" ai-feature-guard; do
  for n in 1 2 3 4 5 6 7 8 9 10; do if [ -z "$p" ]; then b sonnet $n "" & else b sonnet $n "--prompt $p" & fi; done; wait
done
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls *.jsonl | sed 's/.jsonl//') > /dev/null
echo "RUNS DONE"
