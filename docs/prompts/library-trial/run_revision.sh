#!/bin/sh
# The revision trial (docs/prompts/library-trial/revision-protocol.md): 110 builds, no MCP server, the specification
# from main (with the shown prompts at the start), git allowed, the loop protocol's Amendment 5 sentence; ten at a time;
# then sv report --run on each by the same sv.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-revision-target/release/sv SV_REPO=/tmp/claude-502/rv-run
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-revision
mkdir -p $O && cp /tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml $O/
b() { python3 $T $O none $1 $2 --budget 1.5 --api --with-spec --allow-git $3; }
first=1
for spec in "haiku:" "haiku:limits-without-asking" "haiku:production-server" "haiku:isolate-the-window" "haiku:security-contact" \
            "haiku:secrets-in-the-environment" "haiku:security-headers" "haiku:git-from-the-start" \
            "sonnet:" "sonnet:ai-feature-guard" "sonnet:isolate-the-window"; do
  m=${spec%%:*}; p=${spec#*:}
  for n in 1 2 3 4 5 6 7 8 9 10; do if [ -z "$p" ]; then b $m $n "" & else b $m $n "--prompt $p" & fi; done; wait
  if [ $first = 1 ]; then first=0
    avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "first ten average \$$avg"
    python3 -c "import sys; sys.exit(0 if $avg <= 0.60 else 1)" || { echo "STOPPED: over the cost guard"; exit 1; }
  fi
done
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls *.jsonl | sed 's/.jsonl//') > /dev/null
echo "RUNS DONE"
