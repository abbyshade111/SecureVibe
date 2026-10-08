#!/bin/sh
# The recipe trial, stage 2 (docs/prompts/library-trial/recipe-protocol.md): the two arms stage 1 named by the rule (Sonnet: password-rules, production-server),
# then sv report --run on each, by one release build of main.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-target-kc/release/sv SV_REPO=/tmp/claude-502/rp-run
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-recipe
mkdir -p $O && cp /tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml $O/
b() { python3 $T $O none $1 $2 $3 --budget 1.5 --api --with-spec --allow-git --brief docs/prompts/trial-4/recipe-brief.md; }
for n in 1 2 3 4 5 6 7 8 9 10; do b sonnet $n "--prompt password-rules" & done; wait
avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/sonnet-p_*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "first ten average \$$avg"
python3 -c "import sys; sys.exit(0 if $avg <= 0.60 else 1)" || { echo "STOPPED: over the cost guard"; exit 1; }
for n in 1 2 3 4 5 6 7 8 9 10; do b sonnet $n "--prompt production-server" & done; wait
echo "billing errors: $(grep -l '"billing_error"' $O/*.jsonl 2>/dev/null | wc -l)"
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls sonnet-p_*.jsonl | sed "s/.jsonl//") > /dev/null
echo "RUNS DONE"
