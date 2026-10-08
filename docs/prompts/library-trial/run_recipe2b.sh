#!/bin/sh
# The recipe trial, stage 2's second arm (production-server, Sonnet), after the first stopped at the cost guard
# and the owner said to go on with the guard at $0.80 (recipe-protocol.md, Amendment 2).
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-target-kc/release/sv SV_REPO=/tmp/claude-502/rp-run
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-recipe
b() { python3 $T $O none $1 $2 $3 --budget 1.5 --api --with-spec --allow-git --brief docs/prompts/trial-4/recipe-brief.md; }
for n in 1 2 3 4 5 6 7 8 9 10; do b sonnet $n "--prompt production-server" & done; wait
avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/sonnet-p_production_server-*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "ten average \$$avg (guard 0.80)"
echo "billing errors: $(grep -l '"billing_error"' $O/sonnet-p_production_server-*.jsonl 2>/dev/null | wc -l)"
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls sonnet-p_production_server-*.jsonl | sed "s/.jsonl//") > /dev/null
echo "RUNS DONE"
