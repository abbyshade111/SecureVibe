#!/bin/sh
# docs/prompts/loop-compare/protocol.md: 10 Haiku 5.5 builds without sv, the cost guard, 10 with sv attached,
# then the blind tester on every app, then sv report --run on every blind copy.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.293/8433d0d9cd0d/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-target-kc/release/sv SV_REPO=/tmp/claude-502/lc-run
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-loop-compare; B=~/sv-loop-compare-blind
b() { python3 $T $O $1 haiku55 $2 --model-id claude-haiku-5-5 --budget 1.5 --api --allow-git --brief docs/prompts/loop-compare/brief.md; }
keycheck() { echo "billing errors: $(grep -l '"billing_error"' $O/*.jsonl $B/*.jsonl 2>/dev/null | wc -l)"; echo "key-in-transcripts: $(cat $O/*.jsonl $B/*.jsonl 2>/dev/null | grep -c 'sk-ant-')"; }
mkdir -p $O
for n in 1 2 3 4 5 6 7 8 9 10; do b none $n & done; wait
avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/haiku55-none-*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "without-sv average \$$avg"
python3 -c "import sys; sys.exit(0 if $avg <= 0.40 else 1)" || { echo "STOPPED: over the cost guard"; keycheck; exit 1; }
for n in 1 2 3 4 5 6 7 8 9 10; do b loop $n & done; wait
keycheck; echo "BUILDS DONE"
python3 /tmp/claude-502/loop/blind_tester.py $O $B
keycheck; echo "TESTERS DONE"
cp $SV_REPO/docs/prompts/trial/policy.toml $B/
cd $B && python3 /tmp/claude-502/loop/prompt_trial.py $B $(ls -d app* | grep -v '\.') > /dev/null
echo "RUNS DONE"
