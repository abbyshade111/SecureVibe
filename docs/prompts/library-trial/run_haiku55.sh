#!/bin/sh
# The Haiku 5.5 trial (docs/prompts/library-trial/haiku55-protocol.md). `smoke`: one uncounted Haiku 5.5 build.
# Otherwise stage 1: 10 Haiku 5.5 builds, the cost guard, 10 Haiku 4.5 builds, then sv report --run on each.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.293/8433d0d9cd0d/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-target-kc/release/sv SV_REPO=/tmp/claude-502/h5-wt
T=/tmp/claude-502/loop/loop_trial.py
b() { python3 $T $O none $1 $2 --model-id $3 --budget 1.5 --api --with-spec --allow-git --brief docs/prompts/trial-4/recipe-brief.md; }
keycheck() { echo "billing errors: $(grep -l '"billing_error"' $O/*.jsonl 2>/dev/null | wc -l)"; echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"; }
if [ "$1" = smoke ]; then
  O=~/sv-haiku55-smoke; mkdir -p $O && cp $SV_REPO/docs/prompts/trial/policy.toml $O/
  b haiku55 1 claude-haiku-5-5
  grep -h '"type":"system"' $O/*.jsonl | head -1 | python3 -c "import json,sys; print('model:', json.loads(sys.stdin.read()).get('model'))"
  grep -h '"type":"result"' $O/*.jsonl | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print('cost:', d.get('total_cost_usd'), 'error:', d.get('is_error'), d.get('subtype'))"
  keycheck; echo "SMOKE DONE"; exit 0
fi
O=~/sv-haiku55; mkdir -p $O && cp $SV_REPO/docs/prompts/trial/policy.toml $O/
for n in 1 2 3 4 5 6 7 8 9 10; do b haiku55 $n claude-haiku-5-5 & done; wait
avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$O/haiku55-*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "Haiku 5.5 average \$$avg"
python3 -c "import sys; sys.exit(0 if $avg <= 0.30 else 1)" || { echo "STOPPED: over the cost guard"; keycheck; exit 1; }
for n in 1 2 3 4 5 6 7 8 9 10; do b haiku45 $n claude-haiku-4-5-20251001 & done; wait
keycheck; echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls *.jsonl | sed 's/.jsonl//') > /dev/null
echo "RUNS DONE"
