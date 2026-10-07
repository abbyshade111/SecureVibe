#!/bin/sh
# Delivery test (docs/prompts/library-trial/delivery-protocol.md). Part A: 20 Haiku builds, no server, the new spec.
# Part B: 40 builds with every tool attached, 10 an arm: today's sv (a9d6fea4) and the delivering sv, both models.
# Every build is checked by the same sv, the delivering one, so the checks are the same for every arm.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; NEW=/tmp/claude-502/sv-delivery-target/release/sv; OLD=/tmp/claude-502/sv-ptrial-target/release/sv
NEWREPO=/tmp/claude-502/pd-run; OLDREPO=/tmp/claude-502/ptr-run
P=/tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml
for d in A B-old B-new; do mkdir -p ~/sv-delivery/$d && cp $P ~/sv-delivery/$d/; done
# Part A, ten at a time, with the protocol's cost stop after the first ten.
for half in "1 2 3 4 5 6 7 8 9 10" "11 12 13 14 15 16 17 18 19 20"; do
  for n in $half; do SV=$NEW SV_REPO=$NEWREPO python3 $T ~/sv-delivery/A none haiku $n --budget 1.5 --api --with-spec & done; wait
  avg=$(python3 -c "
import json,glob
c=[json.loads(l).get('total_cost_usd') or 0 for f in glob.glob('$HOME/sv-delivery/A/*.jsonl') for l in open(f) if '\"type\":\"result\"' in l]
print(round(sum(c)/max(len(c),1),3))"); echo "Part A average so far \$$avg"
  python3 -c "import sys; sys.exit(0 if $avg <= 0.60 else 1)" || { echo "STOPPED: over the cost guard"; exit 1; }
done
# Part B, ten at a time.
for m in sonnet haiku; do
  for n in 1 2 3 4 5 6 7 8 9 10; do SV=$OLD SV_REPO=$OLDREPO python3 $T ~/sv-delivery/B-old loop $m $n --budget 1.5 --api --with-spec & done; wait
  for n in 1 2 3 4 5 6 7 8 9 10; do SV=$NEW SV_REPO=$NEWREPO python3 $T ~/sv-delivery/B-new loop $m $n --budget 1.5 --api --with-spec & done; wait
done
echo "key-in-transcripts: $(cat ~/sv-delivery/*/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
for d in A B-old B-new; do cd ~/sv-delivery/$d && SV=$NEW python3 /tmp/claude-502/loop/prompt_trial.py ~/sv-delivery/$d $(ls *.jsonl | sed 's/.jsonl//') > /dev/null; done
echo "RUNS DONE"
