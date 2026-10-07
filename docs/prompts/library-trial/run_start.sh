#!/bin/sh
# The prompts where every builder starts (docs/prompts/library-trial/start-protocol.md): 40 builds with every tool
# attached, 10 an arm, today's sv (0c7e1448) and the at-start sv, both models; git allowed in both. Every build is
# checked by the at-start sv.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; OLD=/tmp/claude-502/sv-delivery-target/release/sv; NEW=/tmp/claude-502/sv-start-target/release/sv
OLDREPO=/tmp/claude-502/pd-run; NEWREPO=/tmp/claude-502/pas-run
P=/tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml
for d in today at-start; do mkdir -p ~/sv-start/$d && cp $P ~/sv-start/$d/; done
for m in sonnet haiku; do
  for n in 1 2 3 4 5 6 7 8 9 10; do SV=$OLD SV_REPO=$OLDREPO python3 $T ~/sv-start/today loop $m $n --budget 1.5 --api --with-spec --allow-git & done; wait
  for n in 1 2 3 4 5 6 7 8 9 10; do SV=$NEW SV_REPO=$NEWREPO python3 $T ~/sv-start/at-start loop $m $n --budget 1.5 --api --with-spec --allow-git & done; wait
done
echo "key-in-transcripts: $(cat ~/sv-start/*/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
for d in today at-start; do cd ~/sv-start/$d && SV=$NEW python3 /tmp/claude-502/loop/prompt_trial.py ~/sv-start/$d $(ls *.jsonl | sed 's/.jsonl//') > /dev/null; done
echo "RUNS DONE"
