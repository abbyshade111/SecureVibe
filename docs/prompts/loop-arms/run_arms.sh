#!/bin/sh
# Item 3: the 18 new builds, six at a time, then sv report --run on each.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export SV=/tmp/claude-502/sv-trial-target/release/sv SV_REPO=/tmp/claude-502/sv-trial KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-loop
b() { python3 $T $O $2 $1 $3 --budget 1.5 --api; }
b sonnet none 1 & b sonnet none 2 & b sonnet instructions 1 & b sonnet instructions 2 & b sonnet check 1 & b sonnet check 2 & wait
b sonnet plan 1 & b sonnet plan 2 & b sonnet loop 3 & b sonnet loop 4 & b haiku none 1 & b haiku none 2 & wait
b haiku instructions 1 & b haiku instructions 2 & b haiku check 1 & b haiku check 2 & b haiku plan 1 & b haiku plan 2 & wait
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O \
  sonnet-none-1 sonnet-none-2 sonnet-instructions-1 sonnet-instructions-2 sonnet-check-1 sonnet-check-2 \
  sonnet-plan-1 sonnet-plan-2 sonnet-loop-3 sonnet-loop-4 haiku-none-1 haiku-none-2 haiku-instructions-1 \
  haiku-instructions-2 haiku-check-1 haiku-check-2 haiku-plan-1 haiku-plan-2 > /dev/null
echo "RUNS DONE"
