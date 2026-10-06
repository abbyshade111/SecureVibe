#!/bin/sh
# Item 6, amendment 4: the check and plan arms again, with the other tools hidden. Twenty builds, ten at a time.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export SV=/tmp/claude-502/sv-item6-target/release/sv SV_REPO=/tmp/claude-502/wtc-wt KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-loop6
for a in checkhidden planhidden; do
  for m in sonnet haiku; do for n in 1 2 3 4 5; do python3 $T $O $a $m $n --budget 1.5 --api --with-spec & done; done
  wait
done
echo "key-in-transcripts: $(cat $O/*hidden*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
