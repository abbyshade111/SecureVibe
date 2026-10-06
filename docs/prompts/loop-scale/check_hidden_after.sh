#!/bin/sh
# Waits for item 6's fifty sv runs to finish, then runs sv report --run on the twenty hidden-arm builds, one at a time.
O=~/sv-loop6
while [ $(ls $O/runs/*.summary 2>/dev/null | wc -l) -lt 50 ]; do sleep 60; done
export SV=/tmp/claude-502/sv-item6-target/release/sv
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(ls *hidden*.jsonl | sed 's/.jsonl//') > /dev/null
echo "HIDDEN RUNS DONE"
