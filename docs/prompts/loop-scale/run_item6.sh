#!/bin/sh
# Item 6: fifty builds (five arms, two models, five each), eight at a time, then sv report --run on each.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export SV=/tmp/claude-502/sv-item6-target/release/sv SV_REPO=/tmp/claude-502/wtc-wt KEY_HELPER=/tmp/claude-502/loop/key_helper.sh
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-loop6
mkdir -p $O && cp /tmp/claude-502/sv-trial/docs/prompts/trial/policy.toml $O/
ALL=""
for m in sonnet haiku; do for a in none instructions check plan loop; do for n in 1 2 3 4 5; do ALL="$ALL $m:$a:$n"; done; done; done
set -- $ALL
while [ $# -gt 0 ]; do
  for i in 1 2 3 4 5 6 7 8; do
    [ $# -gt 0 ] || break
    IFS=: read m a n <<X
$1
X
    python3 $T $O $a $m $n --budget 1.5 --api --with-spec &
    shift
  done
  wait
done
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
cd $O && python3 /tmp/claude-502/loop/prompt_trial.py $O $(for x in $ALL; do echo $x | awk -F: '{print $1"-"$2"-"$3}'; done) > /dev/null
echo "RUNS DONE"
