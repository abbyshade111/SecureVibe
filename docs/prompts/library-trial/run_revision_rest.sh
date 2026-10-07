#!/bin/sh
# The revision trial's 38 builds that the API credit outage stopped (7 October 2026), re-run after the owner's top-up,
# with everything else exactly as run_revision.sh; then sv report --run on every build without a finished report.
export CLAUDE_BIN="$HOME/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude"
export KEY_HELPER=/tmp/claude-502/loop/key_helper.sh SV=/tmp/claude-502/sv-revision-target/release/sv SV_REPO=/tmp/claude-502/rv-run
T=/tmp/claude-502/loop/loop_trial.py; O=~/sv-revision
cd $O || exit 1
F=$(grep -l '"billing_error"' *.jsonl | sed 's/.jsonl$//')
echo "stopped by the outage: $(echo $F | wc -w)"
mkdir -p no-credit/runs
for b in $F; do
  mv "$b.jsonl" no-credit/; [ -d "$b" ] && mv "$b" no-credit/
  for x in runs/$b-out runs/$b.log runs/$b.summary; do [ -e "$x" ] && mv "$x" no-credit/runs/; done
done
b() { python3 $T $O none $1 $2 --budget 1.5 --api --with-spec --allow-git $3; }
batch() { for x in $1; do m=${x%%:*}; rest=${x#*:}; p=${rest%:*}; n=${rest##*:}
  if [ -z "$p" ]; then b $m $n "" & else b $m $n "--prompt $p" & fi; done; wait; }
G=""; for x in $F; do case $x in haiku-p_git_from_the_start-*) G="$G haiku:git-from-the-start:${x##*-}";; esac; done
batch "$G"
for arm in "" ai-feature-guard isolate-the-window; do
  S=""; lab=$( [ -z "$arm" ] && echo none || echo "p_$(echo $arm | tr - _)")
  for x in $F; do case $x in sonnet-$lab-*) S="$S sonnet:$arm:${x##*-}";; esac; done
  batch "$S"
done
echo "still billing errors: $(grep -l '"billing_error"' *.jsonl 2>/dev/null | wc -l)"
echo "key-in-transcripts: $(cat $O/*.jsonl | grep -c 'sk-ant-')"
echo "BUILDS DONE"
TODO=$(for j in *.jsonl; do x=${j%.jsonl}; [ -f runs/$x-out/report.json ] || echo $x; done)
echo "to check: $(echo $TODO | wc -w)"
python3 /tmp/claude-502/loop/prompt_trial.py $O $TODO > /dev/null
echo "RUNS DONE"
