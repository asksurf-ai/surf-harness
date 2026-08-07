#!/bin/bash
set -u

workspace=${NANO_LIVE_WORKSPACE:-/workspace}
logs=${NANO_LIVE_LOGS:-/logs/verifier}
reward=0
if [ -f "$workspace/nano-sentinel.txt" ] &&
  [ "$(cat "$workspace/nano-sentinel.txt")" = "NANO_REMOTE_OK" ]; then
  reward=1
fi

printf '%s\n' "$reward" > "$logs/reward.txt"
test "$reward" = "1"
