#!/bin/bash
set -u

reward=0
if [ -f /workspace/nano-sentinel.txt ] &&
  [ "$(cat /workspace/nano-sentinel.txt)" = "NANO_REMOTE_OK" ]; then
  survivor=false
  for command_line in /proc/[0-9]*/cmdline; do
    value=$(tr '\0' ' ' < "$command_line" 2>/dev/null || true)
    case "$value" in
      *nano-timeout-survivor*) survivor=true ;;
    esac
  done
  bounded=false
  for size_file in /tmp/nano-grok-build-terminal-v1/requests/*/stdout.size; do
    if [ -f "$size_file" ] && [ "$(cat "$size_file")" -gt 4096 ]; then
      binary_file="${size_file%size}bin"
      if [ -f "$binary_file" ] &&
        [ "$(wc -c < "$binary_file")" -le 4096 ]; then
        bounded=true
      fi
    fi
  done
  raw_capture=false
  if compgen -G '/tmp/nano-grok-build-terminal-v1/requests/*/*.raw' >/dev/null; then
    raw_capture=true
  fi
  if [ "$survivor" = "false" ] &&
    [ "$bounded" = "true" ] &&
    [ "$raw_capture" = "false" ]; then
    reward=1
  fi
fi

printf '%s\n' "$reward" > /logs/verifier/reward.txt
test "$reward" = "1"
