#!/bin/bash
set -u

reachable=false
response=
for _ in $(seq 1 100); do
  response=$(
    perl -MIO::Socket::INET -e '
      $socket = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1",
        PeerPort => 18765,
        Proto => "tcp",
        Timeout => 1,
      ) or exit 1;
      print scalar <$socket>;
    ' 2>/dev/null
  ) || true
  if [ "$response" = "NANO_BACKGROUND_OK" ]; then
    reachable=true
    break
  fi
  sleep 0.02
done

service_running=false
for command_line in /proc/[0-9]*/cmdline; do
  value=$(tr '\0' ' ' < "$command_line" 2>/dev/null || true)
  case "$value" in
    *[n]ano-background-service*) service_running=true ;;
  esac
done

reward=0
if [ "$reachable" = "true" ] && [ "$service_running" = "true" ]; then
  reward=1
fi

printf '{"reachable":%s,"response":"%s","service_running":%s}\n' \
  "$reachable" "$response" "$service_running" \
  > /logs/verifier/reachability.json
printf '%s\n' "$reward" > /logs/verifier/reward.txt
test "$reward" = "1"
