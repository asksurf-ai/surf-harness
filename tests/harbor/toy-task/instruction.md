Use `run_terminal_command` to create `/workspace/nano-sentinel.txt` containing
exactly `NANO_REMOTE_OK`. The same command must emit more than 4,096 bytes to
stdout so the verifier can check bounded binary-safe terminal transport. For
example, create the file and then run `head -c 20000 /dev/zero`. Do not only
describe the work: execute it, verify it, then finish.
