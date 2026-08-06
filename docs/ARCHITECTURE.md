# Architecture

Surf Harness separates trusted provider state from untrusted task effects.

## Runtime boundary

`nano-cli` loads one hash-bound contract and run specification. The Rust
runtime validates complete model responses before admitting tool calls,
serializes mutating effects, bounds read-only parallelism, and writes a
marker-last event record. A transport failure may replay the exact request
body once only before a validated response or tool side effect.

## Sandbox boundary

The Python adapter implements Harbor's agent interface. Tool requests cross a
versioned stdio protocol to `RemoteTerminalActor`, which executes inside the
Harbor environment. The actor validates paths, byte limits, process ownership,
timeouts, and completion receipts. Provider credentials and the Rust loop stay
on the host; task commands do not.

## Lifecycle and evidence

Each trial binds the official task digest, contract hash, runtime binary hash,
model, turn cap, retry policy, and native task timeout before execution.
Terminalization preserves typed provider/tool failures, usage lower bounds,
workspace capture state, and cleanup evidence. Successful publications include
an ATIF trajectory suitable for leaderboard audit.

## Evaluation boundary

The TB2.1 runner resolves the official package dataset rather than presenting
local task paths as an ad-hoc source. Its Harbor config reports the exact
agent/model/reasoning-effort tuple used by the leaderboard filter. Evaluation
collection is downstream of runtime behavior and does not feed task identities,
scores, or verifier output back into the model policy.
