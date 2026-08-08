# Architecture

Surf Harness separates provider state, task effects, and evaluation evidence so
each boundary can be validated independently.

## Contract and provider boundary

`nano-cli` loads one hash-bound `nano-v1` contract and run specification. The
contract fixes the system prompt, model profile, eight tool schemas, renderers,
limits, and context policy. The Rust runtime validates complete xAI Responses
events before admitting tool calls, records provider usage, and writes a
marker-last terminal record. A transport failure may replay the exact request
body once only before a validated response or tool side effect.

The Harbor host explicitly selects `semantic-checkpoint-v5`. Its completion
review is the unchanged Fresh Evidence-Debt V3 path. Separately, after at least
12 settled provider turns, 250,000 observed input tokens, and 32 history items,
one tools-disabled prepare request may produce a closed, byte-bounded semantic
capsule. The gate also requires no unresolved background task, 13 provider
turns of capacity, and more than 990 seconds before the last-send cutoff. It
never reads task identity, reward, verifier output, or previous benchmark
results.

The workspace and runtime state are not reset. An accepted four-item history
contains the original system prompt, wrapped request, canonical capsule, and an
untrusted-continuity notice that requires minimal current-state reinspection.
A 900-second tail and `max_provider_turns - 6` action cutoff preserve one soft
action, one provisional response, and the full Fresh V3 review. Invalid
capsules emit `context.checkpoint_rejected` and retain the old history.

`run.started` records positive policy/schema provenance. The prepare request
binds the uncompacted source hash, while `context.checkpointed` binds prepare,
capsule, reset, counter, and lease facts. Artifactizer and collector validators
require the next request to bind the new four-item history; duplicate,
mistimed, unbound, or counter-inconsistent chains invalidate the runtime prefix.

This boundary keeps model-facing behavior reviewable: a run names the precise
contract and binary hashes instead of relying on a mutable deployment label.

## Sandbox and tool boundary

The Python adapter implements Harbor's agent interface. Tool requests cross the
versioned `external-tool-stdio-v3` protocol to `RemoteTerminalActor`, which
executes inside the Harbor environment. The actor validates paths, byte/count
limits, process ownership, operation timeouts, and completion receipts.
Mutating tools are serialized while read-only tools use bounded parallelism.

Provider credentials and the Rust loop stay outside the task container. Task
commands do not receive the host environment or the control-plane evidence
directory. Protected-target policy blocks access to harness inputs and agent
logs before dispatch.

## Deadline and cleanup boundary

Every request carries absolute lifecycle windows for actor work, tool
settlement, final runtime publication, and cleanup. Foreground and background
processes remain owned until they terminate or are explicitly reconciled.
Cleanup receipts record the subprocess return code, phase, task identity, and a
post-exit survivor census; local child exit alone is not proof of remote cleanup.

Typed provider, tool, verifier, and cleanup failures remain ordinary terminal
results. They are not converted into success and are not silently replaced by a
retry. Evidence of an actual survivor or cross-trial contamination is a distinct
containment failure.

## Workspace and Git boundary

The adapter captures bounded before/after workspace manifests and publishes a
receipt, delta, patch, and changed-file archive. Git topology is censused before
provider start. Existing history is isolated or preserved only when an
instruction-bound capability authorizes it; ambiguous topology fails closed.
The post-run audit checks that non-required historical bytes were not returned
to or causally reused by the model.

These controls reduce two common sources of irreproducibility: hidden initial
state and unverifiable workspace mutation.

## Evidence and publication boundary

Each trial binds the official task digest, contract hash, runtime binary hash,
model, turn cap, retry policy, and task-native timeout before execution.
Terminalization preserves typed failures, usage lower bounds, workspace state,
Git admission, process settlement, and publication hashes. Successful
publications include a direct `ATIF-v1.7` trajectory suitable for upstream
review.

The deterministic collector and submission preflight are downstream of runtime
behavior. They recompute identity, result, artifact, protected-target, Git, and
trajectory projections without modifying rewards or feeding task identities,
scores, or verifier output back into the model policy.

## Evaluation boundary

The TB2.1 runner resolves the pinned official package dataset rather than local
task directories. Its Harbor configuration reports the exact agent, version,
model, and reasoning-effort tuple consumed by the leaderboard filter. One
attempt and retry zero make every terminal trial part of the submitted
denominator, including well-formed errors.
