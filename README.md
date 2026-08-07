# Surf Harness

**An audit-first Grok 4.5 terminal-agent harness for Harbor.**

Surf Harness turns `xai/grok-4.5` into a bounded coding agent for isolated
POSIX workspaces. It combines a Rust provider loop, a Python Harbor adapter,
eight typed tools, deterministic lifecycle receipts, and upstream-native ATIF
trajectories. The goal is not just to run an agent, but to make each run
reproducible, containable, and independently reviewable.

The exact source used by the current evaluated cohort is the immutable
[`v0.4.8`](https://github.com/asksurf-ai/surf-harness/tree/v0.4.8) tag. Public
`main` is the post-release maintenance surface. This repository does not claim
a Terminal-Bench score; results become submission candidates only after the
full public-job and trajectory audit described in [Submitting](docs/SUBMITTING.md).

## Why Surf Harness exists

A capable model is only one part of a credible terminal-agent evaluation. The
runtime also has to preserve tool semantics, stop cleanly at deadlines, keep
task effects inside the sandbox, and publish enough evidence to explain both
successes and failures. Surf Harness makes those properties explicit contracts
instead of relying on best-effort logs.

| Mechanism | What it provides | Why it matters |
|---|---|---|
| Grok-derived `nano-v1` contract | Hash-bound prompt, tool descriptions, renderers, and model profile | Reviewers can identify the exact model-facing contract rather than infer it from runtime behavior. |
| Typed Rust runtime | Validated provider events, tool calls, terminal states, and marker-last records | Malformed or partial responses fail closed and remain distinguishable from task failures. |
| Eight bounded tools | Terminal, file read/write/edit, directory listing, grep, background status, and process kill with byte/time/count limits | The agent keeps a practical coding surface without an unbounded host API. |
| Deterministic scheduling | Mutations are serialized; read-only calls have bounded parallelism | Concurrent actions cannot silently reorder workspace mutations. |
| Deadline and cleanup settlement | Signed lifecycle windows, process ownership, termination grace, survivor census, and typed cleanup receipts | A timeout is not treated as complete until tool and process state has been reconciled. |
| Workspace and Git isolation | Before/after receipts, protected-target checks, and instruction-bound Git-history admission | Pre-existing state is not silently turned into an answer oracle, and workspace changes remain inspectable. |
| Immutable evidence | Run-spec, contract, binary, dataset, image, usage, workspace, and publication hashes | A result can be tied back to the exact inputs and artifacts that produced it. |
| ATIF publication | Direct `ATIF-v1.7` trajectories plus deterministic result collection | Successful trials can be reviewed with the same trajectory format used by the upstream leaderboard flow. |

These controls are deliberately task-neutral: task identities and verifier
results do not feed back into the provider policy.

## Relationship to Grok Build

Surf Harness includes modified contract material derived from Grok Build commit
`a5727c5960452e7527a154b25cb5bf00cda0545e`. That material is normalized into
the checked-in [`nano-v1` contract](contracts/nano-v1/), with its changes and
rendering goldens recorded as hash-bound artifacts.

The execution engine itself is an independent Rust/Python implementation built
for Harbor. Contract provenance does not imply source parity, full Grok Build
compatibility, endorsement, or affiliation with xAI. See [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the precise attribution.

## Architecture

```text
task instruction + nano-v1 contract
                 |
                 v
       Rust provider/runtime loop  <---->  xAI Responses API
                 |
       external-tool-stdio-v3
                 |
                 v
       Python Harbor adapter
                 |
                 v
    RemoteTerminalActor in task container
                 |
                 v
 result + runtime receipts + workspace evidence + ATIF trajectory
```

Rust owns provider conversation state and the fail-closed event record. Python
owns Harbor lifecycle integration and sandbox effects. Harbor owns task
resolution, container isolation, and verification. The model never receives
host credentials or the control-plane evidence directory. See
[Architecture](docs/ARCHITECTURE.md) for the trust boundaries and lifecycle.

## Trial lifecycle

1. **Bind inputs.** Freeze the model profile, contract hash, runtime binary,
   task digest, tool limits, retry policy, and native task timeout.
2. **Admit the workspace.** Census Git topology, isolate history when required,
   verify protected targets, and capture the initial workspace state.
3. **Execute within bounds.** Validate provider events, dispatch typed tool
   requests, serialize mutations, and account for provider/tool usage.
4. **Settle and publish.** Reconcile background processes, capture the final
   workspace, write terminal records marker-last, and emit ATIF/result evidence.
5. **Audit offline.** Recompute inventory, identity, retry-zero, artifact,
   protected-target, Git-history, and rewarded-trajectory gates without changing
   the run.

## Local bootstrap

Use Python `3.12.11` and Rust `1.97.1`. The no-network static gate can run before
installing repository dependencies:

```sh
python3 scripts/check.py --preflight-only
```

Run the complete locked build and test gate:

```sh
python3 scripts/check.py
```

To inspect the pinned Terminal-Bench 2.1 plan without credentials, containers,
or provider calls, check out Harbor and Terminal-Bench at the commits listed in
[Submitting](docs/SUBMITTING.md), then run:

```sh
python3 tests/harbor/run_tb21.py \
  --plan-only \
  --harbor-checkout <harbor-checkout> \
  --tb21-checkout <terminal-bench-2-1-checkout> \
  --all \
  --concurrency 2
```

The formal runner additionally requires a built `nano-cli`, the checked-in
`contracts/nano-v1` directory, Docker readiness, and `XAI_API_KEY`. Run
`python3 tests/harbor/run_tb21.py --help` for the full argument contract.

## Terminal-Bench 2.1 integrity

The release pins Harbor `0.20.0` and the official Terminal-Bench 2.1 dataset
digest. Formal evidence uses all 89 tasks, at least five independent trials per
task, task-native timeouts, one attempt, retry zero, and publicly readable
Harbor jobs. Reward-positive trajectories are reviewed for benchmark leakage,
verifier manipulation, reward hacking, and protected-target access before an
upstream submission is prepared.

Typed provider, tool, verifier, or cleanup errors remain visible denominator
trials; they are never silently retried, replaced, or dropped. Integrity loss
such as identity drift, missing artifacts, cross-trial contamination, or an
actual containment breach blocks the candidate.

## Project guide

- [Architecture](docs/ARCHITECTURE.md) — runtime, sandbox, and evidence boundaries
- [Submitting](docs/SUBMITTING.md) — reproducible TB2.1 evidence and upstream flow
- [Contributing](CONTRIBUTING.md) — task-neutral changes and required checks
- [Security](SECURITY.md) — vulnerability reporting and deployment scope
- [Changelog](CHANGELOG.md) — immutable evaluated releases and maintenance history
- [Source manifest](SOURCE-MANIFEST.json) and [SPDX SBOM](SBOM.spdx.json) — public-tree and dependency provenance

## License and non-affiliation

Surf Harness is licensed under Apache-2.0. This independent community project
is not affiliated with, endorsed by, or sponsored by xAI. “xAI”, “Grok”, and
model IDs identify source provenance and runtime targets only. No trademark
rights, exact source parity, or full Grok Build compatibility are claimed.
