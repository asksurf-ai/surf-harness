# Surf Harness

Surf Harness is a small, headless terminal coding-agent runtime for running
`xai/grok-4.5` in Harbor-isolated POSIX workspaces. It exposes eight bounded
filesystem and process tools, records deterministic runtime evidence, exports
ATIF trajectories, and includes a pinned Terminal-Bench 2.1 runner.

This repository is the public release and evaluation surface for the internal
`nano-grok-build` runtime. The Python import path and raw Harbor agent identity
remain `nano_grok_build` and `nano-grok-build` for compatibility. The public
project and display name are Surf Harness.

Version `0.4.0` retains the exact, owner-approved task-neutral
workspace-integrity contract and adds policy-v2 Git-history admission plus
safe-metadata-only TB2.1 inventory authority. No leaderboard score is claimed
until five complete, public, audited jobs pass the upstream submission checks.

## What is included

- Four Rust crates for the CLI, xAI Responses transport, provider loop, and
  strict runtime types.
- A Python Harbor 0.20.0 adapter, sandbox tool actor, ATIF publisher,
  deterministic collector, prelaunch checks, and TB2.1 runner.
- The exact public protected-target policy used by both the runtime guard and
  collector; the wheel packages these same bytes without a second copy.
- The exact approved `nano-v1` contract and required Apache/MIT notices.
- Runtime schemas, locked dependencies, core regression tests, and public CI.

The export intentionally omits internal experiment reports, legacy design
documents, development plans, private review worktrees, historical governance
machinery, credentials, benchmark task contents, and prior run outputs.

## Architecture

```text
Terminal-Bench task
       |
       v
Harbor Job / Docker sandbox
       |
       v
Python adapter ---- external-tool-stdio-v3 ----> sandbox tool actor
       |
       v
Rust nano-cli -> xAI Responses API
       |
       v
runtime records + workspace receipt + ATIF trajectory + Harbor result
```

Rust owns provider conversation state and the fail-closed event record. Python
owns Harbor lifecycle integration and sandbox effects. Harbor owns task
resolution, container isolation, and verification. See
[Architecture](docs/ARCHITECTURE.md).

## Local bootstrap

Use Rust `1.97.1` and Python `3.12.11`. The unified entry runs a pure-stdlib
static preflight before installing or executing repository-pinned tools:

```sh
python3 scripts/check.py
```

The command runs Rust format, clippy, and tests; Python format, lint, tests,
locked build, and wheel import; dependency policy; and secret checks.

## Inspect the pinned TB2.1 plan

Clone the exact upstream checkouts first:

- Harbor `v0.20.0`, commit
  `459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc`
- Terminal-Bench 2.1, commit
  `5c8eadf1f393183288fa08b8f73ca9a469cc5e00`

Then inspect the exact 89-task plan without credentials or containers:

```sh
python3 tests/harbor/run_tb21.py \
  --plan-only \
  --harbor-checkout <harbor-checkout> \
  --tb21-checkout <terminal-bench-2-1-checkout> \
  --all \
  --concurrency 2
```

Formal runs resolve:

```text
terminal-bench/terminal-bench-2-1@sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a
```

and report the Harbor metadata key:

```text
agent=nano-grok-build
agent_version=0.4.0
model=xai/grok-4.5
reasoning_effort=high
```

The live runner additionally requires a built `nano-cli`, the checked-in
`contracts/nano-v1` directory, Docker readiness, `XAI_API_KEY`, and the
prelaunch arguments described by `run_tb21.py --help`.

## Submission integrity

Formal leaderboard evidence must be produced from a clean public commit, with
89 tasks × at least 5 independent trials, task-native timeouts, one attempt,
retry zero, and publicly readable Harbor jobs and ATIF trajectories.

The harness must never access benchmark solutions, hidden verifier material,
`/logs/agent/input`, another agent's logs, or task-specific answer sources.
Reward-positive trials are reviewed before submission for both reward hacking
and harness cheating. See [Submitting](docs/SUBMITTING.md).

## Internal-to-public release flow

1. Develop and test a candidate in the private engineering repository.
2. Freeze package/agent version, contract, dataset, Harbor pin, and source
   commit.
3. Run the deterministic allowlist exporter to create this public tree.
4. Run all public gates from the exported tree and commit it as one public
   release commit.
5. Run the full benchmark from that exact public commit.
6. Upload the unmodified Harbor jobs publicly, audit every successful
   trajectory, then create the leaderboard submission PR.

Public contributions are welcome. Because public and private histories differ,
accepted public changes are ported into the internal development repository
and returned through the same deterministic exporter.

## License and non-affiliation

The project is licensed under Apache-2.0. See [LICENSE](LICENSE),
[NOTICE](NOTICE), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

This independent community project is not affiliated with, endorsed by, or
sponsored by xAI. “xAI”, “Grok”, and model IDs identify source provenance and
compatibility targets only. No trademark rights, exact source parity, or full
Grok Build compatibility are claimed.
