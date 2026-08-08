# Changelog

## 0.5.3

- Preserve the complete isolated completion critic when its 600-second path
  fits, and add one reserve-aware same-context acceptance review below it.
- Admit the late path only with strict actor, last-send, provider-turn,
  history, and function-call capacity for one provider response, one bounded
  tool batch, and a final response.
- Close the late path to tools-disabled FinalOnly after its single batch and
  preserve an unmutated provisional final on provider/tool failure.
- Record `completion_late_review` as a typed budget phase and validate the new
  `semantic-checkpoint-v7` provenance through runtime, artifactizer, and
  collector boundaries.
- Treat 0.5.2's paired 8/12 tie as a no-go. This version requires fresh raw
  paired uplift and a no-regression guardrail before any K=5 run or uplift claim.

## 0.5.2

- Replace the failure-prone, tools-disabled semantic prepare request with a
  strict runtime-owned checkpoint function in the next normal action response.
- Permit ordinary workspace calls in that response, settle them through the
  unchanged sandbox path, and bind their bounded evidence before resetting
  history; the internal control call has no workspace authority or tool budget.
- Enforce a closed nine-field argument schema with field/list bounds, retain the
  canonical 8,192-byte runtime cap, and fail open once for missing, duplicate,
  malformed, or over-limit capsules.
- Add hash/byte rejection diagnostics, bounded ATIF checkpoint audit receipts,
  inline event-prefix validation, and closed call-limit recovery relations.
- Give the changed inline relation the new `semantic-checkpoint-v6` label while
  keeping legacy `v5` readable only with its historical prepare relation.
- Treat 0.5.1's 351/445 K=5 result as a no-go. This version requires fresh
  positive provider-on paired evidence before any K=5 or uplift claim.

## 0.5.1

- Replace the lossy fresh reset with one tools-disabled semantic prepare phase
  whose closed JSON capsule is byte-bounded, canonicalized, and hash-bound to
  the uncompacted source history.
- Freeze a 900-second post-checkpoint tail for one bounded soft action,
  provisional final, and the complete Fresh Evidence-Debt V3 review path; the
  strict prepare admission reserve is greater than 990 seconds.
- Preserve six provider responses at the action cutoff—soft action,
  provisional, and four worst-case review responses—and record the corrected
  `max_provider_turns - 6` lease in the checkpoint receipt.
- Add positive policy/schema provenance plus typed accepted/rejected checkpoint
  events, with strict runtime, artifactizer, and collector hash-chain checks.
- Keep this release blocked until a pre-registered paired-12 evaluation shows
  at least one native-raw task of uplift without new integrity regressions.

## 0.5.0

- Add a single task-neutral fresh-context checkpoint for long trajectories after
  at least 12 provider turns, 250,000 observed input tokens, 32 history items,
  and sufficient remaining turn and deadline capacity.
- Preserve the original task, current workspace, a bounded structural evidence
  ledger, and recent tool evidence while removing stale conversational history.
- Emit a typed `context.checkpointed` receipt and require the next provider
  request to bind the exact three-item checkpoint history; collectors reject
  duplicate, mistimed, counter-mismatched, or unbound checkpoint events.
- Retain Fresh Evidence-Debt V3 completion review and all existing attempt-one,
  retry-zero, deadline, cleanup, workspace, ATIF, and reward-hacking controls.

## 0.4.9

- Restore Fresh Evidence-Debt V3 after the pre-registered 0.4.8 paired smoke
  showed no raw uplift and regressed strict score, reliability, and observed cost.
- Preserve an already-audited provisional completion when a completion review
  provider call fails or times out without any review-stage workspace mutation.
  Provider failure telemetry remains explicit; corrected work still fails closed
  rather than falling back to a stale completion.
- Keep exact Harbor cost separate from explicitly labelled observed lower bounds
  when provider cost coverage is partial.

## 0.4.8

- Restore Evidence-Debt V2 as the default completion review after the 0.4.7
  five-run cohort did not establish raw uplift for Fresh Evidence-Debt V3.
- Retain the bounded finish controller, deadlines, background ownership,
  workspace capture, retry-zero execution, and truthful ATIF publication.
- Normalize offset-aware and offset-naive Harbor timestamps to UTC before
  verifier-exception ordering so completed rows remain collectable.
- Publish exact `cost_usd` only at complete provider-usage coverage; otherwise
  preserve the observed amount as an explicitly labelled lower bound.
- Add an internal protected paired-smoke lane with an exact pre-registered
  12-task selection. This orchestration is not part of leaderboard submission.

## 0.4.7

- Align the model-visible terminal, background-wait, output-byte, descendant
  ownership, and media contract with the existing bounded runtime profile.
- Turn denied Git-history requests into bounded actionable observations while
  preserving whole-call rejection and an unchanged workspace.
- Add a monotonic finish/review controller with bounded fresh-critic review,
  truthful fallback, and deadline-aware action closure.
- Select the fresh-evidence-debt-v3 review policy without changing the official
  task inventory, resources, timeouts, attempt count, retry-zero rule, or ATIF.

## 0.4.6

- Align remote workspace-inventory production with the fail-closed parser by
  pruning excluded names case-insensitively for every filesystem object kind.
- Add a Linux real-script regression that proves regular files and case variants
  cannot be emitted only to be rejected during inventory parsing.
- Keep archive, size, path, uniqueness, mode, and content-budget validation
  unchanged; this is a narrow producer/parser consistency fix.
- Reposition the public documentation around the audit-first Grok 4.5 runtime,
  Grok Build-derived contract, bounded tools, cleanup settlement, immutable
  evidence, and ATIF publication.
- Remove host-bound historical-result and unreferenced task-selected diagnostics;
  add a public-content gate for local paths, process residue, and task literals.
- Mark `v0.4.5`, public commit
  `d10deb059861c4042ba3b175b3f7b2cf5c097325`, and controller digest
  `sha256:e583160c65b4d2574a36b921dfc3cc44cfd51d0b52e100e6da2234aaff5ce0b7`
  **superseded-not-fixed** after its production cohort exposed repeated workspace
  inventory parse failures. Preserved cohort evidence remains immutable.

## 0.4.5

- Preserve typed external-bridge failure receipts with subprocess return code,
  execution phase, task identity, and cleanup evidence instead of collapsing
  failures into an untyped nonzero exit.
- Require a remote post-exit process census before cleanup can be verified; local
  child exit alone is not evidence that the remote actor left no survivors.
- Keep typed provider deadline, tool settlement, and cleanup failures as official
  errored denominator trials. Campaign stop remains limited to actual identity,
  containment, publication, retry-zero, artifact, or measurement-integrity loss.
- Mark `v0.4.4`, public commit
  `770a02fa0afaf16882bb449c07319164f4c96564`, and controller digest
  `sha256:cf23d5c9db07aa89a88232536bc97b4f9e837df472a1bd5ce07cbc78ec6990fe`
  **superseded-not-fixed** after its production cohort exposed lossy bridge failure
  reporting and insufficient remote-cleanup evidence. The new release does not
  claim to eliminate provider or tool deadlines.

## 0.4.4

- Admit a stable zero-repository workspace as canonical `absent_clean` without
  invoking task-image Git; retain strict isolation/preservation for root, nested,
  required, and ambiguous topologies.
- Fail fast locally after two distinct exact provider-zero setup failures, while
  permanently disabling that trigger after any agent/provider start.
- Remove the superseded public setup-smoke diagnostic and keep post-run submission
  preflight as the clean-submission authority.
- Mark published `v0.4.3`, public commit
  `2fc52871477efc805a68a0811c6bcb1b1343a4cf`, and controller digest
  `sha256:85ad69caf106c8bef40c16969ed92f089acffcca5c4e306f9a58c8d276a3781f`
  **superseded-not-fixed** after the production run exposed an undeclared task-image
  Git prerequisite and was force-terminated with preserved evidence.

## 0.4.3

- Preserve the caller's exact runtime-Python invocation path when setup admission
  compares it with the running interpreter, while retaining strict resolved-target
  and pinned-byte identity checks.
- Add regression coverage for the official Harbor virtual-environment symlink and
  for distinct invocations that resolve to the same interpreter.
- Mark published `v0.4.2`, public commit
  `2116ce4cc08e9618fc3626986c748b134079eb7f`, and controller digest
  `sha256:e4fb17d375528b9aea00d8d5ee7f1b79be7a1d7e0c95e1c526a5e39577f7248d`
  **superseded-not-fixed** after the formal setup runner prematurely resolved the
  selected symlink invocation. These identities remain immutable historical
  evidence and are not moved, deleted, rebuilt, or represented as repaired.

## 0.4.2

- Accept strict tag-form or digest-form task image references from the exact pinned
  TB2.1 inventory while retaining digest-only controller identity.
- Bind every unique task image source ref to one locally resolved immutable image ID,
  reverify those bindings immediately before setup, and record both identities.
- Mark the published `v0.4.1` controller digest
  `sha256:37bbea63b4b8e76fd9ead3c9e2afd2fb32a6b01a99a304b7992026712811b808`
  **superseded-not-fixed** after its setup smoke deterministically rejected all 89
  official `:20251031` task-image refs. The immutable `v0.4.1` source tag remains
  historical and is not moved, deleted, or represented as repaired.

## 0.4.1

- Admit plain, root-repository, and unique nested-repository workspaces through a
  no-follow, fail-closed Git topology census before capture or provider setup.
- Bind created, isolated, or preserved history state to canonical baseline-receipt
  v2 topology, census, workspace-manifest, and repository identity evidence.
- Freeze the exact 89-task Git-history authority and add a provider-free setup-only
  smoke seam; retain one history-required task and 88 history-not-required tasks.
- Remove obsolete paid-POC and staged-promotion controller surfaces; the active
  controller is full-only and retains protected admission, HMAC, five-run,
  terminal, failure-publication, and finalize gates.

## 0.4.0

- Isolate pre-existing Git history by a task-neutral, instruction-bound capability
  compiled before the provider starts.
- Bind authoritative TB2.1 plans to exact clean upstream repository commits and
  root trees, the official 89-task manifest, and a closed public-metadata digest
  scope that never represents itself as a full-task checksum.
- Persist and recheck inventory authority and history-capability projections in
  protected campaign plan and receipt provenance.

History capability records retain schema `nano-git-history-capability-v1`, while
their compiler policy advances from `nano-git-history-capability-policy-v1` to
`nano-git-history-capability-policy-v2`. V1 records remain historical evidence;
new 0.4.0 runs compile and validate V2 records and fail closed on a mixed policy.
The eight owner-approved contract/notice artifacts are byte-identical to 0.3.0.
This release requires a new public commit and a completely fresh five-run cohort.

## 0.3.0

- Publish workspace archives up to the exact 80 MiB protocol bound while retaining
  the 64 MiB captured-payload and 256 MiB aggregate limits.
- Separate blocked-before-dispatch warnings from actual protected access in the
  submission gate while preserving the conservative raw audit.
- Add task-neutral Git-history oracle behavior auditing and fail-closed preflight.
- Export the new audit implementation and tests under one deterministic,
  owner-approved release identity.

The exact-hash owner approval covers the workspace-integrity contract. A fresh,
audited five-run cohort follows from the final public release commit.

## 0.2.0

- Isolate run control artifacts from the task-visible agent log mount.
- Block task-neutral protected harness targets before tool dispatch.
- Publish truthful ATIF trajectories for failed and emergency runs.
- Package one shared protected-target policy for runtime and collector parity.
- Export the offline clean-submission preflight when integrated.

This release starts a fresh five-run evaluation cohort and does not claim a
leaderboard score before review.

## 0.1.0

- Publish the bounded Rust provider/runtime and Python Harbor adapter.
- Include the exact approved `nano-v1` contract and required notices.
- Pin Harbor 0.20.0 and the Terminal-Bench 2.1 dataset digest.
- Emit leaderboard-compatible agent, model, reasoning-effort, and dataset
  metadata.
- Add deterministic runtime evidence, ATIF publication, workspace receipts,
  retry-zero execution, and full public release gates.

This release does not claim a Terminal-Bench leaderboard score. Formal 89 × 5
evaluation and trajectory review follow the public commit.
