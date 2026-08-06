# Changelog

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
  protected Mimir plan and receipt provenance.

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

This release starts a fresh five-run evaluation cohort. It does not reuse or
repair V10.1 evidence and does not claim a leaderboard score before review.

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
