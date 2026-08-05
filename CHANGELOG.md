# Changelog

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
