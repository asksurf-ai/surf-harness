# Contributing

Run the complete local gate before opening a pull request:

```sh
python3 scripts/check.py
```

Changes to provider behavior, prompts, tool schemas, scheduling, deadlines,
workspace access, or benchmark metadata must include focused regression tests
and a concise explanation of their generality. Task names, task-specific
branches, benchmark answers, solution repositories, and verifier-specific
shortcuts are not accepted.

Keep changes source-verifiable and public-tree native. Do not rewrite immutable
release tags, force-push published history, or add experiment plans, local run
directories, host-specific fixtures, or unpublished result artifacts.

Never commit credentials, `.env` files, raw private requests, unpublished
trajectories, or benchmark task contents.
