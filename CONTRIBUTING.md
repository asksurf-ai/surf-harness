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

The private engineering repository and this public repository have different
histories. Accepted public patches are ported into the internal development
tree, validated there, and mirrored back through the deterministic exporter.
Do not resolve drift by force-pushing either history or by copying internal
documents and run artifacts into the public tree.

Never commit credentials, `.env` files, raw private requests, unpublished
trajectories, or benchmark task contents.
