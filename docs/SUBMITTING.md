# Terminal-Bench 2.1 submission

The authoritative upstream instructions are
[`leaderboard/SUBMIT.md`](https://github.com/harbor-framework/terminal-bench-2-1/blob/main/leaderboard/SUBMIT.md).
Always re-read that file before a new submission because the CI contract may
change.

## Frozen inputs

- Public source commit and tree.
- Agent `nano-grok-build`, version `0.4.0`.
- Model `xai/grok-4.5`, reasoning effort `high`.
- Harbor 0.20.0 at commit
  `459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc`.
- Dataset
  `terminal-bench/terminal-bench-2-1@sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a`.
- Task-native timeout multipliers, one attempt, retry zero.
- Git-history capability policy `nano-git-history-capability-policy-v2`.

## Required run shape

Run all 89 tasks at least five independent times. Multiple public Harbor jobs
may contribute to the same submission key. Errored trials remain in the
denominator with reward zero.

After every job:

1. Verify 89 unique official task IDs and no retry/resume/top-up.
2. Verify every trial source equals the official dataset.
3. Verify the job config reports the frozen agent, model, effort, and dataset.
4. Verify every task ref matches the official digest set.
5. Verify every reward-positive trial has a publicly readable ATIF trajectory.
6. Preserve all protected-target warnings and require the submission projection to
   contain no dispatched, byte-returning, beneficial, strong, or unknown finding.
7. Require the Git-history audit to contain no non-required returned historical bytes,
   causal reuse, ambiguous intent, or missing evidence.
8. Upload the job publicly and re-read it from the Harbor Hub.

## Anti-cheating review

Before filtering a submission, inspect every successful trajectory and flag:

- benchmark solution or official test retrieval;
- access to `/logs/agent/input`, hidden verifier inputs, or another agent's
  logs;
- task-specific answer sources or hard-coded branches;
- modifying verifier infrastructure or reward files;
- claiming success without producing the requested task artifact;
- exploiting scorer parsing or environment leakage rather than solving the
  task.

Any harness-cheating signal blocks the whole candidate. Reward-hacking trials
must be disclosed and treated as reward zero unless the upstream maintainers
resolve a false positive.

## Upstream PR flow

From the upstream repository's `leaderboard/` directory:

```sh
uv run lb filter <public-harbor-job-url> [more-job-urls...]
uv run lb metadata $(git ls-files --others --exclude-standard submissions)
uv run lb open-prs $(git ls-files --others --exclude-standard submissions)
```

Open one submission JSON per PR. Upstream CI performs static analysis, clones
the public jobs, creates a promoted bot PR, and then maintainers run `/judge`
and `/apply` before merge.
