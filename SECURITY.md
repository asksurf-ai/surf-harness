# Security policy

Please report vulnerabilities privately to the maintainers through GitHub's
private vulnerability reporting for this repository. Do not open a public
issue containing credentials, exploit payloads, private trajectories, or
benchmark answers.

Security fixes target the latest public `main`. The immutable `v0.5.0` tag is
the current evaluated source identity; a fix that changes evaluated runtime
behavior requires a new version rather than moving that tag. Security-sensitive
boundaries include:

- host credential isolation;
- sandbox path and process ownership;
- external stdio framing;
- timeout and cancellation settlement;
- artifact and trajectory publication;
- contract and dependency integrity;
- public export allowlists.

The project is an evaluation harness, not a general multi-tenant execution
service. Deployments must add their own authentication, authorization,
networking, rate limits, and operational monitoring.
