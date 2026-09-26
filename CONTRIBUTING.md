# Contributing

Bug reports, Source suggestions and pull requests are welcome.

## Issues

Use the issue forms: bug report, feature request or a new Catalog Source. Report security problems
privately (see [SECURITY.md](SECURITY.md)). Before pasting logs or config, remove Feed Tokens,
passwords, hostnames and addresses from your own network.

## Pull requests

1. Open an issue first for anything bigger than a small fix, so we agree on the approach.
2. Branch from `dev` and open the pull request against `dev`. `main` holds releases.
3. Run `make setup` once, then `make check` before you push. CI runs the same checks: ruff, mypy
   strict, tests with coverage, bandit, semgrep, pip-audit, gitleaks, Vale and the Docker build.
4. Write tests for new or changed behaviour.
5. Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
   would notice: an emoji, a bold one-line summary, then what changed and what to do about it.
6. Use [Conventional Commits](https://www.conventionalcommits.org/) with a subject of 72
   characters or less, for example `fix(outputs): keep the header on an empty Output`.

## Releases

The release pull request renames `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and bumps the
version in `pyproject.toml`. Pushing the `vX.Y.Z` tag publishes the image, and the GitHub release
notes come from that CHANGELOG.md section.

## Catalog Sources

A new Source needs its licence or terms of use: name, link and whether business use is allowed.
Sources without published terms stay out of the Catalog. Add them as a custom Source instead.

Every change to `src/threatcull/catalog.yaml` raises its `revision` by one: installs pick up the
change with **Check for updates**, and only a higher revision replaces the Catalog they use. Raise
`requires` when the change needs a newer ThreatCull.

## Licence

By contributing you agree that your contribution is licensed under the
[GNU AGPL-3.0](LICENSE).
