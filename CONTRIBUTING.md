# Contributing

Bug reports, feature ideas and Catalog Source suggestions are welcome.

## Contributions at the moment

ThreatCull doesn't accept code pull requests from outside contributors right now.

Issues are welcome: bug reports, feature ideas, and new Catalog Sources through the
**Add a Source to the Catalog** issue form.

If you have a fix, describe it in an issue instead of posting a patch: say what's wrong and the
idea behind the fix, and the maintainer will implement it.

This may change in the future. If it does, contributors will be asked to sign a Contributor
License Agreement first.

## Issues

Use the issue forms: bug report, feature request or a new Catalog Source. Report security problems
privately (see [SECURITY.md](SECURITY.md)). Before pasting logs or config, remove Feed Tokens,
passwords, hostnames and addresses from your own network.

## Development

How the maintainer builds and changes ThreatCull:

1. Open an issue first for anything bigger than a small fix, so the approach is agreed.
2. Branch from `dev` and open the pull request against `dev`. `main` holds releases.
3. Run `make setup` once, then `make check` before you push. CI runs ruff (with its bandit
   rules), mypy strict, the test suite, semgrep, CodeQL, pip-audit, gitleaks, Vale and the Docker
   build with a smoke test. Each job runs only when the pull request changes files it checks. To build the image yourself, run `docker login dhi.io` with a free Docker account
   first (the base is a Docker Hardened Image), or build on the standard image instead:
   `docker build --build-arg PYTHON_BUILD_IMAGE=python:3.15-slim --build-arg
   PYTHON_RUNTIME_IMAGE=python:3.15-slim .`
4. Add or change tests in `tests/` with the code. `make test` runs the offline suite; tests
   marked `network` reach real upstream URLs and run only with `uv run pytest -m network`.
5. Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
   would notice: an emoji, a bold one-line summary, then what changed and what to do about it.
6. Use [Conventional Commits](https://www.conventionalcommits.org/) with a subject of 72
   characters or less, for example `fix(outputs): keep the header on an empty Output`.

## Releases

The usual way: a release pull request renames `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and
bumps the version in `pyproject.toml`; after it reaches `main`, pushing the `vX.Y.Z` tag publishes the
image and the GitHub release, with its notes taken from that CHANGELOG.md section.

A release made in the GitHub Release UI works too: tag `vX.Y.Z` on `main`. The Release workflow
builds that version even if `pyproject.toml` still has the previous one (it warns), and keeps the
notes written in the UI when CHANGELOG.md has no section for the version. Bump `pyproject.toml` in the
next pull request.

## Catalog Sources

[docs/CATALOG.md](docs/CATALOG.md) lists every Source, the areas where more are wanted and what a
new one needs: a working public feed that adds coverage the Catalog lacks.

Every change to `src/threatcull/catalog.yaml` raises its `revision` by one: installs pick up the
change with **Check for updates**, and only a higher revision replaces the Catalog they use. Raise
`requires` when the change needs a newer ThreatCull. Run `make catalog-docs` to refresh the tables
in [the Catalog page](docs/CATALOG.md); CI fails when they don't match.

A workflow (`.github/workflows/catalog-health.yml`) downloads every Catalog Source and keeps
one open issue, "Catalog health: Sources need attention" with the `catalog-health` label, listing
Sources that failed, served an HTML page, could not be parsed or had no valid entries two weeks in a
row, and blocklists whose entries have not changed for 30 days. Its history lives in `state.json` on the `catalog-health` branch; never merge that
branch. It runs every Monday at 05:00 UTC; to check sooner, start it from the Actions tab with
**Run workflow**.

## Licence

ThreatCull is licensed under the [GNU AGPL-3.0](LICENSE). Outside code contributions aren't
accepted at the moment; see [Contributions at the moment](#contributions-at-the-moment).
