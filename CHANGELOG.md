# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are tagged `vX.Y.Z`
and published as `ghcr.io/spydisec/threatcull` for linux/amd64 and linux/arm64.

## [Unreleased]

### Changed

- 📡 **See what a run is doing.** The status line on the dashboard and Runs page names the step
  ("Fetching *Source* (3 of 10)" or "Compiling the Outputs"), how long it has run, how long it
  took last time and what started it (Run now, Force Compile or the schedule). While idle it shows
  the next Fetch and Compile, and it now refreshes every 20 s, so a scheduled run shows up without
  a reload. Outputs that no Compile has written yet say "not published yet" on the Outputs page
  and in the status line, since their feed URLs answer 404 until then. `GET /api/v1/status`
  returns the same information. [#58](https://github.com/spydisec/threatcull/issues/58)
- ⚡ **Unchanged lists skip parsing.** A Fetch hashes each download and compares it with the list
  it last applied. When nothing changed, ThreatCull refreshes the Source's entries without parsing
  them again, even if the server sends no `ETag` header. A 3 million-line list re-fetched in 5 s
  instead of 4 min in testing. An upgrade, or a change to a Source's URL or format, parses every
  list in full once.
- 🌐 **The first Fetch waits for DNS.** After a restart, the first scheduled Fetch waits up to two
  minutes for the Source's host to resolve, so a server that boots before the router no longer
  records a row of failed Fetches.
- 🗄️ **SQLite tuning.** ThreatCull refreshes the query planner's statistics after each Compile
  (`PRAGMA optimize`) and keeps its temporary tables on disk, so large Compiles don't depend
  on how the Python image's SQLite was built.

- 🐳 **`docker exec` needs no `--data-dir`.** The image sets `THREATCULL_DATA_DIR=/data`, so
  `docker exec threatcull threatcull api-token create <name> --user admin` works as written. It
  also sets `SQLITE_TMPDIR=/data`, so SQLite's temporary files stay on the data volume even when
  `/tmp` is a `tmpfs` mount.
- 🔗 **`feed_path` in `/api/v1/outputs`.** Each Output lists its feed URL path (`/o/<name>`); add
  the Feed Token to get a working URL.
- 📖 **API and sizing docs.** [docs/API.md](docs/API.md) covers every endpoint with curl examples,
  feed URLs and the difference between a feed URL and the Download button. The README has a
  Sizing section with measured numbers and advice for a Raspberry Pi, and `docker-compose.yaml`
  has a commented `mem_limit` example.
- 🗓️ **Enabling a Source no longer starts a Fetch.** A Source enabled in the web UI, the API, the
  CLI or by a Catalog update waits for the regular schedule (at most an hour for its first Fetch),
  so enabling several Sources in a row doesn't start a Fetch and a Compile for each one. Click
  **Run now** to fetch them at once. The Sources page shows when a new Source's first Fetch is
  due. After a restart, ThreatCull still catches up on overdue Sources within minutes.
  [#60](https://github.com/spydisec/threatcull/issues/60)

### Fixed

- 🔁 **Re-enabled Sources fill up again.** A Source disabled for longer than the retention period
  lost its entries to pruning, and when it was re-enabled the server's `304 Not Modified` kept it
  empty until the upstream list changed. ThreatCull now notices the missing entries and downloads
  the full list.
- ⏱️ **Runs show how long they took.** Every Fetch and Compile stored its start time as its finish
  time, so the run history and `/api/v1/runs` showed 0 s for every run. ThreatCull now records the
  real finish time. [#59](https://github.com/spydisec/threatcull/issues/59)
- 🧭 **Force Compile no longer hangs the page.** The page waited until the whole Compile finished,
  which takes minutes with large lists. Force Compile now starts in the background like Run now,
  and the run status shows when it ends. [#57](https://github.com/spydisec/threatcull/issues/57)

## [2.2.1] - 2026-10-03

Updated base images with OpenSSL security fixes. Upgrading is recommended; nothing else to do.

### Security

- 🔐 **OpenSSL fixes in the base image.** The Docker Hardened Images `python:3.14` and
  `python:3.14-dev` bases move to new digests that ship OpenSSL `3.5.7-1~deb13u3`, which fixes
  High-severity vulnerabilities in the 2.2.0 image (CVE-2026-54873, CVE-2026-84782, CVE-2026-84784,
  CVE-2026-72897). The image scan finds no High or Critical vulnerabilities again.

### Changed

- 📦 **uv 0.12.22** builds the image (was 0.12.19).

## [2.2.0] - 2026-09-28

The image runs on Python 3.14. Nothing to do when upgrading.

### Changed

- 🐍 **Python 3.14.** The image builds on `dhi.io/python:3.14-dev` and runs on `dhi.io/python:3.14`,
  both still Docker Hardened Images pinned by digest. Building without a Docker account now uses
  `python:3.14-slim` for both build arguments.
- 🔄 **Base images update themselves.** Dependabot now reads the hardened base images and opens a
  pull request when Docker patches them or a new Python release comes out.

## [2.1.0] - 2026-09-28

The image now builds on Docker Hardened Images: no shell or package manager inside, and no known
vulnerabilities in the scan. Nothing to do when upgrading: it still runs as uid 10001, so your
`/data` volume keeps working, and you still pull it from `ghcr.io/spydisec/threatcull`.

### Changed

- 🛡️ **Docker Hardened Images base.** The image builds on `dhi.io/python:3.13` (runtime) and
  `dhi.io/python:3.13-dev` (build): no shell or package manager in the image, near-zero known CVEs,
  signed SBOMs and provenance from Docker. It still runs as uid 10001, so existing `/data` volumes
  keep working, and the image is still published to `ghcr.io/spydisec/threatcull`.
  [#39](https://github.com/spydisec/threatcull/issues/39)

## [2.0.2] - 2026-09-28

A security fix for domain feeds in `csv` or `json` format. Upgrading is recommended; nothing else
to do.

### Security

- 🧱 **Line breaks can't reach Outputs.** A `csv` or `json` feed could list a domain containing a line
  break (for example `"google\n.com\n.zz.zz"`): it passed validation and each part became its own
  line in plain, hosts, AdGuard and RPZ Outputs, which could add broad blocking rules past the
  allowlist. Values with whitespace or control characters inside are now rejected, and the Output
  writer refuses a line break as a last check. Found in an internal security review.

## [2.0.1] - 2026-09-28

A new Catalog Source, owner-only approval for Catalog suggestions, and releases that also work when
made in the GitHub Release UI. Nothing to do when upgrading from 2.0.0.

### Added

- 🆕 **New Catalog Source: BlackHole TODAY IPs.** An IP blocklist (`blackhole-today-ips`) of
  about 7,000 addresses, disabled until you enable it. Installs on 2.0.0 already get it with
  **Check for updates**. [#28](https://github.com/spydisec/threatcull/issues/28)

### Changed

- 🔏 **Only the owner approves Catalog suggestions.** The `approved` label opens the pull request
  only when the repository owner adds it; the bot removes it when others add it. Approval also closes
  the issue.
- 🏷️ **Releases from the GitHub Release UI build the image.** The tag sets the version: when
  `pyproject.toml` still has the previous one, the Release workflow builds the tagged version and
  warns instead of stopping. Without a CHANGELOG.md section the release keeps its own notes.

## [2.0.0] - 2026-09-28

ThreatCull no longer tracks licences: every Source is a public feed, and you decide which ones to
use. The Catalog gets its own page, and Source suggestions are checked automatically.

**Upgrading from 1.x**

| If you | Now |
|---|---|
| Use the `:1` image tag (the 1.x compose file) | Change it to `:2` in your compose file or Portainer stack; `:1` stays on 1.x. |
| Read the Licence or Business use columns on the Sources page | The Feed column links each Source to its list; check the publisher's page. |
| Run `sources enable --acknowledge-restricted` or `sources add-custom --business-use` | Drop the flag; both are gone. |
| Read `licence`, `licence_url`, `licence_class` or `business_use` from `/api/v1/sources` | Those fields are gone. |
| Send `acknowledge_restricted` to `POST /api/v1/sources/{id}` | Send `{"enabled": true}` only; the old field is refused (422). |
| Parse Output headers | Each Source line reads `name \| feed URL`; JSON `attribution` entries carry `name` and `url`. |
| Import a configuration file from 1.x | It still imports; `business_use` is ignored. |
| Stay on 1.x and use **Check for updates** | 1.x refuses the 2.0 Catalog ("needs ThreatCull 2.0.0"). Upgrade the image. |

### Added

- 📖 **Catalog page.** [docs/CATALOG.md](docs/CATALOG.md) lists every Source with its category,
  feed and default, explains Catalog updates, and says which Sources are wanted and how to suggest
  one. The tables are generated from `catalog.yaml` (`make catalog-docs`).
- 🤖 **Checked Catalog suggestions.** The "Add a Source to the Catalog" issue form asks for
  everything a Source needs. A bot downloads the feed, counts the entries ThreatCull would keep,
  looks for duplicates, and comments with the result. The `approved` label from a maintainer opens
  the pull request that adds the Source.

### Removed

- 🧹 **Licence data.** The Catalog, the database, the Sources page, the API, the CLI and
  configuration files no longer carry a licence, licence link, licence class or business use, and
  enabling a Source never asks for an acknowledgement. The Sources page shows a Feed link instead.
  Output headers still name every contributing Source, with its feed URL.

## [1.4.0] - 2026-09-26

The web UI can show times in your own timezone, and the README shows what ThreatCull looks like.

**Upgrading from 1.3.x**

| If you | Now |
|---|---|
| Want times in your own timezone | Set `TZ` to an IANA name such as `Australia/Melbourne` in `docker-compose.yaml`. |
| Leave `TZ` unset | Nothing changes. Times stay in UTC. |

### Added

- 🕒 **Local times in the web UI.** Set `TZ` to an IANA timezone name such as `Australia/Melbourne`
  and the web UI shows every time in that zone, with its abbreviation (`AEST`). Hovering a time
  shows its UTC value. ThreatCull still stores and schedules in UTC, and `serve` refuses to start on a
  name it does not know. Unset `TZ` keeps UTC.
- 🖼️ **README screenshots and settings table.** The README shows the dashboard, Sources and lookup
  pages in light and dark themes, and lists every environment variable, `TZ` included.

## [1.3.0] - 2026-09-26

The Catalog of Sources can now be updated between releases, and the container image is scanned for
known vulnerabilities on every change.

**Upgrading from 1.2.x**

| If you | Now |
|---|---|
| Run the image with `docker compose pull && docker compose up -d` | Nothing else to do. The Sources page gains a Catalog card. |
| Keep your own copy of `docker-compose.yaml` | Optionally add `cap_drop: [ALL]` and `security_opt: [no-new-privileges:true]` from the new file. |

### Added

- 📚 **Catalog updates between releases.** **Check for updates** on the Sources page, or
  `threatcull catalog update`, downloads the newest Catalog from this repository. Installs without
  internet access upload a `catalog.yaml` or run `threatcull catalog update --file`. New Sources
  arrive disabled, existing ones get their corrected details, and Sources the Catalog no longer
  lists are disabled. The update survives restarts, and a release with a newer Catalog takes over
  from it. `threatcull catalog show` prints the revision in use.
  [#1](https://github.com/spydisec/threatcull/issues/1)
- 🔎 **Image vulnerability scanning.** Every pull request scans the image with Grype and fails on a
  high or critical CVE that has a fix. A weekly job scans the published `:latest` image.
- 🤝 **Security policy, contributing guide and issue forms.** Report vulnerabilities privately
  through GitHub. The issue forms cover bugs, feature requests and new Catalog Sources.

### Changed

- 🐧 **Debian 13 base image.** The image moves from `python:3.13-slim-bookworm` to
  `python:3.13-slim-trixie`.
- 🔐 **Hardened compose file.** `docker-compose.yaml` drops all Linux capabilities and blocks
  privilege escalation. ThreatCull runs as a non-root user on an unprivileged port and needs
  neither.

- 🐰 **Focused CodeRabbit reviews.** Pull request reviews cover security and correctness in the
  application, workflows and container, and skip tests, lock files and generated files.

### Security

- 🧱 **Catalog updates refuse unsafe files.** An update refuses an older revision, `file://`
  Sources (which could read files on the host), YAML aliases and files over 1 MiB.

## [1.2.0] - 2026-09-26

Your own blocklists and allowlists in one step, no CIDR ranges in Outputs, and a clear message
instead of an error when a large fetch holds the database.

**Upgrading from 1.1.x**

| If you | Now |
|---|---|
| Publish IP Outputs to a firewall | Outputs list single addresses only. Ranges from blocklists stop appearing; the dashboard counts them as "Ranges left out". |
| Keep allowlists outside ThreatCull | Add them on the Sources page with **Use as** set to allowlist. |

### Added

- ➕ **Add your own list in one step.** The Sources page asks for a name, a URL, whether the list
  is a blocklist or an allowlist, and whether it holds IPs or domains. ThreatCull picks the id and
  enables the Source. Format and parsing options sit under Advanced.
- 🛡️ **Sources that feed the allowlist.** Every value on such a custom Source stays out of all
  Outputs, like the built-in CDN ranges. The CLI takes `sources add-custom --allowlist`.

### Changed

- 🎯 **No CIDR ranges in Outputs.** A range on a blocklist can block many unrelated hosts, so
  Outputs list single IP addresses and domains. The dashboard funnel shows "Ranges left out" and
  Lookup explains why a range is in no Output. Ranges on the allowlist still cover every address
  inside them.

### Fixed

- ⏳ **Saving during a large fetch.** Saving a change while a large Source was being stored failed
  with "database is locked". ThreatCull now waits up to 30 seconds for the lock and then shows a
  "busy, try again" page instead of an error.
- 🆔 **Readable custom Source errors.** A custom Source id that doesn't fit the pattern now gets a
  plain explanation instead of a validation error.

## [1.1.0] - 2026-09-26

"My network" replaces the Home Network page, charts work from the first Compile, and the Outputs,
Lookup, Sources, allowlist and login pages are easier to read.

**Upgrading from 1.0.x**

| If you used | Now |
|---|---|
| The Home Network page or `threatcull home` | Your entries moved to the allowlist, marked **My network**. Use `threatcull allow add --mine`. |
| `/api/v1/home` | Use `/api/v1/allowlist` with `"mine": true`. |
| A configuration file with a `home_network` section | It still imports; the entries arrive marked My network. |

### Added

- 👋 **First-run guide and early charts.** A new install shows a getting-started card, and the
  trend charts draw from the first Compile.

### Changed

- 🏠 **My network is part of the allowlist.** Mark an allowlist entry as your own address to keep
  the dashboard alert when a Source lists it. Private and special-purpose addresses need no entry.
- 🧭 **Clearer pages.** Outputs show each feed URL with Download and Rotate buttons, Lookup gives a
  verdict at the top, Sources list enabled ones first, and the login page carries the brand.

### Fixed

- 🏷️ **Settings page title.** The browser tab of the Settings page showed a copy of the
  configuration card.

## [1.0.1] - 2026-09-26

A plain compose file that also works as a Portainer stack, and fixes from the release review.

### Changed

- 🐳 **Plain `docker-compose.yaml`.** Download one file, set `THREATCULL_ADMIN_PASSWORD` and run
  `docker compose up -d`, or paste it into a Portainer stack. `THREATCULL_ADMIN_PASSWORD_FILE`
  still works.
- 📖 **Shorter README** with the quick start, upgrade and backup steps.

### Fixed

- 🧹 **Stricter configuration import, data directory errors and custom Source URLs.**

## [1.0.0] - 2026-09-25

First release.

### Added

- 📋 **Catalog of public blocklists** with licence details and business-use notes for each Source.
- ⚙️ **Compile pipeline.** Fetches Sources, drops invalid entries, duplicates and private ranges,
  scores each indicator by how many independent Sources list it (high, medium, low) and applies
  the allowlist, including the built-in CDN ranges.
- 📤 **Outputs** as plain, hosts, AdGuard, RPZ, CSV or JSON, each at its own URL behind a Feed Token.
  The Shrink Guard keeps the previous Output when a new one would shrink sharply.
- 🖥️ **Web UI** with a dashboard of what each Compile cleaned up, Lookup, run history, table
  search and a built-in scheduler.
- ⌨️ **CLI and JSON API** with API tokens for scripts.
- 💾 **Configuration export and import** as YAML, with no passwords or tokens in the file.
- 🐳 **Container image** for linux/amd64 and linux/arm64 that runs as a non-root user with a health
  check.

[Unreleased]: https://github.com/spydisec/threatcull/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/spydisec/threatcull/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/spydisec/threatcull/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/spydisec/threatcull/compare/v2.0.2...v2.1.0
[2.0.2]: https://github.com/spydisec/threatcull/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/spydisec/threatcull/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/spydisec/threatcull/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/spydisec/threatcull/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/spydisec/threatcull/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/spydisec/threatcull/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/spydisec/threatcull/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/spydisec/threatcull/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/spydisec/threatcull/releases/tag/v1.0.0
