# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are tagged `vX.Y.Z`
and published as `ghcr.io/spydisec/threatcull` for linux/amd64 and linux/arm64.

## [Unreleased]

### Changed

- 🔏 **Only the owner approves Catalog suggestions.** The `approved` label opens the pull request
  only when the repository owner adds it; the bot removes it when others add it. Approval also closes
  the issue.

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

[Unreleased]: https://github.com/spydisec/threatcull/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/spydisec/threatcull/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/spydisec/threatcull/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/spydisec/threatcull/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/spydisec/threatcull/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/spydisec/threatcull/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/spydisec/threatcull/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/spydisec/threatcull/releases/tag/v1.0.0
