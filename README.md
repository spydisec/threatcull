# ThreatCull

**Cull the noise. Block the threats.**

Self-hosted threat-feed compiler: collects indicators from public and private sources, removes noise and
trusted infrastructure, scores them by independent-source agreement, and publishes licence-aware blocklists
for firewalls, DNS and SIEMs, including in air-gapped networks.

> Status: pre-v1, private.

## v1 scope

**For:** SMB IT admins running their own firewall and DNS, designed so OT / air-gapped sites can follow.

**In v1:** licence-tagged Catalog of Sources (plus Custom Sources), Fetch/Compile pipeline,
allowlists (built-in vendor ranges + operator entries), Confidence Score and Tiers, Outputs as plain /
hosts / AdGuard / RPZ / CSV / JSON, served over HTTP with Feed Tokens from the local data directory,
Indicator lookup, Run history, single admin login, YAML configuration export/import. Runs as a plain
Python app first, then as one container.

**Not in v1:** multi-tenant SaaS, SSO/RBAC, STIX/TAXII, signed offline bundles, community sighting network,
pushing rules directly to firewalls, per-Source weights, alerting integrations, built-in TLS,
publishing Outputs to S3-compatible storage (planned for later).

## v1 is done when

1. `docker compose up` (or `uv run threatcull serve --host <lan-ip> --port 6969`) starts the app.
2. An admin logs in, enables a few Catalog Sources, adds an allowlist entry and clicks **Run now**.
3. The Run completes and the UI shows per-Source counts and status.
4. `curl http://<lan-ip>:6969/o/<output>?token=<feed-token>` returns a valid list in the chosen Format.
5. Looking up an Indicator shows which Sources listed it and when, or the allowlist reason.
6. The Sources page shows each Source's licence class, Business Use and a link to its terms.
7. The full pipeline test passes with no internet access.
8. A configuration exported from one install imports into a fresh one and restores its Sources,
   allowlist, Home Network, Outputs and settings.

## Quick start with Docker

GitHub Actions publishes the image to `ghcr.io/spydisec/threatcull` for amd64 and arm64,
so you need only Docker and the compose file, not the source code:

```bash
mkdir threatcull && cd threatcull
curl -fsSL -o compose.yaml \
  https://raw.githubusercontent.com/spydisec/threatcull/main/compose.example.yaml
printf '%s\n' '<a long password>' > threatcull_admin.txt && chmod 644 threatcull_admin.txt
THREATCULL_BIND=<lan-ip> docker compose up -d
```

Open `http://<lan-ip>:6969` and log in as `admin` with that password, then empty the file
with `: > threatcull_admin.txt`. ThreatCull reads it on the first start only; keep the empty
file, because compose refuses to start when a secret file is missing. The container runs as
user ID 10001 with a read-only root filesystem and keeps everything (database, Outputs, session
secret) on the `threatcull-data` volume. Without `THREATCULL_BIND` the port listens on
`127.0.0.1` only.

The first start creates the default Outputs without printing their Feed Tokens, since
container logs are not a safe place for them: rotate each token on the Outputs page to get
its Feed URL. Run CLI commands through the container, for example
`docker compose run --rm threatcull outputs list`.

**Upgrade:** `docker compose pull && docker compose up -d`. The `:1` tag follows every 1.x
release; pin an exact version such as `:1.0.0` in `compose.yaml` to upgrade only by hand.
Database migrations run and the shipped Catalog refreshes on start: new Sources appear, and
Sources you disabled stay disabled.

**Build it yourself:** clone the repository, copy `compose.example.yaml` to `compose.yaml`,
swap its `image:` line for `build: .` and run `docker compose up -d --build`.

## Back up and restore

The configuration file holds the settings, Source choices, custom Sources, allowlist, Home
Network and Output definitions. It holds no passwords, tokens or threat data; Sightings
rebuild on the next Fetch.

```bash
docker compose run --rm -T threatcull config export > threatcull-config.yaml
docker compose run --rm -T threatcull config import - < threatcull-config.yaml
```

Settings > Configuration in the web UI does the same. An import adds and updates, never
deletes, and lists anything it skipped; a new Output shows its Feed Token once. For a full
backup, including users, Feed Tokens and history, copy the `threatcull-data` volume.

## Quick start without Docker

```bash
git clone <repo-url> threatcull && cd threatcull
uv sync
uv run threatcull init
uv run threatcull user create admin
uv run threatcull serve --host <lan-ip> --port 6969
```

`init` prints a Feed Token for each default Output; this is the only time they appear, so
copy them now (or rotate one later on the Outputs page, which shows the new token once).
`serve` never prints tokens, since its output ends up in system logs: if it creates the
default Outputs itself, rotate their tokens on the Outputs page.
`user create` prompts for the password twice; for scripts, pipe it in with
`--password-stdin`. `user set-password <name>` changes it later and signs that user out
everywhere; `user list` shows who has an account.

Open `http://<lan-ip>:6969` and log in as `admin`. Enable a few Catalog Sources on the
Sources page, add any allowlist entries you need and click **Run now**. Each Output
publishes at its own URL, with its Feed Token:

```
http://<lan-ip>:6969/o/ip-high/<feed-token>
```

Point a firewall or DNS resolver at that URL, or pull it with `curl`:

```bash
curl http://<lan-ip>:6969/o/ip-high/<feed-token>
```

A script or another service authenticates with an API token instead of a login session:

```bash
uv run threatcull api-token create my-script --user admin
curl -H 'Authorization: Bearer <api-token>' http://<lan-ip>:6969/api/v1/runs
```

## Homelab and air-gapped use

ThreatCull targets a home lab or an OT network with no route to the internet: plain HTTP
on a bare IP, no DNS name, no TLS.

- `serve` binds to `127.0.0.1` unless you pass `--host`; give it your LAN IP or interface
  address so other devices can reach it. Never pass `--host 0.0.0.0` without a firewall in
  front of it.
- A Source can use a `file://` URL instead of `https://`, so a network with no internet
  access can still feed ThreatCull from indicator lists copied in by hand. Drop those files
  into `data/imports/` (`<data-dir>/imports/`): a custom Source added from the web UI may
  only read files there. The CLI (`sources add-custom`) accepts any local path.
- `serve` runs the Fetches and Compiles on its own schedule. Don't also run
  `threatcull run` from a `cron` job against the same data directory: the two don't share
  the one-run-at-a-time lock. Use **Run now** or the built-in scheduler instead.
- `threatcull home detect` reads this host's own gateway, DNS resolvers and addresses and
  suggests Home Network entries from them (`--public-ip` also asks api.ipify.org, only on
  that explicit request); the Home Network page in the web UI has the same Detect buttons.
  Any value on that list drops out of every Output and raises a dashboard alert if an
  upstream feed lists it, so your own network never ends up in a blocklist you publish.
- An Output URL works two ways, `/o/<name>/<token>` (path) or `/o/<name>?token=<token>`
  (query string); both redact the token from the access log.
- Behind a reverse proxy that terminates TLS, add `--secure-cookies` so the session cookie
  carries the `Secure` flag, and `--trusted-proxy <lan-ip>` (repeatable) so ThreatCull
  believes that proxy, and no other peer, about the client: `X-Forwarded-For` for the
  login rate limiter, `X-Forwarded-Proto` and `X-Forwarded-Host` for the Feed URLs it
  shows. Leave `--secure-cookies` off when serving plain HTTP: over an insecure connection
  the browser discards a `Secure` cookie and login fails.

## Sources and licences

ThreatCull ships software and a Catalog of Source definitions (URL, format, licence class
and a link to the licence evidence). It ships no threat data. Each installation downloads
every Source straight from its publisher, so the operator of that installation accepts
each Source's terms.

- The licence class and Business Use on each Source summarise the published terms as the
  Catalog understood them. ThreatCull shows them but never enforces them: you decide which
  Sources your use allows. Read the linked terms yourself before relying on a Source,
  especially for business use. They are not legal advice.
- Serving Outputs to your own firewalls, DNS servers and SIEM counts as your own use.
  Sharing a Feed URL with another organisation, or exposing `/o/` to the internet, passes
  the data on to others, which many Source licences forbid.

## Licence

[GNU AGPL-3.0](LICENSE).
