# ThreatCull

Self-hosted threat-feed compiler. ThreatCull downloads public blocklists, drops duplicates, private
ranges and your own infrastructure, scores each indicator by how many independent sources list it, and
serves the result to your firewalls, DNS servers and SIEM.

- Catalog of blocklist sources with licence details, plus your own sources (URL or local file)
- Built-in CDN allowlists, your own allowlist entries, and a Home Network list that never gets
  published
- Confidence tiers (high, medium, low) from source agreement
- Outputs as plain, hosts, AdGuard, RPZ, CSV or JSON, each at its own URL with a Feed Token
- Web UI with a dashboard, lookup, run history and a built-in scheduler
- Works offline and on a bare LAN IP

## Quick start

You need Docker with Compose. The image is published for amd64 and arm64.

```bash
mkdir threatcull && cd threatcull
curl -fsSL -o compose.yaml \
  https://raw.githubusercontent.com/spydisec/threatcull/main/compose.example.yaml
printf '%s\n' '<a long password>' > threatcull_admin.txt && chmod 644 threatcull_admin.txt
THREATCULL_BIND=<lan-ip> docker compose up -d
```

Open `http://<lan-ip>:6969` and log in as `admin`. Then empty the password file with
`: > threatcull_admin.txt`; keep the file itself, because compose needs it to exist.

Without `THREATCULL_BIND`, ThreatCull listens on `127.0.0.1` only. Data lives on the
`threatcull-data` volume.

## First steps

1. On **Sources**, enable the lists you want.
2. On **Outputs**, rotate a Feed Token to get the feed URL. Tokens show once.
3. Click **Run now**, or wait for the hourly schedule.
4. Point your firewall or DNS server at the feed URL:

```bash
curl http://<lan-ip>:6969/o/ip-high/<feed-token>
```

## Upgrade

```bash
docker compose pull && docker compose up -d
```

The `:1` tag follows 1.x releases. Pin a version such as `:1.0.0` to upgrade by hand. Sources you
disabled stay disabled.

## Back up and restore

```bash
docker compose run --rm -T threatcull config export > threatcull-config.yaml
docker compose run --rm -T threatcull config import - < threatcull-config.yaml
```

The file holds settings, source choices, allowlist, Home Network and outputs. It holds no passwords,
tokens or threat data. **Settings > Configuration** in the web UI does the same. For a full backup,
copy the `threatcull-data` volume.

## Run without Docker

```bash
git clone https://github.com/spydisec/threatcull.git && cd threatcull
uv sync
uv run threatcull init
uv run threatcull user create admin
uv run threatcull serve --host <lan-ip> --port 6969
```

`init` prints each default output's Feed Token once. `uv run threatcull --help` lists every command.

## Notes

- **Offline networks:** add a custom source with a `file://` URL. Sources added in the web UI must
  point to files in `data/imports/`.
- **Home Network:** list your public addresses on the Home Network page (or run
  `threatcull home detect`). ThreatCull keeps them out of every output and warns you when a source
  lists one.
- **Scripts:** create an API token with `threatcull api-token create <name> --user admin` and send it
  as `Authorization: Bearer <token>` to `/api/v1/`.
- **Reverse proxy with TLS:** start `serve` with `--secure-cookies` and `--trusted-proxy <proxy-ip>`.
- **Scheduling:** `serve` runs fetches and compiles itself. Don't also run `threatcull run` from `cron`
  on the same data directory.

## Sources and licences

ThreatCull ships no threat data. Each install downloads every source from its publisher, so you accept
each source's terms. The Sources page shows each licence and links to its terms; read them before you
rely on a source. Serving outputs to your own devices is your own use; sharing a feed URL with another
organisation passes the data on, which many licences forbid.

## Development

```bash
make setup   # dependencies and git hooks
make check   # lint, types, tests and security checks, as in CI
```

## Licence

[GNU AGPL-3.0](LICENSE)
