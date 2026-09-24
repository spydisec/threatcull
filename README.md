# ThreatCull

**Cull the noise. Block the threats.**

Self-hosted threat-feed compiler: collects indicators from public and private sources, removes noise and
trusted infrastructure, scores them by independent-source agreement, and publishes licence-aware blocklists
for firewalls, DNS and SIEMs, including in air-gapped networks.

> Status: pre-v1, private.

## v1 scope

**For:** SMB IT admins running their own firewall and DNS, designed so OT / air-gapped sites can follow.

**In v1:** licence-tagged Catalog of Sources (plus Custom Sources), Business Mode, Fetch/Compile pipeline,
allowlists (built-in vendor ranges + operator entries), Confidence Score and Tiers, Outputs as plain /
hosts / AdGuard / RPZ / CSV / JSON, served over HTTP with Feed Tokens or pushed to S3-compatible storage,
Indicator lookup, Run history, single admin login, YAML configuration export/import. Runs as a plain
Python app first, then as one container.

**Not in v1:** multi-tenant SaaS, SSO/RBAC, STIX/TAXII, signed offline bundles, community sighting network,
pushing rules directly to firewalls, per-Source weights, alerting integrations, built-in TLS.

## v1 is done when

1. `uv run threatcull serve --host <lan-ip> --port 6969` starts the app.
2. An admin logs in, enables a few Catalog Sources, adds an allowlist entry and clicks **Run now**.
3. The Run completes and the UI shows per-Source counts and status.
4. `curl http://<lan-ip>:6969/o/<output>?token=<feed-token>` returns a valid list in the chosen Format.
5. Looking up an Indicator shows which Sources listed it and when, or the allowlist reason.
6. Business Mode disables every blocklist Source whose Business Use is not `allowed` and says why.
7. The full pipeline test passes with no internet access.

## Quick start

```bash
git clone <repo-url> threatcull && cd threatcull
uv sync
uv run threatcull init
uv run threatcull user create admin
uv run threatcull serve --host <lan-ip> --port 6969
```

Open `http://<lan-ip>:6969` and log in as `admin`. Enable a few Catalog Sources on the
Sources page, add any allowlist entries you need and click **Run now**. Each Output
publishes at its own URL, with a Feed Token shown once on the Outputs page:

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
  access can still feed ThreatCull from indicator lists copied in by hand.
- `threatcull home detect` reads this host's own gateway, DNS resolvers and addresses and
  suggests Home Network entries from them (`--public-ip` also asks api.ipify.org, only on
  that explicit request); the Home Network page in the web UI has the same Detect buttons.
  Any value on that list drops out of every Output and raises a dashboard alert if an
  upstream feed lists it, so your own network never ends up in a blocklist you publish.
- An Output URL works two ways, `/o/<name>/<token>` (path) or `/o/<name>?token=<token>`
  (query string); both redact the token from the access log.
- Behind a reverse proxy that terminates TLS, add `--secure-cookies` so the session cookie
  carries the `Secure` flag, and `--trusted-proxy <lan-ip>` (repeatable) so the login rate
  limiter trusts `X-Forwarded-For` from that proxy and no other peer. Leave
  `--secure-cookies` off when serving plain HTTP: over an insecure connection the browser
  discards a `Secure` cookie and login fails.

## Licence

[GNU AGPL-3.0](LICENSE).
