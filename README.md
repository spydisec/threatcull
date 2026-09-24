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

## Licence

[GNU AGPL-3.0](LICENSE).
