# ThreatCull API

ThreatCull serves two kinds of HTTP endpoints:

- **Feed URLs** (`/o/...`) hand an Output to a firewall, DNS server or SIEM. A Feed Token
  authorises them.
- **The REST API** (`/api/v1/...`) lets scripts read the state of an instance and change a few
  settings. An API token authorises it.

The examples use `http://<server-ip>:6969` and an API token in `$TOKEN`.

## API tokens

Create a token inside the container. ThreatCull prints it once:

```bash
docker exec threatcull threatcull api-token create monitoring --user admin
```

Send it in the `Authorization` header:

```bash
export TOKEN=tc_...
curl -H "Authorization: Bearer $TOKEN" http://<server-ip>:6969/api/v1/me
```

A token acts as the user it was created for. ThreatCull stores only a hash, so a lost token can't
be shown again: revoke it and create a new one.

```bash
docker exec threatcull threatcull api-token list
docker exec threatcull threatcull api-token revoke monitoring
```

Without a token, or with an invalid one, the API answers `401 {"detail": "authentication required"}`.
Requests that use a token don't need the web UI's CSRF token.

## Endpoints

### `GET /api/v1/me`

The user the token belongs to: `{"username": "admin"}`.

### `GET /api/v1/sources`

Every Source, enabled or not. Each entry has `id`, `name`, `family`, `url`, `format`, `kind`
(`ip` or `domain`), `role` (`blocklist` or `allowlist`), `category`, `refresh_minutes`, `custom`,
`enabled`, `disabled_reason`, `last_success_at`, `last_attempt_at`, `last_error`, `last_changed_at`
(when the list last gained or lost an entry) and `frozen` (true for a Frozen Source).

```bash
curl -H "Authorization: Bearer $TOKEN" http://<server-ip>:6969/api/v1/sources
```

### `POST /api/v1/sources/{id}`

Enables or disables a Source. Body: `{"enabled": true}` or `{"enabled": false}`. ThreatCull
returns the Source as `GET /api/v1/sources` shows it, or `404` for an unknown id.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled": false}' http://<server-ip>:6969/api/v1/sources/hagezi-tif-domains
```

### `GET /api/v1/outputs`

Every Output: `name`, `kind`, `categories`, `min_tier`, `max_entries` (the cap, or `null`),
`format`, `last_count` and `last_published_at`. `last_published_at` is `null` until a Compile has
written the Output. `feed_path` is the feed URL path without the token, for example
`/o/ip-high`. Append `/<feed-token>` or `?token=<feed-token>` to it.

```bash
curl -H "Authorization: Bearer $TOKEN" http://<server-ip>:6969/api/v1/outputs
```

### `POST /api/v1/outputs/{name}/rotate`

Replaces the Output's Feed Token and returns the new one once: `{"name": "ip-high", "token": "..."}`.
The old feed URL stops working at once. The response carries `Cache-Control: no-store`.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://<server-ip>:6969/api/v1/outputs/ip-high/rotate
```

### `GET /api/v1/allowlist`

Your allowlist entries followed by the built-in ones. Each entry has `value`, `kind`, `note`,
`origin` and `mine` (your own network).

### `POST /api/v1/allowlist`

Adds an entry. Body: `{"value": "203.0.113.7", "note": "office", "mine": true}`. `note` and `mine`
are optional. An IP, CIDR or domain ThreatCull can't parse returns `400`.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"value": "example.org", "note": "our website"}' \
  http://<server-ip>:6969/api/v1/allowlist
```

### `DELETE /api/v1/allowlist?value=<value>`

Removes an entry: `{"value": "...", "removed": true}`, or `404` when it isn't there.

### `POST /api/v1/allowlist/detect`

Suggests your own public addresses and adds nothing: `{"candidates": [{"value": ..., "reason": ...}]}`.
Add `?public_ip=true` to also ask `api.ipify.org` for the address your traffic leaves from.

### `GET /api/v1/runs?limit=50`

The newest Fetches and Compiles first. `limit` is 1 to 200 (default 50). Each run has `id`, `type`
(`fetch` or `compile`), `source_id`, `started_at`, `finished_at`, `duration_seconds` (`null`
while running), `timings` (seconds per stage, such as `{"download": 0.4, "parse": 12.1,
"apply": 8.3}`; `{}` for runs recorded before 2.4), `status` (`running`, `ok`, `not_modified`,
`failed` or `blocked`), `counts`, `error` and `home_hits`.

```bash
curl -H "Authorization: Bearer $TOKEN" "http://<server-ip>:6969/api/v1/runs?limit=10"
```

### `GET /api/v1/settings`

The Compile settings: `active_window_days`, `retention_days`, `stale_after_hours`, `tier_high`,
`tier_medium`, `max_shrink`, `max_stale_ratio` and `frozen_after_days`. The API can't change them; use
**Settings** in the web UI.

### `GET /api/v1/lookup?q=<value>`

Explains one IP, CIDR or domain: `score`, `tier`, every `sightings` entry (which Source lists it
and since when), `allowlisted_by` and the `eligible_outputs` it would go into. A value that isn't a
public IP, CIDR or domain returns `400`.

```bash
curl -H "Authorization: Bearer $TOKEN" "http://<server-ip>:6969/api/v1/lookup?q=example.org"
```

### `GET /api/v1/status`

What ThreatCull is doing now and what comes next, as the status line in the web UI shows it.

- `running`: `true` while a Fetch or Compile runs.
- `trigger`: what started it: `run_now`, `force_compile`, `scheduled_fetch` or
  `scheduled_compile`.
- `step`: `fetch` or `compile`, with `step_started_at`, `elapsed_seconds` and `previous_seconds`
  (how long the same step took last time, or `null` when unknown).
- `source_id` and `source_name`: the Source being fetched. During Run now, `position` and `total`
  give "3 of 10".
- `next_compile_at`, `next_fetch` (`source_id`, `source_name`, `at`) and `retries_waiting`
  (Fetches that found a run in progress and will retry). `scheduler_on` is `false` when ThreatCull
  runs without its scheduler.
- `unpublished_outputs`: Outputs no Compile has written yet. Their feed URLs answer `404`.
- `database_bytes` and `outputs_bytes`: disk used by the database (with its WAL files) and by the
  published Outputs.

```bash
curl -H "Authorization: Bearer $TOKEN" http://<server-ip>:6969/api/v1/status
```

### Starting a run

The API has no endpoint that starts a Fetch or Compile yet. Use **Run now** in the web UI, or wait
for the schedule.

## Feed URLs

A device fetches an Output from either form:

```text
http://<server-ip>:6969/o/<name>/<feed-token>
http://<server-ip>:6969/o/<name>?token=<feed-token>
```

Get the token by clicking **Rotate token** on **Outputs** (or with the rotate endpoint above). It
shows once.

- `GET` returns the file. `HEAD` returns only its headers.
- Responses carry `ETag` and `Last-Modified`. A request with a matching `If-None-Match` or
  `If-Modified-Since` gets `304 Not Modified` and no body, so a device that checks often costs
  little.
- A wrong token, an unknown Output and an Output no Compile has written yet all return the same
  `404 not found`. Check `last_published_at` in `GET /api/v1/outputs` to tell them apart.

`/outputs/<name>/download` is the **Download** button in the web UI and needs a logged-in session.
A device given that URL gets redirected to the login page. AdGuard Home, for example, then reports
"data is HTML, not plain text". Give devices the feed URL.

## Health check

`GET /healthz` needs no token and returns `{"status": "ok", "version": "2.4.0"}`. The container's
health check uses it.
