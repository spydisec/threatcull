# Security policy

## Supported versions

Only the latest release gets security fixes. Upgrade with `docker compose pull && docker compose up -d`.

## Reporting a vulnerability

Report it privately through **Security > Report a vulnerability** on this repository. Please don't
open a public issue. Include the version, what an attacker can do and the steps to reproduce it.

You get a reply within a week. Once a fix is released, the advisory credits you unless you ask
otherwise.

## Scope

In scope: the ThreatCull web UI, API, CLI, the container image and the Outputs it publishes.

Out of scope: the content of upstream Sources (report wrong listings to their publishers) and
problems that need an attacker who already has the admin password or shell access to the host.
