# HackOn Recon Report

_Generated: 2026-05-04 18:00:00Z_

## Target

- `example.com`

## Open Ports

- 80 (http)
- 443 (https)
- 6379 (redis)

## Discovered Endpoints

- /admin — 403 (https://example.com/admin)
- /api — 200 (https://example.com/api)

## Subdomains

- www.example.com → 93.184.216.34
- api.example.com → 93.184.216.34
- dev.example.com (unresolved)
- test.example.com (unresolved)

## Risk Analysis

- **Overall risk score**: `100` / `100`

- **LOW** — score `30` — `endpoint` `/admin` — Sensitive endpoint exposed: /admin
- **MEDIUM** — score `55` — `endpoint` `https://example.com/admin` — Received 403 (possible access control bypass potential)
- **HIGH** — score `75` — `endpoint` `https://example.com/admin` — Sensitive keyword detected in URL/path (api/dev/test)
- **EXTREME** — score `95` — `port` `6379` — Uncommon service port open: 6379
- **EXTREME** — score `100` — `subdomain` `2` — Multiple subdomains resolved (2) increases attack surface

## High Priority Targets

- `endpoint` `https://example.com/admin` (HIGH / 75)
- `port` `6379` (EXTREME / 95)
- `subdomain` `2` (EXTREME / 100)

## Recommendations

- Restrict or remove public access to administrative endpoints (`/admin`, `/login`) where possible.
- Harden access controls and validate authorization logic for endpoints returning `403`.
- Close or firewall uncommon service ports (e.g. 3306/MySQL, 6379/Redis) from the public internet.
- Reduce fingerprinting by minimizing unnecessary server banner exposure (where feasible).
- Review subdomain inventory and apply consistent TLS, auth, and monitoring across environments (dev/test/api).

