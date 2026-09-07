# secguard

Application security intelligence platform.

## Goal

Accept an authorized application URL, discover its technology and attack surface, perform generic security analysis, and provide deeper platform-specific analysis such as Mendix domain-model and security analysis.

## Run

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m flask --app backend.app run --port 8000
```

Open `http://127.0.0.1:8000`.

## Tests

```bash
.venv/bin/pip install pytest
.venv/bin/python -m pytest tests
```

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/health` | Service status. |
| `POST /api/discover` | Discover, analyze and store an authorized application. Authenticated, rate limited. |
| `POST /api/mendix/analyze` | Analyze a Mendix model export. Authenticated, rate limited. |
| `DELETE /api/applications/<id>` | Delete a stored application and its findings. Authenticated. |
| `GET /api/applications` | Stored applications with their risk summary. |
| `GET /api/applications/<id>` | Full application record. |
| `GET /api/applications/<id>/findings` | Findings, filterable by `severity`, `category`, `platform` and `rule_id`. |
| `GET /api/applications/<id>/findings/<finding_id>` | A single finding. |
| `GET /api/rules` | Catalogue of the rules the engine evaluates. |

## Analysis pipeline

`POST /api/discover` fetches the target, crawls same-origin pages, probes common API and sensitive paths, then runs the rule engine over the collected evidence.

- `backend/discovery/` — fetching, crawling, technology and endpoint discovery.
- `backend/scanners/` — active path probing with soft-404 baselining.
- `backend/rules/` — the rule engine and the generic rule packs (transport, headers, cookies, forms, API, exposure).
- `backend/risk/` — severity and confidence normalisation, per-finding and aggregate scoring.
- `backend/recommendations/` — remediation grouped per rule.
- `backend/platforms/mendix/` — Mendix model parsing and security analysis.

Findings are normalised (rule id, severity, confidence, category, CWE, OWASP, evidence, location) and stored next to the application record under `data/applications/<id>/`.

## Security configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECGUARD_API_TOKEN` | empty | Shared secret for the scanning and delete endpoints, sent as `Authorization: Bearer <token>` or `X-API-Key`. When it is empty those endpoints only answer requests from the loopback interface, so an unconfigured install is never remotely driveable. Set it in the UI's *API token* field. |
| `SECGUARD_ALLOW_PRIVATE_TARGETS` | `0` | Allow scanning targets that resolve to loopback, RFC1918, link-local or reserved addresses. Off by default, so the scanner cannot be pointed at internal services or cloud metadata endpoints. |
| `SECGUARD_ALLOWED_TARGET_HOSTS` | empty | Comma-separated hostnames that may be scanned regardless of the address they resolve to, e.g. `127.0.0.1,localhost` for a local test target. |
| `SECGUARD_RATE_LIMIT_REQUESTS` | `10` | Scan requests allowed per client address per window. |
| `SECGUARD_RATE_LIMIT_WINDOW` | `60` | Rate-limit window in seconds. |

Target policy is enforced before the first request and again on every redirect hop, so a public target cannot bounce the scanner onto an internal address. The rate limiter is in-process; running multiple workers would need a shared store.

Only scan applications you are authorised to test. The scanner is passive apart from unauthenticated GET requests to common paths; it does not attempt exploitation.
