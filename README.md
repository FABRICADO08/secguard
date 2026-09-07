# secguard

Application security intelligence platform.

## Goal

Accept an authorized application URL, discover its technology and attack surface, perform generic security analysis, and provide deeper platform-specific analysis for Mendix and OutSystems models.

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
| `POST /api/outsystems/analyze` | Analyze an OutSystems application export. Authenticated, rate limited. |
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
- `backend/platforms/outsystems/` — OutSystems export parsing and security analysis.

Findings are normalised (rule id, severity, confidence, category, CWE, OWASP, evidence, location) and stored next to the application record under `data/applications/<id>/`.

### OutSystems export format

`POST /api/outsystems/analyze` reads a JSON document describing the application's modules; keys are accepted in camelCase or PascalCase and unknown keys are ignored, so an export only has to carry the parts it knows about. See `tests/fixtures/outsystems_model.json` for a complete example.

```json
{
  "name": "CustomerPortal",
  "modules": [
    {
      "name": "CustomerPortal",
      "roles": ["Customer"],
      "entities": [
        {
          "name": "Customer",
          "public": true,
          "exposeReadOnly": false,
          "attributes": [{"name": "Email", "isEncrypted": false}]
        }
      ],
      "screens": [{"name": "Login", "anonymous": true, "roles": []}],
      "exposedRestApis": [
        {
          "name": "CustomerApi",
          "authentication": "None",
          "methods": [{"name": "ListCustomers", "httpMethod": "GET"}]
        }
      ],
      "consumedRestApis": [{"name": "BillingApi", "baseUrl": "http://..."}],
      "siteProperties": [{"name": "BillingApiKey", "defaultValue": "..."}],
      "queries": [{"name": "SearchCustomers", "expandInline": ["OrderBy"]}]
    }
  ]
}
```

| Rule | Detects |
| --- | --- |
| `OSSEC-101` | Screen reachable without a role. |
| `OSSEC-102` | Exposed REST method with no authentication or roles. |
| `OSSEC-103` | Public entity that consuming modules can write to. |
| `OSSEC-104` | Site property shipping a secret as its default value. |
| `OSSEC-105` | Sensitive attribute stored unencrypted. |
| `OSSEC-106` | Advanced SQL expanding a parameter inline. |
| `OSSEC-107` | Consumed API called over plain HTTP. |

## Security configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECGUARD_API_TOKEN` | empty | Shared secret for the scanning and delete endpoints, sent as `Authorization: Bearer <token>` or `X-API-Key`. When it is empty those endpoints only answer direct requests from the loopback interface — requests carrying `X-Forwarded-For`, `X-Real-IP` or `Forwarded` are refused, so a reverse proxy cannot make remote callers look local. Configure a token when serving SecGuard behind a proxy. Set it in the UI's *API token* field. |
| `SECGUARD_ALLOW_PRIVATE_TARGETS` | `0` | Allow scanning targets that resolve to loopback, RFC1918, link-local or reserved addresses. Off by default, so the scanner cannot be pointed at internal services or cloud metadata endpoints. |
| `SECGUARD_ALLOWED_TARGET_HOSTS` | empty | Comma-separated hostnames that may be scanned regardless of the address they resolve to, e.g. `127.0.0.1,localhost` for a local test target. |
| `SECGUARD_RATE_LIMIT_REQUESTS` | `10` | Scan requests allowed per client address per window. |
| `SECGUARD_RATE_LIMIT_WINDOW` | `60` | Rate-limit window in seconds. |

Target policy is enforced before the first request, again on every redirect hop, and once more against the address each connection actually lands on, so neither a redirect nor a second DNS answer can steer the scanner onto an internal address. Scans always run over direct connections: proxy settings are ignored and an explicitly proxied request is refused, because a proxy would connect on the scanner's behalf. Other environment settings, such as `REQUESTS_CA_BUNDLE`, still apply. The rate limiter is in-process; running multiple workers would need a shared store.

Only scan applications you are authorised to test. The scanner is passive apart from unauthenticated GET requests to common paths; it does not attempt exploitation.
