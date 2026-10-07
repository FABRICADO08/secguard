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

To serve it with a production WSGI server:

```bash
.venv/bin/gunicorn backend.app:app --bind 0.0.0.0:$PORT --workers 1
```

Keep `--workers 1`: the rate limiter holds its counters in process, so additional workers would each enforce the limit separately.

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
| `GET /api/portfolio/summary` | Systems, severity deltas, new/existing/resolved activity and the monthly trend across all scans. |
| `GET /api/rules` | Catalogue of the rules the engine evaluates. |
| `POST /api/repository/scans` | Store a report from the repository scanner (GitHub Action or CLI). Authenticated, rate limited. |
| `GET /api/applications/<id>/sbom?format=cyclonedx\|spdx` | SBOM of a scanned repository. |
| `GET /api/applications/<id>/quality` | Maintainability metrics, hotspots, quality findings and the health score. |

## Interface

The frontend is a static application served from the Flask root. Every page renders the same shell — an icon rail for the Portfolio and System scopes, a contextual navigation drawer, breadcrumbs and a reporting-period selector — and adapts from a phone to a desktop monitor: the drawer becomes an overlay below 1024px and data tables restack as cards below 720px.

| Page | Description |
| --- | --- |
| `/dashboard.html` | Portfolio overview: system count, findings, critical+high and the average rating, plus the systems table. |
| `/portfolio-security.html` | Findings per month (new, existing, resolved), the portfolio severity split and the systems ranking with CSV export. |
| `/index.html` | Start a scan or upload a Mendix/OutSystems model export. |
| `/application.html` | System overview: metadata, scan metrics, attack-surface counts, technologies and scan history. |
| `/system-security.html` | System security: rating, severity split with deltas against the previous scan, activity, and findings grouped by OWASP Top 10, category, severity or platform. |
| `/findings.html` | All findings of a system, or one group of the chosen grouping. |
| `/finding-detail.html` | A single finding with its evidence, recommendation and references. |
| `/attack-surface.html` | Pages, endpoints, forms, scripts, exposed paths and disclosed libraries. |
| `/settings.html` | API token used for the authenticated endpoints, and service health. |

Repeated scans of the same target are separate records; the portfolio views fold them into one system so the latest scan can be compared with its predecessor.

## Analysis pipeline

`POST /api/discover` fetches the target, crawls same-origin pages, reads `robots.txt` and any sitemap it declares, mines same-origin JavaScript for endpoints and secrets, probes common API and sensitive paths, sends an inert reflection marker through GET parameters, inspects the TLS endpoint when the target is HTTPS, then runs the rule engine over the collected evidence.

The TLS inspection handshakes with the host directly: it records the negotiated protocol and cipher, whether the chain validates, the certificate subject/issuer and its expiry, and which protocol versions the server still accepts. Legacy versions are offered with the local security level lowered so a current OpenSSL build does not make a server that still speaks them look clean; versions the local build cannot offer at all are listed under `untested_protocols` rather than counted as refused. Each handshake goes to an address that passed the target policy, so it cannot be redirected to an internal host by a second DNS answer.

Component versions are read from whatever the target discloses — versioned script filenames and CDN paths, the banners libraries print into the page or into a served bundle, and `Server`/`X-Powered-By` headers — and matched against `backend/knowledge/advisories.py`, a small hand-checked set where every entry names a public advisory and the release that fixed it. A version at or above the fixed release clears the advisory; a release line that no longer receives fixes at all is reported separately, because the risk there is the absence of future patches rather than a specific CVE.

The reflection probe is the only active input test: it appends `"'<>` plus a random marker to a GET parameter and reports how the value comes back. It never touches POST forms, so a scan cannot create or modify data on the target.

A target whose certificate does not validate cannot be fetched, but that failure is itself the finding, so the scan is still recorded from the TLS diagnosis alone: the application is saved with status `certificate_rejected`, carries only its `tls` attack surface, and the response reports `"partial": true` alongside the certificate error. Any other connection failure is still a `502`.

- `backend/discovery/` — fetching, crawling, robots/sitemap reading, script mining, reflection probing, technology and endpoint discovery.
- `backend/scanners/` — active path probing with soft-404 baselining.
- `backend/rules/` — the rule engine and the generic rule packs (transport, headers, content security policy, CORS, client-side secrets, cookies, forms, API, exposure, dependencies).
- `backend/knowledge/` — the advisory and end-of-life dataset component versions are matched against.
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

### Generic rule packs

| Rule | Detects |
| --- | --- |
| `GEN-HDR-*` | Missing or weak security headers, wildcard CORS. |
| `GEN-CSP-001` | Script sources allowing `'unsafe-inline'` or `'unsafe-eval'`, unless a nonce or hash neutralises them. |
| `GEN-CSP-002` | Script sources allowing any origin (`*`, `http:`, `https:`, `data:`). |
| `GEN-CSP-003` | Policy without `object-src`, `base-uri` or `frame-ancestors` and no `default-src` to fall back on. |
| `GEN-CORS-001` | `Access-Control-Allow-Origin: null`. |
| `GEN-CORS-002` | State-changing methods allowed from any origin. |
| `GEN-JS-001` | Credentials embedded in inline scripts, reported redacted. |
| `GEN-JS-002` | Source map referenced by the page. |
| `GEN-JS-003` | Credentials found in a served JavaScript file, reported redacted. |
| `GEN-JS-004` | Source map referenced by a served JavaScript bundle. |
| `GEN-INP-001` | GET parameter reflected with its quotes and angle brackets intact. |
| `GEN-TLS-001` to `GEN-TLS-003` | Plain HTTP, missing HTTPS redirect, mixed content. |
| `GEN-TLS-004` | Deprecated protocol version still accepted (TLS 1.1 or below). |
| `GEN-TLS-005` | Weak or export-grade cipher suite negotiated. |
| `GEN-TLS-006` | Certificate expired, or expiring within 30 days. |
| `GEN-TLS-007` | Certificate chain does not validate (self-signed, incomplete or wrong name). |
| `GEN-SES-001` to `GEN-SES-003` | Cookies missing `Secure`, `HttpOnly` or a `SameSite` policy. |
| `GEN-SES-004` | Session cookie persisted to disk through an expiry date. |
| `GEN-SES-005` | Cookie scoped to a parent domain and shared with every subdomain. |
| `GEN-AUTH-001` to `GEN-AUTH-003` | Credentials over plain HTTP, missing CSRF token, password autocomplete. |
| `GEN-AUTH-004` | HTTP Basic authentication challenge. |
| `GEN-AUTHZ-001`, `GEN-CFG-001` | Unauthenticated admin interfaces and exposed sensitive paths. |
| `GEN-API-*` | Exposed API documentation, unauthenticated endpoints, exposed GraphQL. |
| `GEN-INF-001`, `GEN-INF-002` | Server banner disclosure, directory listing. |
| `GEN-INF-004` | `robots.txt` disallowing administrative or internal paths. |
| `GEN-DEP-001` | Disclosed component version listed as vulnerable by a public advisory. |
| `GEN-DEP-002` | Component release line that no longer receives security fixes. |

## Repository scanning

`python -m backend.repository scan <path>` analyses a checked-out repository:

- **Dependencies** from `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `package.json`, `package-lock.json`, `go.mod`, `pom.xml`, `composer.lock` and `Gemfile.lock`. Without a lockfile, a ranged dependency is checked as the newest release its range allows.
- **Known vulnerabilities** from [OSV](https://osv.dev), one finding per advisory (aliases merged), with the smallest upgrade that clears every advisory and whether it crosses a major version.
- **Reachability**: advisories against packages your own code never imports are reported with `tentative` confidence.
- **Supply chain**: deprecated, unmaintained (no release for 2+ years) and archived packages, single-maintainer packages, typo-squats of popular packages, and brand-new rarely downloaded packages.
- **Licences**: SPDX expressions are classified (permissive, weak/strong/network copyleft, non-commercial) and compared with the project's own licence; `GPL OR commercial` dual licensing is flagged.
- **Freshness**: major/minor versions behind the latest release, libyears and a freshness index.
- **Code quality**: cyclomatic and cognitive complexity, long functions, many parameters, oversized classes/files, unused imports and variables, unreachable code, duplicated blocks, docstring and type-annotation coverage, missing README or API specification.
- **Health**: security, open-source and maintainability scores (0-100), an overall A-F grade and a star rating.

Outputs: a JSON report, SARIF for GitHub code scanning, CycloneDX 1.5 and SPDX 2.3 SBOMs. `--offline` skips registry and advisory lookups; `--fail-on high` fails the run on high or critical findings.

### GitHub Action

Copy `integrations/github/secguard.yml` to `.github/workflows/secguard.yml` in each repository. It scans every day at 06:00 UTC (adjust the cron for your timezone), on every pull request, and on demand from **Actions > SecGuard > Run workflow**. Each run:

1. publishes results to the repository's code scanning alerts,
2. on pull requests, posts a review with inline comments and one-click `suggestion` upgrades on the changed manifest lines,
3. keeps the report and SBOMs as a run artifact,
4. uploads the report to SecGuard when the `SECGUARD_URL` repository variable (and `SECGUARD_API_TOKEN` secret) are set.

### Sign in with GitHub

With GitHub sign-in configured, every page first opens a **Sign in** page with a **Sign in with GitHub** button; after GitHub confirms the account the user returns to the page they asked for, and the top bar shows their GitHub account on every page. **My Applications** lists every application whose repository the signed-in account can read, under its application name, like a Sigrid system, each with its latest scan and health grade; selecting one opens its **Application Health** page (vulnerable dependencies with the minimum fixing version, licences, freshness, code quality, SBOM downloads). Scans of repositories the user cannot read are hidden from every application, findings, SBOM and portfolio endpoint. **Run scan** starts the repository's SecGuard workflow and needs write access.

Each application has its own name, as in Sigrid, independent of the GitHub repository it is attached to. Set it in the workflow with `application-name:` (or the `SECGUARD_APPLICATION_NAME` repository variable used by the bundled workflow), or with **Rename** on the Application Health page (`PUT /api/repositories/<owner>/<repo>/name`, needs write access). A name set in SecGuard wins over the workflow's; without either, the repository name without its owner is used.

1. Create an OAuth app (GitHub > Settings > Developer settings > OAuth Apps) with the callback URL `https://<your-secguard-host>/auth/github/callback`.
2. Set:

| Variable | Purpose |
| --- | --- |
| `SECGUARD_GITHUB_CLIENT_ID` / `SECGUARD_GITHUB_CLIENT_SECRET` | OAuth app credentials. Sign-in, and repository filtering, are off while either is empty. |
| `SECGUARD_SECRET_KEY` | Signs the session cookie. Without it users are signed out on every restart. |
| `SECGUARD_SECURE_COOKIES` | `1` when served over HTTPS. |
| `SECGUARD_GITHUB_CALLBACK_URL` | Optional; must match the OAuth app when SecGuard sits behind a proxy. |
| `SECGUARD_GITHUB_WORKFLOW` | Workflow file **Run scan** starts (default `secguard.yml`). |
| `SECGUARD_SESSION_HOURS` | Session lifetime (default 8). |

The login uses the authorization-code flow with `state` and PKCE; the GitHub token stays in server memory and the cookie only carries a random session id.

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
