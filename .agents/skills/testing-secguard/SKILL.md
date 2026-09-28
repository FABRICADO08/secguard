---
name: testing-secguard
description: How to run and end-to-end test the SecGuard application security platform (Flask backend + static frontend), including how to scan a target safely with a local vulnerable fixture server.
---

# Testing SecGuard

## Running the app

```bash
cd <repo>
python -m venv .venv && .venv/bin/pip install -r requirements.txt
SECGUARD_ALLOW_PRIVATE_TARGETS=1 .venv/bin/python -m flask --app backend.app run --port 8010
```

- **`SECGUARD_ALLOW_PRIVATE_TARGETS=1` is mandatory for local fixture testing.**
  `assert_target_allowed` (`backend/security/targets.py`) rejects loopback and RFC1918 targets
  outright, so without it every fixture scan fails on an allow-list error rather than reaching the
  scanner. `SECGUARD_ALLOWED_TARGET_HOSTS=127.0.0.1` is the narrower alternative, but the env flag
  is what the TLS tests use. If a scan fails with a blocked/forbidden target message, check this
  first — it looks like a scanner bug but is not.
- The frontend is served from the Flask root (`/`); the API lives under `/api`.
- `backend/app.py`'s `__main__` block hardcodes port 8000, but `flask --app backend.app run --port N`
  works and is preferable — port 8000 has been flaky on test boxes.
- No login, no credentials, no secrets required. `data/applications/<id>/` is the on-disk store;
  scans accumulate there, so delete stale dirs if you need a clean list.

## Devin Secrets Needed

None.

## Never scan public internet sites

Use a local, deliberately-vulnerable fixture server instead. A minimal `http.server` handler that
triggers most `GEN-*` rules should serve, on `127.0.0.1:8099`:

- no security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- `Server: TestServer/1.2.3`, `Access-Control-Allow-Origin: *`
- `Set-Cookie: SESSIONID=abc; Path=/` (no Secure/HttpOnly/SameSite)
- an HTML body containing `Index of /`, a POST login form with a `password` input and no CSRF token,
  and a `<script src>`
- 200 responses for `/.env`, `/swagger.json`, `/api/v1`; 404 for everything else

Against that fixture the rule engine should produce `risk_score` 100, `risk_grade` "E" and
`rule_errors: []`. **Do not hardcode the finding/rule counts from this file** — the generic catalog
grows most PRs. Measured baselines by revision:

| revision | rules evaluated | findings | severity split |
|---|---|---|---|
| findings-UI era | 23 | 17 | `1/2/8/3/3` |
| `ca4e4d8` (TLS partial-scan) | 37 | 25 | `1/3/11/6/4` |

Re-measure at the start of a run with
`curl -s http://127.0.0.1:8010/api/rules | python3 -c "import json,sys;print(len(json.load(sys.stdin)['rules']))"`
rather than trusting the table, and use *that* as the run's baseline.

Note the finding baseline dropped by one once `GEN-INF-002` was narrowed (see "Directory-listing
rule" below): the fixture body has `<h1>Index of /</h1>` but no `<a href=`, so the rule correctly no
longer fires.

## Directory-listing rule (GEN-INF-002) — falsifiable fixture pair

`GEN-INF-002` requires BOTH a marker (`index of /` inside `<title>`/`<h1>`, or `[To Parent Directory]`)
AND at least one `<a href=`. Testing it properly needs two fixtures, otherwise a pass is meaningless:

- a **prose** page (e.g. `127.0.0.1:8096`) whose body mentions "index of /" in ordinary text and also
  has links → the rule must **not** fire
- a **genuine listing** (e.g. `127.0.0.1:8097`) with the marker in `<title>`/`<h1>` plus `<a href=`
  entries → the rule **must** fire

A helper serving both is at `/home/ubuntu/listing_fixtures.py`. Always assert both halves; a
no-false-positive result alone does not prove the rule still detects real listings.

## TLS / certificate-rejected scans

A target whose certificate fails validation does **not** error out: `/api/discover` returns HTTP
**200** with `success: true`, `partial: true`, `reason: "certificate_rejected"`, and persists the
application with `status: "certificate_rejected"`. The frontend (`app.js`, the `data.partial`
branch) renders an **amber warning** reading `"<cert error> Only the TLS findings were recorded.
Application ID: …"` — not the green `Discovery completed.` line. Asserting "a 502" or "a success
line" here is wrong on both counts.

On such a scan only rules with `requires_response = False` run — currently exactly
`GEN-TLS-004/005/006/007` — because `ScanContext.response_observed=False` gates every rule that
reads the HTTP response. So expect **4** rules evaluated and **only** `GEN-TLS-*` findings. Any
`GEN-HDR-*`, `GEN-CSP-*`, `GEN-SES-*` or `GEN-CFG-*` finding on a certificate-rejected scan is a
regression: the scanner never saw a response and cannot know a header is absent.

### Minting TLS fixtures

OpenSSL 3.0's `req` rejects `-not_before`/`-not_after`, and `faketime` is usually unavailable, so
mint certificates programmatically with `cryptography` (`.venv/bin/pip install cryptography`;
it is not in `requirements.txt`). Give each cert a
`SubjectAlternativeName([x509.IPAddress(ip_address("127.0.0.1"))])` or the failure is a hostname
mismatch rather than the trust failure you meant to test. A ready-made four-server script lives at
`/home/ubuntu/tls_pr18_fixtures.py`:

| target | certificate | exercises |
|---|---|---|
| `https://127.0.0.1:8443` | self-signed, valid dates | `GEN-TLS-007` only |
| `https://127.0.0.1:8444` | self-signed, expired 2021 | `GEN-TLS-006` + `007`, risk 94/E |
| `https://127.0.0.1:8445` | self-signed, `notAfter` UTCTime `600101000000Z` | ASN.1 century pivot |
| `http://127.0.0.1:8446` | plain HTTP, 302 → `https://127.0.0.1:8443` | redirect-hop diagnosis |

**The 1960 cert is the only falsifiable expiry test.** ASN.1 UTCTime pivots at 50 (50-99 → 19xx)
but Python's `%y` pivots at 69, so the two disagree *only* for years 50-68. A cert expiring in
2021 or the 1990s passes under both the correct and the broken parser. Assert the detail-page
evidence shows `expires_at: "1960-…"` with a negative `days_until_expiry`; a 2060 date means the
pivot is broken.

For the redirect fixture, the failing hop — not the healthy first hop — must be named in the
warning and in the `GEN-TLS-007` evidence `port`. The application keeps `requested_url:
http://127.0.0.1:8446` and `final_url: https://127.0.0.1:8443`. Note the **UI only ever displays
`final_url`** (dashboard row, findings header, detail location), so check `requested_url`
preservation via `curl /api/applications/<id>`.

## Mendix model analysis (`POST /api/mendix/analyze`)

The discovery page has a **"Analyze a Mendix model" card** (`#mendixModel` file input,
`#mendixButton`, `#mendixStatus`) that posts multipart field `model` and reuses `showResults()`;
prefer it for UI testing. To set a file in the picker, focus it and use `ctrl+l` to type the path.
The API is still the faster path for bulk adversarial cases:

```bash
# multipart
curl -s -F "model=@tests/fixtures/mendix_model.json" http://127.0.0.1:8010/api/mendix/analyze
# JSON body (honours an explicit "name")
curl -s -H 'Content-Type: application/json' \
  --data '{"model": {...}, "name": "access-review.json"}' http://127.0.0.1:8010/api/mendix/analyze
```

The record appears with `platform: "Mendix"` and `final_url: mendix-model://<sanitized name>`.

Adversarial inputs worth covering (all should be HTTP 400 and must create **no** Application record —
assert the `/api/applications` count is unchanged before/after):

| input | expected error |
|---|---|
| 0-byte file (repo-root `domain-model.json`) | `Uploaded Mendix model file is empty.` |
| malformed JSON | `Uploaded Mendix model is not valid JSON: ...` |
| JSON array root (multipart) | `Mendix model JSON root must be an object.` |
| JSON array root (body) | `Provide a Mendix model as a 'model' file upload or a JSON body.` |
| `{}` or unrelated JSON | `No Mendix model elements were found. ...` |
| >25 MB (body **or** multipart) | `Mendix model exceeds the 25 MB upload limit.` |

The size limit is enforced via `request.content_length`, so it covers JSON bodies too — test both
transports, since an earlier revision only limited the multipart branch.

Upload filenames are sanitized server-side (path components stripped, `<>"'&` and non-printables
removed, truncated to 128 chars). Upload with
`filename=../<img src=x onerror=alert(1)>.json` and assert the stored name is
`img src=x onerror=alert(1).json`, that it renders as literal text on the dashboard and findings
header, and that `document.querySelectorAll('img').length === 0`.

## Frontend pages (check which exist on the branch under test)

Every page is an empty `<body>` filled by `js/shell.js` (`renderShell()` writes the icon rail,
navigation drawer, breadcrumbs and the `#view` container) plus one page script. Shared helpers,
formatting, severity/rating components, grouping and the inline-SVG charts live in `js/common.js`;
styling is `css/shell.css` (layout, responsiveness) and `css/views.css` (components).

Portfolio scope:

- `/dashboard.html` — KPI tiles (systems, findings, critical+high, average rating) and the systems
  table with search and per-system delete.
- `/portfolio-security.html` — findings-per-month trend (new/existing/resolved), severity split and
  the systems ranking with CSV export. The topbar period chip (3/6/12 months) redraws the trend.
- `/index.html` — scan form (URL + authorization checkbox) and the Mendix/OutSystems model upload
  cards; the result card links into the system security view.
- `/settings.html` — API token (stored as `secguardApiToken`, sent as `X-API-Key`) and `/api/health`.

System scope (all take `?application=<id>`, falling back to `currentApplicationId` in localStorage):

- `/application.html` — metadata, scan metrics, attack-surface counts, technologies, scan history.
- `/system-security.html` — findings/latest-scan KPI, rating stars, severity split with deltas,
  new/existing/resolved activity against the previous scan, findings-by-category chart and the
  grouped table (OWASP / category / severity / platform) whose rows drill into the findings page.
- `/findings.html` — all findings, or one group with `&grouping=<key>&group=<name>`; Severity,
  Category and Platform dropdowns persist in the query string.
- `/finding-detail.html?...&finding=<id>` — severity, risk, confidence, CWE/OWASP, description,
  recommendation, references, evidence JSON.
- `/attack-surface.html` — pages, endpoints, forms, scripts, exposed paths, disclosed libraries.

Responsiveness is part of the product: below 1024px the drawer becomes an overlay opened by the
topbar menu button (Escape or the scrim closes it), and below 720px the data tables restack as
cards using each cell's `data-label`. Test at phone, tablet and desktop widths.

## Cross-checking the UI against the API

The fastest high-signal check is to compare filter counts. For the standard fixture:

```bash
B=http://127.0.0.1:8010/api/applications
curl -s "$B/<id>/findings"                               # all findings (re-measure per revision)
curl -s "$B/<id>/findings?severity=critical"             # 1  (GEN-CFG-001, /.env)
curl -s "$B/<id>/findings?category=session"              # GEN-SES-*
curl -s "$B/<id>/findings?severity=medium&category=session"
curl -s "$B/<id>/findings?platform=Nonsense"             # 0 — negative control
curl -s "$B/<id>/findings/does-not-exist"                # 404 "Finding not found."
curl -s http://127.0.0.1:8010/api/rules                  # current GEN-* rule count
```

When checking the Platform filter, confirm the value is genuinely sent by looking for
`?platform=<value>` in the Flask access log, and use a nonsense value as a negative control so you
are not just observing a permissive filter. `findings.html` is per-application, so one page only
ever offers a single real platform (Mendix **or** Generic) — Mendix and URL findings never share a
dropdown.

Dashboard tiles should equal the aggregate over `/api/applications`: app count, sum of
`total_findings`, max `risk_score`, and sum of `critical + high`. Note each scan appends a new
application, so re-scanning during a test run changes dashboard totals — recheck them at the end or
wipe `data/applications/` first for determinism.

## Adversarial / routing cases worth covering

- `/findings.html` with no `?application=` → "No application selected." plus a dashboard link.
- `/findings.html?application=bogus` → "Application not found."
- `/finding-detail.html?application=<real>&finding=bogus` → "Finding not found."
- `/finding-detail.html` with no params → "No finding selected."
- Empty URL → "Enter an application URL."; non-URL text → "URL must start with http:// or https://.";
  unchecked box → "Confirm that you are authorized to assess this application.";
  unreachable host (`http://127.0.0.1:9`) → "Application discovery failed." with the button
  re-enabled and no spurious application record.
- On failure paths `app.js` deliberately calls `console.error("Discovery error: ...")`. Those console
  entries are expected and are NOT unhandled exceptions — only treat a console error as a defect if
  it appears on a *successful* scan.

## Testing XSS / escaping

Stand up a second fixture (e.g. `127.0.0.1:8098`) that embeds a payload such as
`"><img src=x onerror="window.__xss=1">` in the `Server` header and in the `Set-Cookie` cookie name.
Those strings flow into the technology name, the `GEN-SES-*` finding titles and `GEN-INF-001`
evidence, exercising the index, findings-list and detail rendering paths at once. Assert the payload
is visible as literal text, `document.querySelectorAll('img').length === 0`, and `window.__xss` is
`undefined`. A single console read is acceptable as the assertion here; do the rest via the UI.

## Known rough edges to expect

- Client-side validation only checks non-empty URL and the "authorized" checkbox; the checkbox is
  NOT enforced server-side, so `POST /api/discover` will scan without it.
- An unreachable target now returns HTTP **502** with `reason: "unreachable"` and an actionable
  message ("Could not connect to <url>. Check the host, port and scheme, ...") that `app.js` renders
  via `data.error`. Older revisions returned a generic 500 "Application discovery failed.".
- The detected technology name is the raw concatenated `Server` header, e.g.
  `basehttp/0.6 python/3.10.12, testserver/1.2.3`, rendered verbatim.
- Findings-page filter selections are preserved across in-page option re-renders but **not across a
  real browser refresh** (`findings.js` has no localStorage/sessionStorage/URL-history code). If a
  PR claims "preserved across reloads", press F5 and check rather than assuming.
- Aggregate `security.recommendations` are grouped by `(rule_id, recommendation)`, so one rule
  firing with two different texts (e.g. `MXSEC-101` delete-only vs create-only) keeps **both**
  entries, while identical texts collapse into one carrying a `finding_count` ("N finding(s)").
  Test both directions — "keep both" alone would also pass a never-deduplicate implementation.
  `/home/ubuntu/multi_exposure_fixture.py` (8095) emits three identical `GEN-CFG-001` findings and
  is the collapse half of that pair.
- Mendix/OutSystems applications render `HTTP -`, `- ms` and `0 Pages/Endpoints/Technologies`
  because no HTTP request is made for a model upload. Cosmetic, not a regression.
- TLS evidence can read `"self_signed": false` alongside `"trust_error": "self-signed
  certificate"` — the boolean comes from a subject/issuer comparison that is empty on the
  unverified retry. Judge the trust failure by `trusted`/`trust_error`, not `self_signed`.
- Aggregate recommendations are only rendered on `index.html` right after a direct URL scan; they
  are not shown for persisted applications opened from the dashboard (including Mendix uploads).
- Historical bugs that were fixed but are worth re-checking on new branches: `HTTP -` / `- ms`
  placeholders (`Application.to_dict()` omitting `status_code`/`response_time_ms`), an inflated
  "API Candidates" count from 404 probe paths, and a validation error leaving the previous scan's
  result cards on screen (`clearResults()` must run *before* the validation early-returns).

## Chrome omnibox gotcha

When navigating between API URLs that share a prefix, Chrome inline-autocompletes to the previously
visited URL (e.g. re-adding `?severity=critical`). Press `Delete` after typing and before `Return`.
