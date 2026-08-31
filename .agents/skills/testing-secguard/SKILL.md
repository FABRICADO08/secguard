---
name: testing-secguard
description: How to run and end-to-end test the SecGuard application security platform (Flask backend + static frontend), including how to scan a target safely with a local vulnerable fixture server.
---

# Testing SecGuard

## Running the app

```bash
cd <repo>
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m flask --app backend.app run --port 8010
```

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

Against that fixture the rule engine should evaluate 23 rules, produce **17** findings
(`critical:1, high:2, medium:8, low:3, informational:3`), `risk_score` 100, `risk_grade` "E",
and `rule_errors: []`. Use those numbers as a regression baseline.

Note the baseline changed from 18/`medium:9` to 17/`medium:8` once `GEN-INF-002` was narrowed (see
"Directory-listing rule" below): the fixture body has `<h1>Index of /</h1>` but no `<a href=`, so the
rule correctly no longer fires. If you see 18 findings, you are probably on an older revision.

## Directory-listing rule (GEN-INF-002) — falsifiable fixture pair

`GEN-INF-002` requires BOTH a marker (`index of /` inside `<title>`/`<h1>`, or `[To Parent Directory]`)
AND at least one `<a href=`. Testing it properly needs two fixtures, otherwise a pass is meaningless:

- a **prose** page (e.g. `127.0.0.1:8096`) whose body mentions "index of /" in ordinary text and also
  has links → the rule must **not** fire
- a **genuine listing** (e.g. `127.0.0.1:8097`) with the marker in `<title>`/`<h1>` plus `<a href=`
  entries → the rule **must** fire

A helper serving both is at `/home/ubuntu/listing_fixtures.py`. Always assert both halves; a
no-false-positive result alone does not prove the rule still detects real listings.

## Mendix model analysis (`POST /api/mendix/analyze`)

There is **no UI upload control**, so drive the upload over the API and verify the persisted
Application through the existing dashboard / findings / detail pages.

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

The frontend has historically lagged the backend, so always confirm page state before planning UI
steps. As of the findings-UI work these are functional:

- `/index.html` — scan form plus result cards: application metrics (`HTTP <code>`, response time),
  risk score + grade, severity counts, top 10 findings (each links to finding-detail),
  grouped recommendations, technology, attack surface, endpoints.
- `/dashboard.html` — all analyzed apps ranked by risk; summary tiles are app count, total findings,
  highest risk score, critical+high total. Each row links to that app's findings page.
- `/findings.html?application=<id>` — full findings list with severity and category dropdowns that
  forward to the API query params.
- `/finding-detail.html?application=<id>&finding=<id>` — severity, risk, confidence, category,
  platform, CWE/OWASP, description, recommendation, evidence JSON.
- Shared helpers live in `/js/common.js`.

`application.html`, `attack-path.html` and `attack-surface.html` may still be placeholders.

## Cross-checking the UI against the API

The fastest high-signal check is to compare filter counts. For the standard fixture:

```bash
B=http://127.0.0.1:8010/api/applications
curl -s "$B/<id>/findings"                               # 17 (was 18 before GEN-INF-002 narrowed)
curl -s "$B/<id>/findings?severity=critical"             # 1  (GEN-CFG-001, /.env)
curl -s "$B/<id>/findings?category=session"              # 3  (GEN-SES-001/002/003)
curl -s "$B/<id>/findings?severity=medium&category=session"  # 2
curl -s "$B/<id>/findings/does-not-exist"                # 404 "Finding not found."
curl -s http://127.0.0.1:8010/api/rules                  # 23 GEN-* rules
```

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
- The findings UI has **no platform filter control**, even though the API supports
  `?platform=<name>` on the findings endpoint. Platform filtering is therefore API-only and cannot
  be asserted through the UI; flag it as a gap rather than reporting it as tested.
- Aggregate `security.recommendations` are deduplicated per `rule_id`, so when one rule fires more
  than once with different guidance (e.g. `MXSEC-101` for delete-only vs create-only access) only
  the first recommendation survives and the count is lower than the finding count. Per-finding
  recommendations on the detail page are still correct — check there if an aggregate looks short.
- Aggregate recommendations are only rendered on `index.html` right after a direct URL scan; they
  are not shown for persisted applications opened from the dashboard (including Mendix uploads).
- Historical bugs that were fixed but are worth re-checking on new branches: `HTTP -` / `- ms`
  placeholders (`Application.to_dict()` omitting `status_code`/`response_time_ms`), an inflated
  "API Candidates" count from 404 probe paths, and a validation error leaving the previous scan's
  result cards on screen (`clearResults()` must run *before* the validation early-returns).

## Chrome omnibox gotcha

When navigating between API URLs that share a prefix, Chrome inline-autocompletes to the previously
visited URL (e.g. re-adding `?severity=critical`). Press `Delete` after typing and before `Return`.
