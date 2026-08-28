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

Against that fixture the rule engine should evaluate 23 rules, produce 18 findings
(`critical:1, high:2, medium:9, low:3, informational:3`), `risk_score` 100, `risk_grade` "E",
and `rule_errors: []`. Use those numbers as a regression baseline.

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
curl -s "$B/<id>/findings"                               # 18
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
- An unreachable target is reported as a generic "Application discovery failed." (backend 500)
  rather than a 4xx with an actionable message.
- The detected technology name is the raw concatenated `Server` header, e.g.
  `basehttp/0.6 python/3.10.12, testserver/1.2.3`, rendered verbatim.
- `GEN-INF-002` ("Directory listing is enabled") fires purely on the body text marker `index of /`,
  so it will false-positive on any page containing that phrase.
- Historical bugs that were fixed but are worth re-checking on new branches: `HTTP -` / `- ms`
  placeholders (`Application.to_dict()` omitting `status_code`/`response_time_ms`), an inflated
  "API Candidates" count from 404 probe paths, and a validation error leaving the previous scan's
  result cards on screen (`clearResults()` must run *before* the validation early-returns).

## Chrome omnibox gotcha

When navigating between API URLs that share a prefix, Chrome inline-autocompletes to the previously
visited URL (e.g. re-adding `?severity=critical`). Press `Delete` after typing and before `Return`.
