# secguard

Application security intelligence platform.

## Goal

Accept an authorized application URL, discover its technology and attack surface, perform generic security analysis, and provide deeper platform-specific analysis such as Mendix domain-model and security analysis.

## Run

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run.py
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
| `POST /api/discover` | Discover, analyze and store an authorized application. |
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

Only scan applications you are authorised to test. The scanner is passive apart from unauthenticated GET requests to common paths; it does not attempt exploitation.
