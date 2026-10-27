# Operations runbook

## What holds state

| Store | Postgres (`POSTGRES_URL` / `DATABASE_URL` set) | File storage |
| --- | --- | --- |
| Scans, findings, names, triage, settings | `applications`, `findings`, `application_names`, `finding_triage`, `portfolio_settings` | `data/applications/`, `data/*.json` |
| Sign-in sessions | `sessions` | `data/sessions/` |
| Audit log | `audit_log` (append-only trigger) | `data/audit/audit.jsonl` |
| Rate limits (disposable) | `rate_limits` | memory |
| Schema version | `schema_migrations` | — |

Production should run on Postgres. App Service's local disk is not backed up, and it is reset when the app is redeployed or moved to another instance.

## Backups

**Postgres.** Use your provider's point-in-time restore as the primary backup: Neon keeps history for its restore window, and Azure Database for PostgreSQL keeps 7–35 days. Also take a logical dump on a schedule, for example nightly, and keep it outside the database provider:

```bash
pg_dump --format=custom --no-owner --file="secguard-$(date +%F).dump" "$POSTGRES_URL"
```

Keep dumps for at least as long as your audit evidence policy requires. Treat them as secrets: they contain session rows and GitHub repository details.

**File storage.** Stop the app or take a filesystem snapshot first, so files aren't copied mid-write. Then archive the whole `data/` directory:

```bash
tar -czf "secguard-data-$(date +%F).tar.gz" data/
```

**Audit evidence.** For long-term retention, export the log as well: `GET /api/audit.csv` with an admin credential.

## Restore

1. Stop traffic: scale to zero, or stop the App Service.
2. Postgres: restore point-in-time to a **new** database, or load a dump into an empty one:
   ```bash
   pg_restore --no-owner --dbname="$NEW_POSTGRES_URL" secguard-YYYY-MM-DD.dump
   ```
   The `audit_log` append-only trigger blocks only `UPDATE` and `DELETE`, so restoring into an empty database works.
   File storage: extract the archive over an empty `data/` directory.
3. Point `POSTGRES_URL` at the restored database and deploy the **same or newer** release as the backup was taken with. An older release refuses a newer schema with `SchemaTooNew`.
4. Check that `GET /api/health/ready` returns 200, that the portfolio lists the expected systems, and that `GET /api/audit` shows entries up to the backup time.
5. Users sign in again if their sessions have expired.

Rehearse a restore into a scratch database at least once a quarter, and record how long it took.

## Schema changes

Add a new numbered entry to `MIGRATIONS` in `backend/storage/db.py`; never edit a version that has already been applied. Migrations run in one transaction under an advisory lock the first time a process opens a connection. Take a backup before deploying a release that adds a migration.

## Retention

`SECGUARD_SCAN_RETENTION_DAYS` (default `0`, keep everything) sets how many days a scan is kept after its last update. Each system's newest scan is always kept. Prune once a day:

```bash
curl -fsS -X POST -H "Authorization: Bearer $SECGUARD_API_TOKEN" https://<host>/api/retention/prune
```

or run `python -m backend.storage.retention` on the host. Add `?dry_run=1` or `--dry-run` to see what would be removed. Each prune request is recorded in the audit log.

Sessions expire on their own. The audit log is never pruned by SecGuard; archive and trim it according to your compliance policy, using a database role that bypasses the trigger.
