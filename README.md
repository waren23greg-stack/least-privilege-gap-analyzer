# Least-Privilege Gap Analyzer

Detects **privilege creep** in PostgreSQL by comparing what accounts are *granted* with what they *actually use*, scores the risk, generates `REVOKE` scripts with rollback, and keeps forensic evidence of who touched what and when.

Built with PostgreSQL (SQL / psql), Excel and Power BI. Runs against a lab database with fake data only.

## The problem

Access only ever grows. People change teams and keep old rights, leavers keep working accounts, logins get shared, and roles collect permissions nobody uses. Native PostgreSQL tells you what is **granted**. It does not tell you what is **needed**. This project closes that gap with evidence from usage logs.

## What it detects

| Gap | How it is detected | Planted in the lab data |
|---|---|---|
| Unused / stale privileges | Granted privilege with no use, or last use older than 90 days | `esther_w` payments SELECT, `hassan_i` payments UPDATE |
| Dormant account | Valid login, zero log activity | `quinn_s` |
| Over-privileged account | `SUPERUSER` / `CREATEROLE` on non-admin staff | `brian_o`, `grace_m` |
| Leaver still active | HR says terminated, DB login still works and is used | `peter_x` |
| Mover keeping old access | Department changed, old role never removed | `tom_l` (Finance to Support) |
| Shared account | One account, many source IPs, no HR owner | `shared_reports` |
| Role bloat | Role grants far more than its members use | `role_analyst` (full write, read-only in practice) |
| Direct grants bypassing roles | Privileges granted to a user outside any role | `david_n`, `mary_c`, `irene_k`, `kevin_b` |

Planned: segregation-of-duties conflicts, sensitive-column exposure, off-hours and volume anomalies, log tamper detection. See [ROADMAP](docs/ROADMAP.md).

## How it works

1. **Lab**: build a messy fake company database with planted problems.
2. **Snapshot**: record who holds which privileges, and through which role.
3. **Usage**: load the access log (simulated here, real logs later).
4. **Detect**: join granted vs used, classify each privilege as active, stale or never used, and raise flags.
5. **Score**: `sensitivity x privilege weight x days unused`, then rank accounts and roles.
6. **Remediate**: generate `REVOKE` and rollback scripts. Nothing is applied automatically.
7. **Prove**: apply in the lab, re-score, replay the log to show nothing in active use breaks.
8. **Report**: export to Excel and Power BI.

Details: [ARCHITECTURE](docs/ARCHITECTURE.md).

## Lab results

Measured on the simulated company database (207 effective privileges, 20 accounts, 180 days of log):

| Metric | Before | After |
|---|---|---|
| Privileges granted | 207 | 92 |
| Privileges in active use | 68 | 68 |
| Utilization | 32.9% | 73.9% |
| Risk points | 311,540 | 35,250 (-88.7%) |
| Critical accounts | 2 | 1 |
| Recent events by current staff denied (last 90 days) | | 0 of 1,321 |
| Rollback | | Restored grants and accounts identical to before |

What is left is deliberate: `SUPERUSER`, `CREATEROLE`, the dormant account and the shared account need a human decision, and role grants that only some members use cannot be revoked per member.

## Repo layout

```
sql/        numbered pipeline scripts, run in order
docs/       ROADMAP.md, ARCHITECTURE.md
exports/    generated REVOKE and rollback scripts (CSV for Excel / Power BI planned)
scripts/    run_all.sh helper                    (planned)
excel/      analysis workbook                    (planned)
powerbi/    dashboard                            (planned)
```

## Quick start (Git Bash, Windows)

Requires PostgreSQL with `psql` on your PATH.

```bash
createdb -U postgres privilege_audit
psql -U postgres -d privilege_audit -f sql/01_setup_messy_db.sql
psql -U postgres -d privilege_audit -v snapshot=before -f sql/02_collect_granted.sql
psql -U postgres -d privilege_audit -f sql/03_load_usage_log.sql
psql -U postgres -d privilege_audit -v snapshot=before -f sql/04_gap_queries.sql
psql -U postgres -d privilege_audit -v snapshot=before -f sql/05_risk_scoring.sql
mkdir -p exports
psql -U postgres -d privilege_audit -v snapshot=before -f sql/06_generate_revokes.sql
```

`02`, `04`, `05` and `06` take `-v snapshot=before|after`. `03` takes an optional `-v as_of=YYYY-MM-DD`; keep the default, because the leaver's termination date is fixed relative to it.

Apply the plan in the lab, re-measure and compare:

```bash
psql -v ON_ERROR_STOP=1 -U postgres -d privilege_audit -f exports/revoke_before.sql
for s in 02_collect_granted 04_gap_queries 05_risk_scoring; do
  psql -q -v ON_ERROR_STOP=1 -U postgres -d privilege_audit -v snapshot=after -f sql/$s.sql > /dev/null
done
psql -U postgres -d privilege_audit -f sql/07_verify_after.sql
```

Undo it and prove the undo is exact (section 6 of `07` then reports zero differences):

```bash
psql -v ON_ERROR_STOP=1 -U postgres -d privilege_audit -f exports/rollback_before.sql
psql -q -U postgres -d privilege_audit -v snapshot=restored -f sql/02_collect_granted.sql > /dev/null
psql -U postgres -d privilege_audit -f sql/07_verify_after.sql
```

## Safety

- `01` refuses to run unless connected to `privilege_audit`, because PostgreSQL roles are cluster-wide.
- All data is fake.
- REVOKE scripts are generated for human review, never auto-applied.
- Every REVOKE ships with its rollback.

## Status

| Script | Purpose | State |
|---|---|---|
| `01_setup_messy_db.sql` | Fake company DB, roles, planted gaps | Done |
| `02_collect_granted.sql` | Snapshot of accounts and effective grants | Done |
| `03_load_usage_log.sql` | Simulated 180-day usage log | Done |
| `04_gap_queries.sql` | Granted vs used, flags, sensitivity, findings | Done |
| `05_risk_scoring.sql` | Risk points, percentiles, tiers | Done |
| `06_generate_revokes.sql` | Remediation plan, REVOKE and rollback files | Done |
| `07_verify_after.sql` | Before/after comparison, log replay, rollback proof | Done |
| `08` | Forensics: timelines, tamper evidence | Planned |
