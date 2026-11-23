# Roadmap

Working rules: one file per commit, review the diff before every push, lab database only. Each phase has a "done when" so progress is checkable.

## Phase 0: Lab (done)

- [x] `01_setup_messy_db.sql`: fake company schema, 5 group roles, 20 logins, planted gaps
- [x] `03_load_usage_log.sql`: simulated 180-day usage log, parameterised `as_of`
- [x] `05_risk_scoring.sql`: privilege, account and role risk, percentiles, tiers

## Phase 1: Snapshot and detect (done)

- [x] `02_collect_granted.sql`: `audit.accounts` (attributes, role memberships) and `audit.granted_privileges` (direct and inherited, with `granted_via`), tagged by snapshot name
- [x] `04_gap_queries.sql`: `audit.table_sensitivity`, `audit.privilege_usage` (active / stale / never_used), `audit.account_flags`, six findings

**Done when:** the verification queries at the end of `03` run clean, `05` runs end to end, and every planted gap in the README table appears as a flag or a stale / never-used row.

## Phase 2: Remediation

- [ ] `06_generate_revokes.sql`: `audit.revoke_plan` with `revoke_sql`, `rollback_sql`, reason and risk points
- [ ] Rules: revoke only stale or never-used privileges; leavers get `NOLOGIN`; `SUPERUSER` / `CREATEROLE` removal and shared accounts go to a manual-review list
- [ ] Export `revoke.sql` and `rollback.sql` as files

**Done when:** applying the rollback restores the `before` snapshot exactly (diff is empty).

## Phase 3: Prove it

- [ ] `07_verify_after.sql`: apply the plan in the lab, take an `after` snapshot, re-run scoring
- [ ] Replay the usage log against the `after` grants: count events that would now be denied
- [ ] Before/after comparison: risk points, privileges granted, accounts per tier

**Done when:** zero events from active privileges would be denied, and risk drops measurably.

## Phase 4: Forensics

- [ ] `08_forensics.sql`: per-account timeline, activity after termination, source-IP changes, shared-account fingerprint
- [ ] Tamper evidence: hash chain over `audit.usage_log` (each row stores a hash of the previous row plus its own content), verification query, deliberate tamper test
- [ ] Make the log append-only (revoke UPDATE / DELETE on it)
- [ ] Case file export: one account's full evidence as CSV

**Done when:** editing or deleting one log row is detected by the verification query.

## Phase 5: Reporting

- [ ] `exports/` via `\copy` to CSV
- [ ] Excel workbook: pivots, conditional formatting, top-risk table
- [ ] Power BI pages: executive summary, role analysis, account drill-down, forensics timeline

**Done when:** the dashboard refreshes from the exports with no manual edits.

## Phase 6: Engineering quality

- [ ] `scripts/run_all.sh`: one command rebuilds everything
- [ ] Regression checks in SQL: assert each planted gap is detected, fail loudly if not
- [ ] GitHub Actions: Postgres service container runs the pipeline and the checks on every push
- [ ] Idempotency: running any script twice gives the same result

**Done when:** a clean clone builds and passes checks with one command, locally and in CI.

## Phase 7: Stretch

- Segregation of duties (same account can both create and approve or delete)
- Column-level sensitivity (`national_id`, `card_number`, `monthly_salary`) instead of table-level
- Off-hours and volume anomaly detection
- Grant drift between two snapshots
- Real log ingestion from `pgaudit` into `audit.usage_log`
