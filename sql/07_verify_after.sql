-- 07_verify_after.sql
-- Proves the remediation plan worked. Read-only: it only reads the audit snapshots.
-- Needs the 'before' and 'after' snapshots from scripts 02, 04 and 05. Section 6 also needs a
-- 'restored' snapshot (script 02 run again after the rollback file was applied).
--   1-4  before and after side by side: privileges, risk tiers, flags, risk by source
--   5    replay of the usage log against the after grants; recent use by current staff must
--        not be denied (leavers and use older than stale_days are expected to be denied)
--   6    rollback proof: the restored grants and accounts must equal the before snapshot
-- Run: psql -U postgres -d privilege_audit -f sql/07_verify_after.sql

\set ON_ERROR_STOP on

\echo
\echo == 1. Privileges and risk, before and after ==
SELECT p.snapshot,
       count(*)                                    AS granted,
       count(*) FILTER (WHERE p.status = 'active') AS active,
       count(*) FILTER (WHERE p.status <> 'active') AS unused,
       round(100.0 * count(*) FILTER (WHERE p.status = 'active') / count(*), 1) AS utilization_pct,
       (SELECT sum(r.risk_points) FROM audit.privilege_risk r
        WHERE r.snapshot = p.snapshot)             AS risk_points
FROM audit.privilege_usage p
WHERE p.snapshot IN ('before', 'after')
GROUP BY p.snapshot
ORDER BY array_position(ARRAY['before', 'after'], p.snapshot);

\echo == 2. Accounts by risk tier ==
SELECT risk_tier,
       count(*) FILTER (WHERE snapshot = 'before') AS n_before,
       count(*) FILTER (WHERE snapshot = 'after')  AS n_after
FROM audit.account_risk
WHERE snapshot IN ('before', 'after')
GROUP BY risk_tier
ORDER BY array_position(ARRAY['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], risk_tier);

\echo == 3. Account flags ==
SELECT flag,
       count(*) FILTER (WHERE snapshot = 'before') AS n_before,
       count(*) FILTER (WHERE snapshot = 'after')  AS n_after
FROM audit.account_flags
WHERE snapshot IN ('before', 'after')
GROUP BY flag
ORDER BY flag;

\echo == 4. Risk points by source ==
SELECT source,
       COALESCE(sum(risk_points) FILTER (WHERE snapshot = 'before'), 0) AS points_before,
       COALESCE(sum(risk_points) FILTER (WHERE snapshot = 'after'), 0)  AS points_after
FROM audit.role_risk
WHERE snapshot IN ('before', 'after')
GROUP BY source
ORDER BY points_before DESC, source;

-- Every logged event, marked denied when the after grants no longer allow it
CREATE TEMP VIEW _replay AS
SELECT u.account,
       u.event_time::date                          AS day,
       (g.account IS NULL)                         AS denied,
       COALESCE(e.status = 'terminated', false)    AS leaver
FROM audit.usage_log u
LEFT JOIN (SELECT DISTINCT account, table_name, privilege
           FROM audit.granted_privileges
           WHERE snapshot = 'after') g
  ON g.account = u.account AND g.table_name = u.table_name AND g.privilege = u.action
LEFT JOIN company.employees e ON e.username = u.account;

\echo == 5a. Accounts with denied events when the log is replayed against the after grants ==
SELECT r.account,
       count(*)                                  AS events,
       count(*) FILTER (WHERE r.denied)          AS denied,
       max(r.day) FILTER (WHERE r.denied)        AS latest_denied,
       CASE WHEN bool_or(r.leaver) THEN 'leaver: expected'
            WHEN max(r.day) FILTER (WHERE r.denied) <= c.as_of - c.stale_days
                 THEN 'older than the active window: expected'
            ELSE 'BREAKS ACTIVE USE' END         AS verdict
FROM _replay r
CROSS JOIN audit.analysis_config c
GROUP BY r.account, c.as_of, c.stale_days
HAVING count(*) FILTER (WHERE r.denied) > 0
ORDER BY denied DESC, r.account;

\echo == 5b. Active-use check: events by current staff in the last stale_days ==
SELECT CASE WHEN count(*) FILTER (WHERE r.denied) = 0 THEN 'PASS' ELSE 'FAIL' END AS result,
       count(*)                         AS events_checked,
       count(*) FILTER (WHERE r.denied) AS denied
FROM _replay r
CROSS JOIN audit.analysis_config c
WHERE NOT r.leaver
  AND r.day > c.as_of - c.stale_days;

\echo == 6. Rollback proof ==
SELECT EXISTS (SELECT 1 FROM audit.accounts WHERE snapshot = 'restored') AS has_restored
\gset
\if :has_restored
  SELECT (SELECT count(*) FROM audit.granted_privileges WHERE snapshot = 'restored') AS restored_rows,
         (SELECT count(*) FROM (
            (SELECT account, table_name, privilege, granted_via
             FROM audit.granted_privileges WHERE snapshot = 'before'
             EXCEPT
             SELECT account, table_name, privilege, granted_via
             FROM audit.granted_privileges WHERE snapshot = 'restored')
            UNION ALL
            (SELECT account, table_name, privilege, granted_via
             FROM audit.granted_privileges WHERE snapshot = 'restored'
             EXCEPT
             SELECT account, table_name, privilege, granted_via
             FROM audit.granted_privileges WHERE snapshot = 'before')) d) AS grant_differences,
         (SELECT count(*) FROM (
            (SELECT account, can_login, is_superuser, can_createrole, member_of
             FROM audit.accounts WHERE snapshot = 'before'
             EXCEPT
             SELECT account, can_login, is_superuser, can_createrole, member_of
             FROM audit.accounts WHERE snapshot = 'restored')
            UNION ALL
            (SELECT account, can_login, is_superuser, can_createrole, member_of
             FROM audit.accounts WHERE snapshot = 'restored'
             EXCEPT
             SELECT account, can_login, is_superuser, can_createrole, member_of
             FROM audit.accounts WHERE snapshot = 'before')) d) AS account_differences;
\else
  \echo Not run yet: apply the rollback file, then run script 02 with snapshot=restored
\endif
