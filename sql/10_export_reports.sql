-- 10_export_reports.sql
-- Flat, BI-friendly report views (audit.report_*) and CSV exports for Excel and Power BI.
-- Reads the audit results and writes exports/reports/*.csv; it changes no audit data.
--   summary.csv            one row per snapshot: privileges, utilization, risk points, tiers, flags
--   account_risk.csv       one row per account and snapshot
--   privilege_usage.csv    one row per effective privilege and snapshot
--   role_risk.csv          risk by role or direct grants, per snapshot
--   flags.csv              account-level flags with evidence, per snapshot
--   revoke_plan.csv        the remediation plan (AUTO and REVIEW actions)
--   events.csv             every logged event with HR context (for timelines)
--   forensic_accounts.csv  one summary row per account that appears in the log
-- Needs: the 'before' and 'after' snapshots (scripts 02, 04, 05 and the plan from 06 applied, see the
-- README), the plan (06) and the forensic views (08). Create the folder first: mkdir -p exports/reports
-- Run: psql -U postgres -d privilege_audit -f sql/10_export_reports.sql

\set ON_ERROR_STOP on

CREATE SCHEMA IF NOT EXISTS audit;

CREATE OR REPLACE VIEW audit.report_summary AS
WITH u AS (
  SELECT snapshot,
         count(*)                                     AS granted,
         count(*) FILTER (WHERE status = 'active')    AS active,
         count(*) FILTER (WHERE status <> 'active')   AS unused
  FROM audit.privilege_usage
  WHERE snapshot IN ('before', 'after')
  GROUP BY snapshot
), r AS (
  SELECT snapshot, sum(risk_points) AS risk_points
  FROM audit.privilege_risk
  WHERE snapshot IN ('before', 'after')
  GROUP BY snapshot
), a AS (
  SELECT snapshot,
         count(*)                                         AS accounts,
         count(*) FILTER (WHERE risk_tier = 'CRITICAL')   AS accounts_critical,
         count(*) FILTER (WHERE risk_tier = 'HIGH')       AS accounts_high,
         count(*) FILTER (WHERE risk_tier = 'MEDIUM')     AS accounts_medium,
         count(*) FILTER (WHERE risk_tier = 'LOW')        AS accounts_low
  FROM audit.account_risk
  WHERE snapshot IN ('before', 'after')
  GROUP BY snapshot
), f AS (
  SELECT snapshot, count(*) AS flags
  FROM audit.account_flags
  WHERE snapshot IN ('before', 'after')
  GROUP BY snapshot
)
SELECT u.snapshot,
       u.granted                                   AS privileges_granted,
       u.active                                    AS privileges_active,
       u.unused                                    AS privileges_unused,
       round(100.0 * u.active / u.granted, 1)      AS utilization_pct,
       r.risk_points,
       a.accounts, a.accounts_critical, a.accounts_high, a.accounts_medium, a.accounts_low,
       COALESCE(f.flags, 0)                        AS flags
FROM u
JOIN r USING (snapshot)
JOIN a USING (snapshot)
LEFT JOIN f USING (snapshot);

CREATE OR REPLACE VIEW audit.report_account_risk AS
SELECT snapshot, account, department, privileges_granted, privileges_unused,
       risk_points, percentile, COALESCE(flags, '') AS flags, risk_tier
FROM audit.account_risk
WHERE snapshot IN ('before', 'after');

CREATE OR REPLACE VIEW audit.report_privilege_usage AS
SELECT p.snapshot, p.account, p.table_name, p.privilege,
       array_to_string(p.granted_via, ';') AS granted_via,
       p.status, p.uses, p.last_used, p.days_since_use,
       s.sensitivity,
       COALESCE(r.risk_points, 0)          AS risk_points
FROM audit.privilege_usage p
JOIN audit.table_sensitivity s ON s.table_name = p.table_name
LEFT JOIN audit.privilege_risk r
  ON r.snapshot = p.snapshot AND r.account = p.account
 AND r.table_name = p.table_name AND r.privilege = p.privilege
WHERE p.snapshot IN ('before', 'after');

CREATE OR REPLACE VIEW audit.report_role_risk AS
SELECT snapshot, source, members, granted_pairs, risk_points, share_pct
FROM audit.role_risk
WHERE snapshot IN ('before', 'after');

CREATE OR REPLACE VIEW audit.report_flags AS
SELECT snapshot, account, flag, evidence
FROM audit.account_flags
WHERE snapshot IN ('before', 'after');

CREATE OR REPLACE VIEW audit.report_revoke_plan AS
SELECT snapshot, plan_id, decision, category, target, table_name, privilege,
       reason, risk_points, revoke_sql
FROM audit.revoke_plan
WHERE snapshot = 'before';

CREATE OR REPLACE VIEW audit.report_events AS
SELECT log_id, event_time, account, client_ip, table_name, action,
       sensitivity, department, context
FROM audit.forensic_events;

CREATE OR REPLACE VIEW audit.report_forensic_accounts AS
SELECT account, department, emp_status, termination_date, events, first_event, last_event,
       distinct_ips, events_after_termination, sensitive_events
FROM audit.forensic_accounts;

-- ===================== CSV exports =====================

\copy (SELECT * FROM audit.report_summary ORDER BY array_position(ARRAY['before','after'], snapshot)) TO 'exports/reports/summary.csv' CSV HEADER
\copy (SELECT * FROM audit.report_account_risk ORDER BY array_position(ARRAY['before','after'], snapshot), risk_points DESC, account) TO 'exports/reports/account_risk.csv' CSV HEADER
\copy (SELECT * FROM audit.report_privilege_usage ORDER BY array_position(ARRAY['before','after'], snapshot), account, table_name, privilege) TO 'exports/reports/privilege_usage.csv' CSV HEADER
\copy (SELECT * FROM audit.report_role_risk ORDER BY array_position(ARRAY['before','after'], snapshot), risk_points DESC, source) TO 'exports/reports/role_risk.csv' CSV HEADER
\copy (SELECT * FROM audit.report_flags ORDER BY array_position(ARRAY['before','after'], snapshot), flag, account) TO 'exports/reports/flags.csv' CSV HEADER
\copy (SELECT * FROM audit.report_revoke_plan ORDER BY plan_id) TO 'exports/reports/revoke_plan.csv' CSV HEADER
\copy (SELECT * FROM audit.report_events ORDER BY event_time, log_id) TO 'exports/reports/events.csv' CSV HEADER
\copy (SELECT * FROM audit.report_forensic_accounts ORDER BY account) TO 'exports/reports/forensic_accounts.csv' CSV HEADER

\echo
\echo == Rows per report ==
SELECT 'summary' AS report, count(*) AS n FROM audit.report_summary
UNION ALL SELECT 'account_risk',       count(*) FROM audit.report_account_risk
UNION ALL SELECT 'privilege_usage',    count(*) FROM audit.report_privilege_usage
UNION ALL SELECT 'role_risk',          count(*) FROM audit.report_role_risk
UNION ALL SELECT 'flags',              count(*) FROM audit.report_flags
UNION ALL SELECT 'revoke_plan',        count(*) FROM audit.report_revoke_plan
UNION ALL SELECT 'events',             count(*) FROM audit.report_events
UNION ALL SELECT 'forensic_accounts',  count(*) FROM audit.report_forensic_accounts;
