-- 04_gap_queries.sql
-- Compares what is GRANTED (audit.granted_privileges) with what is USED (audit.usage_log).
-- Stores two result tables that later scripts and Power BI read:
--   audit.privilege_usage : one row per effective privilege, with a status
--       active     = used within the last stale_days (90)
--       stale      = last used more than stale_days ago
--       never_used = not seen anywhere in the log window (180 days)
--   audit.account_flags   : account-level problems (leaver, dormant, shared, superuser, ...)
-- Use by an employee after their termination date is not counted as legitimate use.
-- Then prints six findings. Re-running a snapshot label replaces that label's rows.
-- Run: psql -U postgres -d privilege_audit -v snapshot=before -f sql/04_gap_queries.sql

\set ON_ERROR_STOP on
\if :{?snapshot}
\else
  \set snapshot before
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS audit;

-- Sensitivity of each table, 1 (low) to 5 (critical). Edit to match your own data.
CREATE TABLE IF NOT EXISTS audit.table_sensitivity (
  table_name         text    PRIMARY KEY,
  sensitivity        integer NOT NULL CHECK (sensitivity BETWEEN 1 AND 5),
  sensitive_columns  text
);

CREATE TABLE IF NOT EXISTS audit.privilege_usage (
  snapshot        text    NOT NULL,
  account         text    NOT NULL,
  table_name      text    NOT NULL,
  privilege       text    NOT NULL,
  granted_via     text[]  NOT NULL,
  uses            integer NOT NULL,
  last_used       date,
  days_since_use  integer,
  status          text    NOT NULL CHECK (status IN ('active','stale','never_used')),
  PRIMARY KEY (snapshot, account, table_name, privilege)
);

CREATE TABLE IF NOT EXISTS audit.account_flags (
  snapshot  text NOT NULL,
  account   text NOT NULL,
  flag      text NOT NULL,
  evidence  text NOT NULL,
  PRIMARY KEY (snapshot, account, flag)
);

DELETE FROM audit.table_sensitivity;
INSERT INTO audit.table_sensitivity (table_name, sensitivity, sensitive_columns) VALUES
  ('salaries',  5, 'monthly_salary'),
  ('payments',  5, 'card_number'),
  ('employees', 4, 'national_id'),
  ('customers', 4, 'national_id'),
  ('orders',    2, NULL);

-- Granted vs used, one row per effective privilege
DELETE FROM audit.privilege_usage WHERE snapshot = :'snapshot';

WITH granted AS (
  SELECT account, table_name, privilege,
         array_agg(granted_via ORDER BY granted_via) AS granted_via
  FROM audit.granted_privileges
  WHERE snapshot = :'snapshot'
  GROUP BY account, table_name, privilege
),
legit AS (   -- events after an employee's termination date are excluded
  SELECT u.account, u.table_name, u.action AS privilege,
         count(*) AS uses, max(u.event_time)::date AS last_used
  FROM audit.usage_log u
  LEFT JOIN company.employees e ON e.username = u.account
  WHERE e.termination_date IS NULL OR u.event_time::date <= e.termination_date
  GROUP BY u.account, u.table_name, u.action
)
INSERT INTO audit.privilege_usage
  (snapshot, account, table_name, privilege, granted_via, uses, last_used, days_since_use, status)
SELECT :'snapshot'::text, g.account, g.table_name, g.privilege, g.granted_via,
       COALESCE(l.uses, 0), l.last_used, c.as_of - l.last_used,
       CASE WHEN l.last_used IS NULL                  THEN 'never_used'
            WHEN c.as_of - l.last_used > c.stale_days THEN 'stale'
            ELSE 'active' END
FROM granted g
CROSS JOIN audit.analysis_config c
LEFT JOIN legit l
  ON l.account = g.account AND l.table_name = g.table_name AND l.privilege = g.privilege;

-- Account-level flags
DELETE FROM audit.account_flags WHERE snapshot = :'snapshot';

CREATE TEMP TABLE _acct ON COMMIT DROP AS
SELECT a.account, a.can_login, a.is_superuser, a.can_createrole, a.member_of,
       e.department, e.status AS emp_status, e.termination_date
FROM audit.accounts a
LEFT JOIN company.employees e ON e.username = a.account
WHERE a.snapshot = :'snapshot';

INSERT INTO audit.account_flags (snapshot, account, flag, evidence)
-- Leaver: terminated employee whose login still works
SELECT :'snapshot'::text, a.account, 'LEAVER_ACTIVE'::text,
       'Terminated ' || a.termination_date || ', login still enabled; '
       || (SELECT count(*) FROM audit.usage_log u
           WHERE u.account = a.account AND u.event_time::date > a.termination_date)
       || ' events after termination'
FROM _acct a
WHERE a.emp_status = 'terminated' AND a.can_login
UNION ALL
-- Dormant: login account with no activity at all in the last stale_days
SELECT :'snapshot'::text, a.account, 'DORMANT'::text,
       'No activity in the last ' || c.stale_days || ' days'
FROM _acct a
CROSS JOIN audit.analysis_config c
WHERE a.can_login
  AND NOT EXISTS (SELECT 1 FROM audit.usage_log u
                  WHERE u.account = a.account AND u.event_time::date > c.as_of - c.stale_days)
UNION ALL
-- Shared account: no HR owner, or used from 3+ different IPs
SELECT :'snapshot'::text, a.account, 'SHARED_ACCOUNT'::text,
       CASE WHEN a.department IS NULL THEN 'No HR owner; ' ELSE '' END
       || COALESCE(n.ips, 0) || ' distinct source IPs'
FROM _acct a
LEFT JOIN (SELECT account, count(DISTINCT client_ip) AS ips
           FROM audit.usage_log GROUP BY account) n ON n.account = a.account
WHERE a.department IS NULL OR n.ips >= 3
UNION ALL
SELECT :'snapshot'::text, a.account, 'SUPERUSER'::text,
       'SUPERUSER attribute; department: ' || COALESCE(a.department, 'none')
FROM _acct a
WHERE a.is_superuser
UNION ALL
SELECT :'snapshot'::text, a.account, 'CREATEROLE'::text,
       'CREATEROLE attribute; department: ' || COALESCE(a.department, 'none')
FROM _acct a
WHERE a.can_createrole
UNION ALL
-- Mover: member of a department role that does not match their HR department
SELECT :'snapshot'::text, a.account, 'ROLE_MISMATCH'::text,
       'Department ' || a.department || ' but member of '
       || string_agg(r.role_name, ', ' ORDER BY r.role_name)
FROM _acct a
CROSS JOIN LATERAL unnest(a.member_of) AS r(role_name)
WHERE a.department IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM (VALUES ('Analytics','role_analyst'), ('Sales','role_sales'), ('Finance','role_finance'),
                 ('HR','role_hr'), ('Support','role_support')) AS d(department, role_name)
    WHERE d.department = a.department AND d.role_name = r.role_name)
GROUP BY a.account, a.department;

COMMIT;

-- ===================== Findings =====================

\echo
\echo == 1. Privilege Utilization Rate (:snapshot) ==
SELECT count(*)                                       AS granted,
       count(*) FILTER (WHERE status = 'active')      AS active,
       count(*) FILTER (WHERE status = 'stale')       AS stale,
       count(*) FILTER (WHERE status = 'never_used')  AS never_used,
       round(100.0 * count(*) FILTER (WHERE status = 'active') / count(*), 1) AS utilization_pct
FROM audit.privilege_usage
WHERE snapshot = :'snapshot';

\echo == 2. Unused privileges by type ==
SELECT privilege,
       count(*)                                    AS granted,
       count(*) FILTER (WHERE status = 'active')   AS active,
       count(*) FILTER (WHERE status <> 'active')  AS unused,
       round(100.0 * count(*) FILTER (WHERE status <> 'active') / count(*), 1) AS pct_unused
FROM audit.privilege_usage
WHERE snapshot = :'snapshot'
GROUP BY privilege
ORDER BY array_position(ARRAY['SELECT','INSERT','UPDATE','DELETE'], privilege);

\echo == 3. Account flags (leaver, dormant, shared, superuser, mover) ==
SELECT account, flag, evidence
FROM audit.account_flags
WHERE snapshot = :'snapshot'
ORDER BY flag, account;

\echo == 4. Accounts that hold write privileges but only ever read ==
SELECT account,
       count(*) FILTER (WHERE privilege <> 'SELECT')                AS write_privileges_granted,
       COALESCE(sum(uses) FILTER (WHERE privilege = 'SELECT'), 0)   AS select_events,
       COALESCE(sum(uses) FILTER (WHERE privilege <> 'SELECT'), 0)  AS write_events
FROM audit.privilege_usage
WHERE snapshot = :'snapshot'
GROUP BY account
HAVING count(*) FILTER (WHERE privilege <> 'SELECT') > 0
   AND COALESCE(sum(uses) FILTER (WHERE privilege <> 'SELECT'), 0) = 0
   AND COALESCE(sum(uses) FILTER (WHERE privilege = 'SELECT'), 0) > 0
ORDER BY write_privileges_granted DESC, account;

\echo == 5. Exposure on sensitive tables ==
SELECT s.table_name, s.sensitivity,
       count(*)                                    AS granted,
       count(*) FILTER (WHERE p.status = 'active') AS active,
       count(*) FILTER (WHERE p.status <> 'active') AS unused,
       round(100.0 * count(*) FILTER (WHERE p.status <> 'active') / count(*), 1) AS pct_unused
FROM audit.privilege_usage p
JOIN audit.table_sensitivity s ON s.table_name = p.table_name
WHERE p.snapshot = :'snapshot'
GROUP BY s.table_name, s.sensitivity
ORDER BY s.sensitivity DESC, pct_unused DESC;

\echo == 6. Role bloat (bloated = members use under 30 percent of granted rights) ==
WITH role_pairs AS (
  SELECT substr(v.via, 6) AS role_name, p.account, p.table_name, p.privilege, p.status
  FROM audit.privilege_usage p
  CROSS JOIN LATERAL unnest(p.granted_via) AS v(via)
  WHERE p.snapshot = :'snapshot' AND v.via LIKE 'role:%'
)
SELECT role_name,
       count(DISTINCT account)                   AS members,
       count(DISTINCT (table_name, privilege))   AS role_privileges,
       count(*)                                  AS granted_pairs,
       count(*) FILTER (WHERE status = 'active') AS active_pairs,
       round(100.0 * count(*) FILTER (WHERE status = 'active') / count(*), 1) AS utilization_pct,
       (100.0 * count(*) FILTER (WHERE status = 'active') / count(*)) < 30   AS bloated
FROM role_pairs
GROUP BY role_name
ORDER BY utilization_pct, role_name;
