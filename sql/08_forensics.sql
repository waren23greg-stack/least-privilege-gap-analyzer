-- 08_forensics.sql
-- Forensic views over the usage log, two cross-account findings, and a case file for one account.
-- Read-only on the evidence: it creates views and writes a CSV, nothing else.
--   audit.forensic_events    : every logged event with HR context (normal / after termination / no HR owner)
--   audit.forensic_ip_usage  : which source IPs each account used, and when
--   audit.forensic_accounts  : one summary row per account that appears in the log
-- The views are also meant for Power BI. Run after 03 and 04 (and 05 for the tier in the case file).
-- Case file account: -v account=<name> (default peter_x). Also writes exports/case_<account>.csv
-- (create the exports folder first). Accounts with no log activity, such as a dormant one, have no
-- trail, so their case file is empty.
-- Evidence is only as trustworthy as the log itself; script 09 will seal it with a hash chain.
-- Run: psql -U postgres -d privilege_audit -v account=peter_x -f sql/08_forensics.sql

\set ON_ERROR_STOP on
\if :{?account}
\else
  \set account peter_x
\endif

CREATE SCHEMA IF NOT EXISTS audit;

CREATE OR REPLACE VIEW audit.forensic_events AS
SELECT u.log_id, u.event_time, u.account, u.client_ip, u.table_name, u.action,
       s.sensitivity,
       e.department, e.status AS emp_status, e.termination_date,
       CASE WHEN e.username IS NULL THEN 'no HR owner'
            WHEN e.termination_date IS NOT NULL
                 AND u.event_time::date > e.termination_date THEN 'after termination'
            ELSE 'normal' END AS context
FROM audit.usage_log u
LEFT JOIN company.employees e ON e.username = u.account
LEFT JOIN audit.table_sensitivity s ON s.table_name = u.table_name;

CREATE OR REPLACE VIEW audit.forensic_ip_usage AS
SELECT account, client_ip,
       count(*)          AS events,
       min(event_time)   AS first_seen,
       max(event_time)   AS last_seen
FROM audit.usage_log
GROUP BY account, client_ip;

CREATE OR REPLACE VIEW audit.forensic_accounts AS
SELECT account, department, emp_status, termination_date,
       count(*)                                       AS events,
       min(event_time)::date                          AS first_event,
       max(event_time)::date                          AS last_event,
       count(DISTINCT client_ip)                      AS distinct_ips,
       count(*) FILTER (WHERE context = 'after termination') AS events_after_termination,
       count(*) FILTER (WHERE sensitivity >= 4)       AS sensitive_events
FROM audit.forensic_events
GROUP BY account, department, emp_status, termination_date;

-- ===================== Cross-account findings =====================

\echo
\echo == 1. Activity after termination ==
SELECT account, termination_date,
       count(*)                                          AS events,
       min(event_time)::date                             AS first_event,
       max(event_time)::date                             AS last_event,
       string_agg(DISTINCT table_name || ' ' || action, ', ') AS used,
       max(sensitivity)                                  AS max_sensitivity
FROM audit.forensic_events
WHERE context = 'after termination'
GROUP BY account, termination_date
ORDER BY events DESC, account;

\echo == 2. Accounts used from more than one source IP ==
SELECT account, client_ip, events,
       first_seen::date AS first_seen, last_seen::date AS last_seen
FROM audit.forensic_ip_usage
WHERE account IN (SELECT account FROM audit.forensic_ip_usage
                  GROUP BY account HAVING count(*) > 1)
ORDER BY account, client_ip;

-- ===================== Case file =====================

\echo == 3a. Case file: profile of :account ==
SELECT a.account, a.department, a.emp_status, a.termination_date,
       a.events, a.first_event, a.last_event, a.distinct_ips,
       a.events_after_termination, a.sensitive_events,
       r.risk_tier, r.flags
FROM audit.forensic_accounts a
LEFT JOIN audit.account_risk r ON r.snapshot = 'before' AND r.account = a.account
WHERE a.account = :'account';

\echo == 3b. Activity by month ==
SELECT to_char(date_trunc('month', event_time), 'YYYY-MM')          AS month,
       count(*)                                                     AS events,
       count(*) FILTER (WHERE context = 'after termination')        AS after_termination
FROM audit.forensic_events
WHERE account = :'account'
GROUP BY 1
ORDER BY 1;

\echo == 3c. What the account actually did ==
SELECT table_name, action, count(*) AS events,
       min(event_time)::date AS first_used, max(event_time)::date AS last_used
FROM audit.forensic_events
WHERE account = :'account'
GROUP BY table_name, action
ORDER BY last_used DESC, table_name, action;

\echo == 3d. Ten most recent events ==
SELECT log_id, event_time, client_ip, table_name, action, context
FROM audit.forensic_events
WHERE account = :'account'
ORDER BY event_time DESC, log_id DESC
LIMIT 10;

-- Full case file as CSV
SELECT 'exports/case_' || :'account' || '.csv' AS case_file
\gset

\pset format csv
\o :case_file
SELECT log_id, event_time, account, client_ip, table_name, action, context
FROM audit.forensic_events
WHERE account = :'account'
ORDER BY event_time, log_id;
\o
\pset format aligned

\echo
\echo Wrote :case_file
