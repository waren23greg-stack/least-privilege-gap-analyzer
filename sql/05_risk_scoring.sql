-- 05_risk_scoring.sql
-- Scores every granted-but-unused privilege, then ranks accounts and roles.
--   risk_points = table sensitivity (1-5) x privilege weight x days unused
--   days unused: active = 0, stale = actual days since last use, never used = window_days
-- Account tier: CRITICAL if LEAVER_ACTIVE or SUPERUSER flag; HIGH if any other flag or
-- percentile >= 75; MEDIUM if percentile >= 50; otherwise LOW.
-- Percentile = share of accounts with a lower score (percent_rank).
-- A privilege held through a role AND directly is attributed to the role; privileges
-- granted only directly are grouped as '(direct grants only)'.
-- Weights and tier thresholds are judgment calls: edit them here and re-run.
-- Run: psql -U postgres -d privilege_audit -v snapshot=before -f sql/05_risk_scoring.sql

\set ON_ERROR_STOP on
\if :{?snapshot}
\else
  \set snapshot before
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.privilege_weights (
  privilege  text    PRIMARY KEY,
  weight     integer NOT NULL CHECK (weight > 0)
);

CREATE TABLE IF NOT EXISTS audit.privilege_risk (
  snapshot     text    NOT NULL,
  account      text    NOT NULL,
  table_name   text    NOT NULL,
  privilege    text    NOT NULL,
  granted_via  text[]  NOT NULL,
  status       text    NOT NULL,
  sensitivity  integer NOT NULL,
  weight       integer NOT NULL,
  days_unused  integer NOT NULL,
  risk_points  integer NOT NULL,
  PRIMARY KEY (snapshot, account, table_name, privilege)
);

CREATE TABLE IF NOT EXISTS audit.account_risk (
  snapshot            text    NOT NULL,
  account             text    NOT NULL,
  department          text,
  privileges_granted  integer NOT NULL,
  privileges_unused   integer NOT NULL,
  risk_points         integer NOT NULL,
  percentile          numeric(5,1) NOT NULL,
  flags               text,
  risk_tier           text    NOT NULL,
  PRIMARY KEY (snapshot, account)
);

CREATE TABLE IF NOT EXISTS audit.role_risk (
  snapshot       text    NOT NULL,
  source         text    NOT NULL,    -- role name, or '(direct grants only)'
  members        integer NOT NULL,
  granted_pairs  integer NOT NULL,
  risk_points    integer NOT NULL,
  share_pct      numeric(5,1) NOT NULL,
  PRIMARY KEY (snapshot, source)
);

DELETE FROM audit.privilege_weights;
INSERT INTO audit.privilege_weights (privilege, weight) VALUES
  ('SELECT', 1), ('INSERT', 3), ('UPDATE', 3), ('DELETE', 5);

DELETE FROM audit.role_risk      WHERE snapshot = :'snapshot';
DELETE FROM audit.account_risk   WHERE snapshot = :'snapshot';
DELETE FROM audit.privilege_risk WHERE snapshot = :'snapshot';

-- 1. Score each privilege
INSERT INTO audit.privilege_risk
  (snapshot, account, table_name, privilege, granted_via, status,
   sensitivity, weight, days_unused, risk_points)
SELECT :'snapshot'::text, p.account, p.table_name, p.privilege, p.granted_via, p.status,
       s.sensitivity, w.weight, d.days_unused,
       s.sensitivity * w.weight * d.days_unused
FROM audit.privilege_usage p
JOIN audit.table_sensitivity s ON s.table_name = p.table_name
JOIN audit.privilege_weights w ON w.privilege  = p.privilege
CROSS JOIN audit.analysis_config c
CROSS JOIN LATERAL (
  SELECT CASE p.status WHEN 'active' THEN 0
                       WHEN 'stale'  THEN p.days_since_use
                       ELSE c.window_days END AS days_unused
) d
WHERE p.snapshot = :'snapshot';

-- 2. Total per account, percentile and tier
INSERT INTO audit.account_risk
  (snapshot, account, department, privileges_granted, privileges_unused,
   risk_points, percentile, flags, risk_tier)
WITH base AS (
  SELECT a.account, e.department,
         count(r.privilege)                                      AS privileges_granted,
         count(r.privilege) FILTER (WHERE r.status <> 'active')  AS privileges_unused,
         COALESCE(sum(r.risk_points), 0)                         AS risk_points
  FROM audit.accounts a
  LEFT JOIN company.employees e ON e.username = a.account
  LEFT JOIN audit.privilege_risk r ON r.snapshot = a.snapshot AND r.account = a.account
  WHERE a.snapshot = :'snapshot'
  GROUP BY a.account, e.department
),
ranked AS (
  SELECT b.*,
         round((100 * percent_rank() OVER (ORDER BY b.risk_points))::numeric, 1) AS percentile,
         (SELECT string_agg(f.flag, ', ' ORDER BY f.flag)
          FROM audit.account_flags f
          WHERE f.snapshot = :'snapshot' AND f.account = b.account) AS flags
  FROM base b
)
SELECT :'snapshot'::text, account, department, privileges_granted, privileges_unused,
       risk_points, percentile, flags,
       CASE WHEN flags ~ '(LEAVER_ACTIVE|SUPERUSER)'      THEN 'CRITICAL'
            WHEN flags IS NOT NULL OR percentile >= 75    THEN 'HIGH'
            WHEN percentile >= 50                         THEN 'MEDIUM'
            ELSE 'LOW' END
FROM ranked;

-- 3. Total per role (and for direct-only grants)
INSERT INTO audit.role_risk
  (snapshot, source, members, granted_pairs, risk_points, share_pct)
WITH attributed AS (
  SELECT r.account, r.risk_points,
         CASE WHEN v.via = 'direct' THEN '(direct grants only)'
              ELSE substr(v.via, 6) END AS source
  FROM audit.privilege_risk r
  CROSS JOIN LATERAL unnest(r.granted_via) AS v(via)
  WHERE r.snapshot = :'snapshot'
    AND (v.via LIKE 'role:%' OR cardinality(array_remove(r.granted_via, 'direct')) = 0)
),
totals AS (
  SELECT sum(risk_points) AS total FROM audit.privilege_risk WHERE snapshot = :'snapshot'
)
SELECT :'snapshot'::text, a.source, count(DISTINCT a.account), count(*), sum(a.risk_points),
       COALESCE(round(100.0 * sum(a.risk_points) / NULLIF(t.total, 0), 1), 0)
FROM attributed a
CROSS JOIN totals t
GROUP BY a.source, t.total;

COMMIT;

-- ===================== Results =====================

\echo
\echo == 1. Ten riskiest accounts (:snapshot) ==
SELECT account, department, risk_points, percentile, risk_tier, flags
FROM audit.account_risk
WHERE snapshot = :'snapshot'
ORDER BY risk_points DESC, account
LIMIT 10;

\echo == 2. Accounts by risk tier ==
SELECT risk_tier, count(*) AS accounts, sum(risk_points) AS risk_points
FROM audit.account_risk
WHERE snapshot = :'snapshot'
GROUP BY risk_tier
ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW'], risk_tier);

\echo == 3. Risk by source: role or direct grant ==
SELECT source, members, granted_pairs, risk_points, share_pct
FROM audit.role_risk
WHERE snapshot = :'snapshot'
ORDER BY risk_points DESC, source;

\echo == 4. Risk by privilege type ==
SELECT privilege,
       count(*) FILTER (WHERE status <> 'active') AS unused_privileges,
       sum(risk_points)                            AS risk_points,
       round(100.0 * sum(risk_points) / NULLIF(sum(sum(risk_points)) OVER (), 0), 1) AS share_pct
FROM audit.privilege_risk
WHERE snapshot = :'snapshot'
GROUP BY privilege
ORDER BY risk_points DESC;
