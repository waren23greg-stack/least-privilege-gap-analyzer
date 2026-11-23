-- 06_generate_revokes.sql
-- Turns the findings of scripts 04 and 05 into a remediation plan (audit.revoke_plan).
-- Every action carries its own rollback statement. Nothing is applied here.
--   decision AUTO   = the evidence shows the access is unused; safe to apply after a read-through
--   decision REVIEW = needs a human: the log cannot prove it is unneeded, or active users are affected
-- Rules:
--   1. Direct grant not in active use               -> REVOKE from the account (AUTO)
--   2. Role privilege that no member uses           -> REVOKE from the role (AUTO)
--   3. Role privilege that only some members use    -> listed without SQL (REVIEW); it cannot be
--                                                      revoked for some members only
--   4. Leaver with a working login                  -> NOLOGIN and removal from roles (AUTO)
--   5. Mover still in a role of the old department  -> remove from that role (AUTO if no active
--                                                      privilege depends on it, otherwise REVIEW)
--   6. SUPERUSER / CREATEROLE, dormant and shared accounts -> REVIEW
-- risk_points = points of the privileges removed (a privilege held through several routes can be
-- counted more than once). Account-level actions carry 0.
-- Writes exports/revoke_<snapshot>.sql and exports/rollback_<snapshot>.sql: create the exports
-- folder first (mkdir -p exports).
-- Run after 05: psql -U postgres -d privilege_audit -v snapshot=before -f sql/06_generate_revokes.sql

\set ON_ERROR_STOP on
\if :{?snapshot}
\else
  \set snapshot before
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.revoke_plan (
  plan_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  snapshot      text    NOT NULL,
  category      text    NOT NULL,   -- DIRECT_GRANT, ROLE_GRANT, MEMBERSHIP, LOGIN, ATTRIBUTE, MANUAL
  decision      text    NOT NULL CHECK (decision IN ('AUTO','REVIEW')),
  target        text    NOT NULL,   -- the account or role the action applies to
  table_name    text,
  privilege     text,
  reason        text    NOT NULL,
  risk_points   integer NOT NULL DEFAULT 0,
  revoke_sql    text,               -- NULL when no safe automatic statement exists
  rollback_sql  text
);

DELETE FROM audit.revoke_plan WHERE snapshot = :'snapshot';

-- Rule 1: direct grants that are not in active use
INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, 'DIRECT_GRANT', 'AUTO', p.account, p.table_name, p.privilege,
       CASE p.status WHEN 'never_used' THEN 'Direct grant, never used in the log window'
                     ELSE 'Direct grant, last used ' || p.days_since_use || ' days ago' END,
       COALESCE(r.risk_points, 0),
       format('REVOKE %s ON company.%I FROM %I;', p.privilege, p.table_name, p.account),
       format('GRANT %s ON company.%I TO %I;',    p.privilege, p.table_name, p.account)
FROM audit.privilege_usage p
LEFT JOIN audit.privilege_risk r
  ON r.snapshot = p.snapshot AND r.account = p.account
 AND r.table_name = p.table_name AND r.privilege = p.privilege
WHERE p.snapshot = :'snapshot'
  AND 'direct' = ANY (p.granted_via)
  AND p.status <> 'active'
  AND p.privilege IN ('SELECT','INSERT','UPDATE','DELETE');

-- Rules 2 and 3: role privileges, judged across all members of the role
CREATE TEMP TABLE _role_priv ON COMMIT DROP AS
SELECT substr(v.via, 6)                            AS role_name,
       p.table_name, p.privilege,
       count(*)                                    AS members,
       count(*) FILTER (WHERE p.status = 'active') AS used_by,
       COALESCE(sum(r.risk_points), 0)::integer    AS risk_points
FROM audit.privilege_usage p
CROSS JOIN LATERAL unnest(p.granted_via) AS v(via)
LEFT JOIN audit.privilege_risk r
  ON r.snapshot = p.snapshot AND r.account = p.account
 AND r.table_name = p.table_name AND r.privilege = p.privilege
WHERE p.snapshot = :'snapshot'
  AND v.via LIKE 'role:%'
  AND p.privilege IN ('SELECT','INSERT','UPDATE','DELETE')
GROUP BY substr(v.via, 6), p.table_name, p.privilege;

INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, 'ROLE_GRANT', 'AUTO', role_name, table_name, privilege,
       'No member of the role uses it (' || members || ' members)',
       risk_points,
       format('REVOKE %s ON company.%I FROM %I;', privilege, table_name, role_name),
       format('GRANT %s ON company.%I TO %I;',    privilege, table_name, role_name)
FROM _role_priv
WHERE used_by = 0;

INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, 'ROLE_GRANT', 'REVIEW', role_name, table_name, privilege,
       'Used by ' || used_by || ' of ' || members
         || ' members; cannot be revoked for the others without splitting the role',
       risk_points, NULL::text, NULL::text
FROM _role_priv
WHERE used_by > 0 AND used_by < members;

-- Rule 4: leavers lose their login and their role memberships
INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, 'LOGIN', 'AUTO', f.account, NULL::text, NULL::text,
       'Leaver: ' || f.evidence, 0,
       format('ALTER ROLE %I NOLOGIN;', f.account),
       format('ALTER ROLE %I LOGIN;',   f.account)
FROM audit.account_flags f
WHERE f.snapshot = :'snapshot' AND f.flag = 'LEAVER_ACTIVE';

INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, 'MEMBERSHIP', 'AUTO', a.account, NULL::text, NULL::text,
       'Leaver: remove from ' || r.role_name, 0,
       format('REVOKE %I FROM %I;', r.role_name, a.account),
       format('GRANT %I TO %I;',    r.role_name, a.account)
FROM audit.account_flags f
JOIN audit.accounts a ON a.snapshot = f.snapshot AND a.account = f.account
CROSS JOIN LATERAL unnest(a.member_of) AS r(role_name)
WHERE f.snapshot = :'snapshot' AND f.flag = 'LEAVER_ACTIVE';

-- Rule 5: movers still in a role of their old department
INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
WITH dept_role (department, role_name) AS (VALUES      -- same mapping as script 04
  ('Analytics','role_analyst'), ('Sales','role_sales'), ('Finance','role_finance'),
  ('HR','role_hr'), ('Support','role_support')),
mismatch AS (
  SELECT a.account, e.department, r.role_name
  FROM audit.account_flags f
  JOIN audit.accounts a ON a.snapshot = f.snapshot AND a.account = f.account
  JOIN company.employees e ON e.username = a.account
  CROSS JOIN LATERAL unnest(a.member_of) AS r(role_name)
  WHERE f.snapshot = :'snapshot' AND f.flag = 'ROLE_MISMATCH'
    AND NOT EXISTS (SELECT 1 FROM dept_role d
                    WHERE d.department = e.department AND d.role_name = r.role_name)
),
checked AS (   -- active privileges that exist only through the old role would be lost
  SELECT m.account, m.department, m.role_name,
         count(p.privilege) FILTER (
           WHERE p.status = 'active'
             AND cardinality(array_remove(p.granted_via, 'role:' || m.role_name)) = 0) AS would_break
  FROM mismatch m
  LEFT JOIN audit.privilege_usage p
    ON p.snapshot = :'snapshot' AND p.account = m.account
   AND ('role:' || m.role_name) = ANY (p.granted_via)
  GROUP BY m.account, m.department, m.role_name
)
SELECT :'snapshot'::text, 'MEMBERSHIP',
       CASE WHEN would_break = 0 THEN 'AUTO' ELSE 'REVIEW' END,
       account, NULL::text, NULL::text,
       CASE WHEN would_break = 0
            THEN 'HR department is ' || department || '; no active privilege depends on ' || role_name
            ELSE 'HR department is ' || department || '; ' || would_break
                 || ' active privileges depend on ' || role_name END,
       0,
       format('REVOKE %I FROM %I;', role_name, account),
       format('GRANT %I TO %I;',    role_name, account)
FROM checked;

-- Rule 6: attribute and account problems that need a human decision
INSERT INTO audit.revoke_plan
  (snapshot, category, decision, target, table_name, privilege, reason, risk_points,
   revoke_sql, rollback_sql)
SELECT :'snapshot'::text, m.category, 'REVIEW', f.account, NULL::text, NULL::text,
       m.why || ' (' || f.evidence || ')', 0,
       format(m.revoke_fmt, f.account), format(m.rollback_fmt, f.account)
FROM audit.account_flags f
JOIN (VALUES
  ('SUPERUSER',      'ATTRIBUTE', 'Superuser on a non-admin account; the table log cannot show its use',
                     'ALTER ROLE %I NOSUPERUSER;',  'ALTER ROLE %I SUPERUSER;'),
  ('CREATEROLE',     'ATTRIBUTE', 'CREATEROLE on a non-admin account; the table log cannot show its use',
                     'ALTER ROLE %I NOCREATEROLE;', 'ALTER ROLE %I CREATEROLE;'),
  ('DORMANT',        'LOGIN',     'Dormant account; confirm with HR before disabling',
                     'ALTER ROLE %I NOLOGIN;',      'ALTER ROLE %I LOGIN;'),
  ('SHARED_ACCOUNT', 'MANUAL',    'Shared login; replace with named accounts',
                     NULL,                          NULL)
) AS m(flag, category, why, revoke_fmt, rollback_fmt) ON m.flag = f.flag
WHERE f.snapshot = :'snapshot';

COMMIT;

-- ===================== Findings =====================

\echo
\echo == 1. Remediation plan (:snapshot) ==
SELECT decision, category, count(*) AS actions, sum(risk_points) AS risk_points
FROM audit.revoke_plan
WHERE snapshot = :'snapshot'
GROUP BY decision, category
ORDER BY decision, category;

\echo == 2. Ten largest automatic actions by risk points ==
SELECT category, target, table_name, privilege, risk_points
FROM audit.revoke_plan
WHERE snapshot = :'snapshot' AND decision = 'AUTO'
ORDER BY risk_points DESC, plan_id
LIMIT 10;

\echo == 3. Needs a human decision: accounts and attributes ==
SELECT category, target, reason
FROM audit.revoke_plan
WHERE snapshot = :'snapshot' AND decision = 'REVIEW' AND category <> 'ROLE_GRANT'
ORDER BY category, target;

-- ===================== Export =====================

SELECT 'exports/revoke_'   || :'snapshot' || '.sql' AS revoke_file,
       'exports/rollback_' || :'snapshot' || '.sql' AS rollback_file
\gset

\pset tuples_only on
\pset format unaligned

\o :revoke_file
SELECT line FROM (
  SELECT 0 AS ord, 0::bigint AS pid,
         '-- REVOKE plan for snapshot ' || :'snapshot' || ' (AUTO actions only). Review before running.' AS line
  UNION ALL SELECT 1, 0, 'BEGIN;'
  UNION ALL SELECT 2, plan_id, revoke_sql
            FROM audit.revoke_plan
            WHERE snapshot = :'snapshot' AND decision = 'AUTO'
  UNION ALL SELECT 3, 0, 'COMMIT;'
) x
ORDER BY ord, pid;
\o

\o :rollback_file
SELECT line FROM (
  SELECT 0 AS ord, 0::bigint AS pid,
         '-- ROLLBACK for the REVOKE plan of snapshot ' || :'snapshot' || ' (reverse order).' AS line
  UNION ALL SELECT 1, 0, 'BEGIN;'
  UNION ALL SELECT 2, -plan_id, rollback_sql
            FROM audit.revoke_plan
            WHERE snapshot = :'snapshot' AND decision = 'AUTO'
  UNION ALL SELECT 3, 0, 'COMMIT;'
) x
ORDER BY ord, pid;
\o

\pset tuples_only off
\pset format aligned

\echo
\echo Wrote :revoke_file and :rollback_file
