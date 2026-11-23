-- 02_collect_granted.sql
-- Snapshots what each login account is GRANTED: attributes, role memberships and
-- table privileges (direct and inherited through roles) on the company schema.
-- Each run is stored under a snapshot label, so the same script measures 'before'
-- and 'after' remediation. Re-running a label replaces that label's rows.
-- Assumes roles are not nested (true for this lab).
-- Run: psql -U postgres -d privilege_audit -v snapshot=before -f sql/02_collect_granted.sql

\set ON_ERROR_STOP on
\if :{?snapshot}
\else
  \set snapshot before
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.accounts (
  snapshot        text        NOT NULL,
  account         text        NOT NULL,
  can_login       boolean     NOT NULL,
  is_superuser    boolean     NOT NULL,
  can_createrole  boolean     NOT NULL,
  member_of       text[]      NOT NULL,
  collected_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (snapshot, account)
);

CREATE TABLE IF NOT EXISTS audit.granted_privileges (
  snapshot     text NOT NULL,
  account      text NOT NULL,
  table_name   text NOT NULL,
  privilege    text NOT NULL,
  granted_via  text NOT NULL,        -- 'direct' or 'role:<role name>'
  PRIMARY KEY (snapshot, account, table_name, privilege, granted_via)
);

-- Replace any earlier rows for this snapshot label
DELETE FROM audit.granted_privileges WHERE snapshot = :'snapshot';
DELETE FROM audit.accounts           WHERE snapshot = :'snapshot';

-- Login accounts and their attributes
INSERT INTO audit.accounts (snapshot, account, can_login, is_superuser, can_createrole, member_of)
SELECT :'snapshot'::text, r.rolname::text, r.rolcanlogin, r.rolsuper, r.rolcreaterole,
       COALESCE(
         (SELECT array_agg(DISTINCT g.rolname::text ORDER BY g.rolname::text)
          FROM pg_auth_members m
          JOIN pg_roles g ON g.oid = m.roleid
          WHERE m.member = r.oid),
         '{}')
FROM pg_roles r
WHERE r.rolcanlogin AND r.rolname <> 'postgres' AND r.rolname !~ '^pg_';

-- Table privileges: direct grants, plus grants inherited through role membership
INSERT INTO audit.granted_privileges (snapshot, account, table_name, privilege, granted_via)
SELECT :'snapshot'::text, a.account, p.table_name::text, p.privilege_type::text, 'direct'::text
FROM audit.accounts a
JOIN information_schema.table_privileges p
  ON p.grantee::text = a.account AND p.table_schema = 'company'
WHERE a.snapshot = :'snapshot'
UNION
SELECT :'snapshot'::text, a.account, p.table_name::text, p.privilege_type::text, 'role:' || r.role_name
FROM audit.accounts a
CROSS JOIN LATERAL unnest(a.member_of) AS r(role_name)
JOIN information_schema.table_privileges p
  ON p.grantee::text = r.role_name AND p.table_schema = 'company'
WHERE a.snapshot = :'snapshot';

COMMIT;

-- Verification
SELECT count(*)                                         AS grant_rows,
       count(DISTINCT (account, table_name, privilege)) AS distinct_effective_privileges,
       count(DISTINCT account)                          AS accounts_with_grants,
       count(*) FILTER (WHERE granted_via = 'direct')   AS direct_rows
FROM audit.granted_privileges
WHERE snapshot = :'snapshot';

SELECT account, is_superuser, can_createrole, member_of
FROM audit.accounts
WHERE snapshot = :'snapshot'
  AND (is_superuser OR can_createrole OR cardinality(member_of) > 1)
ORDER BY account;

SELECT account,
       count(DISTINCT (table_name, privilege))        AS effective_privileges,
       count(*) FILTER (WHERE granted_via = 'direct') AS direct_rows
FROM audit.granted_privileges
WHERE snapshot = :'snapshot'
GROUP BY account
ORDER BY effective_privileges DESC, account;
