-- 01_setup_messy_db.sql
-- Builds a fake company database with deliberately planted privilege problems.
-- Safe to re-run: it removes and rebuilds everything it created.
-- Run: psql -U postgres -d privilege_audit -f sql/01_setup_messy_db.sql
-- Login roles have no passwords, so nobody can actually authenticate as them.

\set ON_ERROR_STOP on
BEGIN;

-- 0. Guard: roles are cluster-wide, so only run this against the lab database
DO $$
BEGIN
  IF current_database() <> 'privilege_audit' THEN
    RAISE EXCEPTION 'Run this against privilege_audit only (connected to: %)', current_database();
  END IF;
END $$;

-- 1. Clean slate
DROP SCHEMA IF EXISTS company CASCADE;

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY[
    'role_analyst','role_sales','role_finance','role_hr','role_support',
    'amina_k','brian_o','chloe_m','quinn_s',
    'david_n','esther_w','felix_a','grace_m',
    'hassan_i','irene_k','james_t',
    'kevin_b','lucy_n','victor_h',
    'mary_c','noah_p','olivia_r',
    'peter_x','tom_l','shared_reports'
  ] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I', r);
      EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP;
END $$;

-- 2. Fake company tables (sensitive columns are marked)
CREATE SCHEMA company;

CREATE TABLE company.customers (
  customer_id  integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name    text NOT NULL,
  email        text,
  national_id  text,                 -- sensitive
  city         text,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE company.orders (
  order_id      integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id   integer NOT NULL REFERENCES company.customers,
  order_date    date NOT NULL DEFAULT CURRENT_DATE,
  total_amount  numeric(12,2) NOT NULL,
  status        text NOT NULL DEFAULT 'new'
);

CREATE TABLE company.payments (
  payment_id   integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_id     integer NOT NULL REFERENCES company.orders,
  card_number  text,                 -- sensitive
  amount       numeric(12,2) NOT NULL,
  paid_at      timestamptz NOT NULL DEFAULT now()
);

-- employees doubles as the HR roster used later to spot leavers
CREATE TABLE company.employees (
  employee_id       integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username          text NOT NULL UNIQUE,
  full_name         text NOT NULL,
  department        text NOT NULL,
  status            text NOT NULL CHECK (status IN ('active','terminated')),
  hire_date         date NOT NULL,
  termination_date  date,
  national_id       text             -- sensitive
);

CREATE TABLE company.salaries (
  salary_id       integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  employee_id     integer NOT NULL REFERENCES company.employees,
  monthly_salary  numeric(12,2) NOT NULL,   -- sensitive
  effective_from  date NOT NULL
);

-- 3. Group roles (no login)
CREATE ROLE role_analyst NOLOGIN;
CREATE ROLE role_sales   NOLOGIN;
CREATE ROLE role_finance NOLOGIN;
CREATE ROLE role_hr      NOLOGIN;
CREATE ROLE role_support NOLOGIN;

-- 4. Login accounts (20)
CREATE ROLE amina_k LOGIN;
CREATE ROLE brian_o LOGIN SUPERUSER;     -- PLANTED: analyst with SUPERUSER
CREATE ROLE chloe_m LOGIN;
CREATE ROLE quinn_s LOGIN;               -- PLANTED: dormant (no usage will be logged)
CREATE ROLE david_n LOGIN;
CREATE ROLE esther_w LOGIN;
CREATE ROLE felix_a LOGIN;
CREATE ROLE grace_m LOGIN CREATEROLE;    -- PLANTED: sales rep with CREATEROLE
CREATE ROLE hassan_i LOGIN;
CREATE ROLE irene_k LOGIN;
CREATE ROLE james_t LOGIN;
CREATE ROLE kevin_b LOGIN;
CREATE ROLE lucy_n LOGIN;
CREATE ROLE victor_h LOGIN;
CREATE ROLE mary_c LOGIN;
CREATE ROLE noah_p LOGIN;
CREATE ROLE olivia_r LOGIN;
CREATE ROLE peter_x LOGIN;               -- PLANTED: leaver, account still active
CREATE ROLE tom_l LOGIN;                 -- PLANTED: moved Finance -> Support, kept old access
CREATE ROLE shared_reports LOGIN;        -- PLANTED: shared account used by several people

-- 5. Role privileges (explicit list, no GRANT ALL)
GRANT USAGE ON SCHEMA company TO role_analyst, role_sales, role_finance, role_hr, role_support;

-- PLANTED role bloat: analysts only need to read, but get full write access to everything
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA company TO role_analyst;

GRANT SELECT, INSERT, UPDATE ON company.customers TO role_sales;
GRANT SELECT, INSERT, UPDATE ON company.orders    TO role_sales;
GRANT SELECT                 ON company.payments  TO role_sales;

GRANT SELECT, INSERT, UPDATE, DELETE ON company.payments TO role_finance;  -- DELETE is excess
GRANT SELECT ON company.orders, company.customers, company.salaries TO role_finance;

GRANT SELECT, INSERT, UPDATE ON company.employees TO role_hr;
GRANT SELECT, INSERT, UPDATE ON company.salaries  TO role_hr;

GRANT SELECT, UPDATE ON company.customers TO role_support;
GRANT SELECT, UPDATE, DELETE ON company.orders TO role_support;            -- DELETE is excess

-- 6. Role memberships
GRANT role_analyst TO amina_k, brian_o, chloe_m, quinn_s, shared_reports;
GRANT role_sales   TO david_n, esther_w, felix_a, grace_m;
GRANT role_finance TO hassan_i, irene_k, james_t, peter_x, tom_l;
GRANT role_hr      TO kevin_b, lucy_n, victor_h;
GRANT role_support TO mary_c, noah_p, olivia_r, tom_l;

-- 7. PLANTED direct grants that bypass roles
GRANT DELETE ON company.payments TO david_n;
GRANT SELECT ON company.salaries TO mary_c;
GRANT SELECT ON company.employees TO irene_k;
GRANT SELECT, INSERT, UPDATE, DELETE ON company.customers TO kevin_b;
GRANT SELECT, UPDATE ON company.salaries TO peter_x;
GRANT SELECT ON company.payments, company.customers, company.orders TO shared_reports;

-- 8. HR roster (all fake). shared_reports has no owner, so it has no row.
INSERT INTO company.employees (username, full_name, department, status, hire_date, termination_date) VALUES
  ('amina_k',  'Amina Kamau',   'Analytics', 'active',     '2021-03-15', NULL),
  ('brian_o',  'Brian Otieno',  'Analytics', 'active',     '2019-07-01', NULL),
  ('chloe_m',  'Chloe Mwangi',  'Analytics', 'active',     '2022-01-10', NULL),
  ('quinn_s',  'Quinn Sharma',  'Analytics', 'active',     '2023-05-22', NULL),
  ('david_n',  'David Njoroge', 'Sales',     'active',     '2020-09-14', NULL),
  ('esther_w', 'Esther Wanjiru','Sales',     'active',     '2021-11-03', NULL),
  ('felix_a',  'Felix Abdi',    'Sales',     'active',     '2022-06-27', NULL),
  ('grace_m',  'Grace Muthoni', 'Sales',     'active',     '2018-02-19', NULL),
  ('hassan_i', 'Hassan Ibrahim','Finance',   'active',     '2019-04-08', NULL),
  ('irene_k',  'Irene Kiplagat','Finance',   'active',     '2020-12-01', NULL),
  ('james_t',  'James Tanui',   'Finance',   'active',     '2023-02-13', NULL),
  ('kevin_b',  'Kevin Barasa',  'HR',        'active',     '2021-08-30', NULL),
  ('lucy_n',   'Lucy Nyambura', 'HR',        'active',     '2022-10-17', NULL),
  ('victor_h', 'Victor Hamisi', 'HR',        'active',     '2024-03-04', NULL),
  ('mary_c',   'Mary Chebet',   'Support',   'active',     '2020-05-25', NULL),
  ('noah_p',   'Noah Peters',   'Support',   'active',     '2022-09-12', NULL),
  ('olivia_r', 'Olivia Rono',   'Support',   'active',     '2023-07-31', NULL),
  ('peter_x',  'Peter Xander',  'Finance',   'terminated', '2020-02-10', '2026-06-30'),
  ('tom_l',    'Tom Lenana',    'Support',   'active',     '2019-10-21', NULL);

UPDATE company.employees SET national_id = (30000000 + employee_id * 7919)::text;

COMMIT;

-- 9. Verification
SELECT count(*) FILTER (WHERE rolcanlogin)     AS login_accounts,
       count(*) FILTER (WHERE NOT rolcanlogin) AS group_roles,
       count(*) FILTER (WHERE rolsuper)        AS superusers,
       count(*) FILTER (WHERE rolcreaterole)   AS createrole_holders
FROM pg_roles
WHERE rolname LIKE 'role\_%'
   OR rolname = 'shared_reports'
   OR rolname IN (SELECT username FROM company.employees);

SELECT r.rolname AS role, count(*) AS members
FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
WHERE r.rolname LIKE 'role\_%'
GROUP BY r.rolname ORDER BY r.rolname;

SELECT grantee, count(*) AS privilege_rows
FROM information_schema.table_privileges
WHERE table_schema = 'company' AND grantee <> 'postgres'
GROUP BY grantee ORDER BY grantee;
