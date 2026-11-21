\set ON_ERROR_STOP on
\if :{?as_of}
\else
  \set as_of '2026-11-12'
\endif

BEGIN;

CREATE SCHEMA IF NOT EXISTS audit;
DROP TABLE IF EXISTS audit.usage_log;
DROP TABLE IF EXISTS audit.analysis_config;

-- Single-row settings table (the PRIMARY KEY on a constant-true column enforces one row)
CREATE TABLE audit.analysis_config (
  id           boolean PRIMARY KEY DEFAULT true CHECK (id),
  as_of        date    NOT NULL,   -- analysis date (use CURRENT_DATE against a real log)
  window_days  integer NOT NULL,   -- how far back the log reaches
  stale_days   integer NOT NULL    -- a privilege unused longer than this is "stale"
);
INSERT INTO audit.analysis_config (as_of, window_days, stale_days)
VALUES (:'as_of'::date, 180, 90);

-- timestamp (no time zone): the simulated log is treated as UTC
CREATE TABLE audit.usage_log (
  log_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_time  timestamp NOT NULL,
  account     text      NOT NULL,
  client_ip   inet      NOT NULL,
  table_name  text      NOT NULL,
  action      text      NOT NULL CHECK (action IN ('SELECT','INSERT','UPDATE','DELETE'))
);

-- Usage profile: account, table, action, number of events, first and last day (days before as_of).
-- Events are spread evenly from first to last, so each privilege's last-used date is exact.
WITH profile (account, table_name, action, n_events, first_ago, last_ago) AS (VALUES
  -- Analytics: read-only in practice
  ('amina_k','customers','SELECT',60,175,1),
  ('amina_k','orders','SELECT',80,175,1),
  ('amina_k','payments','SELECT',30,170,3),
  ('chloe_m','customers','SELECT',45,170,2),
  ('chloe_m','orders','SELECT',55,170,2),
  ('brian_o','orders','SELECT',25,160,5),
  ('brian_o','payments','SELECT',20,160,5),
  ('shared_reports','customers','SELECT',40,175,1),
  ('shared_reports','orders','SELECT',50,175,1),
  ('shared_reports','payments','SELECT',35,175,1),
  -- Sales
  ('david_n','customers','SELECT',70,175,1),
  ('david_n','customers','UPDATE',30,170,2),
  ('david_n','orders','SELECT',90,175,1),
  ('david_n','orders','INSERT',40,175,1),
  ('david_n','orders','UPDATE',25,170,3),
  ('david_n','payments','SELECT',20,170,4),
  ('esther_w','customers','SELECT',65,175,1),
  ('esther_w','customers','INSERT',20,170,2),
  ('esther_w','customers','UPDATE',25,175,2),
  ('esther_w','orders','SELECT',70,175,1),
  ('esther_w','orders','INSERT',35,170,2),
  ('esther_w','payments','SELECT',6,175,120),
  ('felix_a','customers','SELECT',55,175,1),
  ('felix_a','customers','UPDATE',10,175,100),
  ('felix_a','orders','SELECT',60,175,1),
  ('felix_a','orders','INSERT',30,170,3),
  ('felix_a','orders','UPDATE',15,170,4),
  ('grace_m','customers','SELECT',50,175,2),
  ('grace_m','customers','INSERT',15,170,6),
  ('grace_m','orders','SELECT',45,175,2),
  ('grace_m','orders','INSERT',20,170,6),
  -- Finance
  ('hassan_i','payments','SELECT',80,175,1),
  ('hassan_i','payments','INSERT',45,175,1),
  ('hassan_i','payments','UPDATE',20,175,130),
  ('hassan_i','orders','SELECT',40,175,2),
  ('hassan_i','customers','SELECT',25,170,2),
  ('hassan_i','salaries','SELECT',8,170,10),
  ('irene_k','payments','SELECT',75,175,1),
  ('irene_k','payments','INSERT',30,175,2),
  ('irene_k','payments','UPDATE',12,170,5),
  ('irene_k','orders','SELECT',35,170,3),
  ('irene_k','customers','SELECT',20,170,3),
  ('james_t','payments','SELECT',50,175,2),
  ('james_t','payments','INSERT',25,175,2),
  ('james_t','orders','SELECT',30,175,3),
  ('james_t','customers','SELECT',15,175,3),
  -- Leaver (terminated 135 days before as_of): normal use before, salaries access after
  ('peter_x','payments','SELECT',12,170,140),
  ('peter_x','salaries','SELECT',6,120,22),
  -- Mover (Finance -> Support about 140 days ago): old Finance use stops, Support use starts
  ('tom_l','payments','SELECT',30,175,140),
  ('tom_l','salaries','SELECT',5,175,150),
  ('tom_l','customers','SELECT',40,130,1),
  ('tom_l','customers','UPDATE',25,130,2),
  ('tom_l','orders','SELECT',45,130,1),
  ('tom_l','orders','UPDATE',20,130,3),
  -- Support
  ('mary_c','customers','SELECT',80,175,1),
  ('mary_c','customers','UPDATE',50,175,1),
  ('mary_c','orders','SELECT',70,175,1),
  ('mary_c','orders','UPDATE',30,170,2),
  ('noah_p','customers','SELECT',70,175,1),
  ('noah_p','customers','UPDATE',35,175,2),
  ('noah_p','orders','SELECT',60,175,1),
  ('noah_p','orders','UPDATE',25,170,3),
  ('olivia_r','customers','SELECT',30,100,1),
  ('olivia_r','orders','SELECT',25,100,2),
  -- HR
  ('kevin_b','employees','SELECT',40,175,1),
  ('kevin_b','employees','INSERT',10,170,15),
  ('kevin_b','employees','UPDATE',25,175,3),
  ('kevin_b','salaries','SELECT',20,175,2),
  ('kevin_b','salaries','UPDATE',8,170,20),
  ('lucy_n','employees','SELECT',35,175,1),
  ('lucy_n','employees','INSERT',8,170,30),
  ('lucy_n','employees','UPDATE',20,175,4),
  ('lucy_n','salaries','SELECT',15,175,5),
  ('victor_h','employees','SELECT',20,175,2),
  ('victor_h','salaries','SELECT',10,170,6)
),
-- one workstation IP per account; shared_reports is handled separately below
ips (account, client_ip) AS (VALUES
  ('amina_k','10.20.1.11'), ('chloe_m','10.20.1.12'), ('brian_o','10.20.1.13'),
  ('david_n','10.20.2.11'), ('esther_w','10.20.2.12'), ('felix_a','10.20.2.13'), ('grace_m','10.20.2.14'),
  ('hassan_i','10.20.3.11'), ('irene_k','10.20.3.12'), ('james_t','10.20.3.13'), ('peter_x','10.20.3.14'),
  ('tom_l','10.20.4.15'), ('mary_c','10.20.4.11'), ('noah_p','10.20.4.12'), ('olivia_r','10.20.4.13'),
  ('kevin_b','10.20.5.11'), ('lucy_n','10.20.5.12'), ('victor_h','10.20.5.13')
),
events AS (
  SELECT p.account, p.table_name, p.action, i,
         p.first_ago - ((i - 1) * (p.first_ago - p.last_ago)) / (p.n_events - 1) AS days_ago
  FROM profile p
  CROSS JOIN LATERAL generate_series(1, p.n_events) AS i
)
INSERT INTO audit.usage_log (event_time, account, client_ip, table_name, action)
SELECT (c.as_of - e.days_ago)::timestamp
         + make_interval(hours => 8 + (e.i * 7) % 10, mins => (e.i * 13) % 60),
       e.account,
       CASE WHEN e.account = 'shared_reports'
            THEN ('10.20.9.' || (11 + e.i % 6))::inet      -- rotates across 6 IPs
            ELSE ip.client_ip::inet END,
       e.table_name, e.action
FROM events e
CROSS JOIN audit.analysis_config c
LEFT JOIN ips ip ON ip.account = e.account
ORDER BY 1, 2;

COMMIT;

-- Verification 1: overall size of the log
SELECT count(*)                                  AS events,
       count(DISTINCT account)                   AS accounts_with_activity,
       count(DISTINCT (account, table_name, action)) AS distinct_privileges_used,
       min(event_time)::date                     AS first_event,
       max(event_time)::date                     AS last_event
FROM audit.usage_log;

-- Verification 2: granted accounts with no activity at all (dormant)
SELECT a.account AS dormant_account
FROM audit.accounts a
WHERE a.snapshot = 'before'
  AND NOT EXISTS (SELECT 1 FROM audit.usage_log u WHERE u.account = a.account);

-- Verification 3: accounts used from more than one IP (shared-account fingerprint)
SELECT account, count(DISTINCT client_ip) AS distinct_ips
FROM audit.usage_log
GROUP BY account
HAVING count(DISTINCT client_ip) > 1;

-- Verification 4: activity after the employee's termination date
SELECT u.account, e.termination_date,
       count(*) AS events_after_termination,
       max(u.event_time)::date AS last_event
FROM audit.usage_log u
JOIN company.employees e ON e.username = u.account
WHERE e.status = 'terminated' AND u.event_time::date > e.termination_date
GROUP BY u.account, e.termination_date;

-- Verification 5: privileges used in the window but not within the stale threshold
SELECT account, table_name, action,
       max(event_time)::date AS last_used,
       (SELECT as_of FROM audit.analysis_config) - max(event_time)::date AS days_since_use
FROM audit.usage_log
GROUP BY account, table_name, action
HAVING (SELECT as_of FROM audit.analysis_config) - max(event_time)::date
       > (SELECT stale_days FROM audit.analysis_config)
ORDER BY days_since_use DESC, account;
