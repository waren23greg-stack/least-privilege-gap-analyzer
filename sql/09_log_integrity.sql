-- 09_log_integrity.sql
-- Makes audit.usage_log tamper-evident with a hash chain, then proves it by tampering.
--   content_hash(row) = sha256 of the row's fields (including log_id)
--   chain_hash(n)     = sha256(chain_hash(n-1) || content_hash(n)), starting from sha256('genesis')
-- The last chain hash is the HEAD: one value that changes if any row is edited, deleted or added.
-- Views kept for later use (also for Power BI):
--   audit.log_verification : per row status OK / MODIFIED / DELETED / INSERTED against the seal
--   audit.log_current_head : head hash recomputed from the log as it is right now
-- Running this script SEALS the log as it is now (trust on first seal), so run it right after loading
-- a log you trust, and copy the printed head hash somewhere outside the database. A superuser who
-- rewrites the log, the seal and the anchor together is only caught by that outside copy.
-- The tamper test edits the real table inside a transaction that is rolled back, so the log is
-- unchanged afterwards.
-- Run after 03: psql -U postgres -d privilege_audit -f sql/09_log_integrity.sql

\set ON_ERROR_STOP on

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.log_seal (
  log_id        bigint PRIMARY KEY,
  seq           bigint NOT NULL,
  content_hash  bytea  NOT NULL,
  chain_hash    bytea  NOT NULL
);

CREATE TABLE IF NOT EXISTS audit.log_anchor (
  sealed_at  timestamptz NOT NULL DEFAULT now(),
  log_rows   bigint      NOT NULL,
  head_hash  text        NOT NULL
);

-- The one place that defines what a row's content is
CREATE OR REPLACE VIEW audit.log_row_digest AS
SELECT log_id,
       sha256(convert_to(log_id::text || '|' || event_time::text || '|' || account || '|'
                         || client_ip::text || '|' || table_name || '|' || action, 'UTF8')) AS content_hash
FROM audit.usage_log;

CREATE OR REPLACE VIEW audit.log_current_head AS
WITH RECURSIVE cur AS (
  SELECT content_hash, row_number() OVER (ORDER BY log_id) AS seq
  FROM audit.log_row_digest
), chain AS (
  SELECT seq, sha256(sha256('genesis'::bytea) || content_hash) AS h
  FROM cur WHERE seq = 1
  UNION ALL
  SELECT c.seq, sha256(p.h || c.content_hash)
  FROM chain p JOIN cur c ON c.seq = p.seq + 1
)
SELECT encode(h, 'hex') AS head_hash, seq AS log_rows
FROM chain
ORDER BY seq DESC
LIMIT 1;

CREATE OR REPLACE VIEW audit.log_verification AS
SELECT COALESCE(s.log_id, c.log_id) AS log_id,
       s.seq,
       CASE WHEN c.log_id IS NULL THEN 'DELETED'
            WHEN s.log_id IS NULL THEN 'INSERTED'
            WHEN s.content_hash <> c.content_hash THEN 'MODIFIED'
            ELSE 'OK' END AS status
FROM audit.log_seal s
FULL JOIN audit.log_row_digest c ON c.log_id = s.log_id;

-- Seal the log as it is now
BEGIN;

DELETE FROM audit.log_seal;

INSERT INTO audit.log_seal (log_id, seq, content_hash, chain_hash)
WITH RECURSIVE cur AS (
  SELECT log_id, content_hash, row_number() OVER (ORDER BY log_id) AS seq
  FROM audit.log_row_digest
), chain AS (
  SELECT seq, log_id, content_hash,
         sha256(sha256('genesis'::bytea) || content_hash) AS chain_hash
  FROM cur WHERE seq = 1
  UNION ALL
  SELECT c.seq, c.log_id, c.content_hash, sha256(p.chain_hash || c.content_hash)
  FROM chain p JOIN cur c ON c.seq = p.seq + 1
)
SELECT log_id, seq, content_hash, chain_hash FROM chain;

INSERT INTO audit.log_anchor (log_rows, head_hash)
SELECT count(*), encode((SELECT chain_hash FROM audit.log_seal ORDER BY seq DESC LIMIT 1), 'hex')
FROM audit.log_seal;

COMMIT;

-- ===================== Results =====================

\echo
\echo == 1. Seal: copy the head hash somewhere outside the database ==
SELECT log_rows, head_hash
FROM audit.log_anchor
ORDER BY sealed_at DESC
LIMIT 1;

\echo == 2. Verification of the untouched log ==
SELECT status, count(*) AS n
FROM audit.log_verification
GROUP BY status
ORDER BY status;

SELECT (SELECT head_hash FROM audit.log_current_head)
     = (SELECT head_hash FROM audit.log_anchor ORDER BY sealed_at DESC LIMIT 1) AS head_matches;

\echo == 3. Seal self-check: each stored chain hash must follow from the one before ==
WITH RECURSIVE c AS (
  SELECT seq, chain_hash AS stored,
         sha256(sha256('genesis'::bytea) || content_hash) AS calc
  FROM audit.log_seal WHERE seq = 1
  UNION ALL
  SELECT s.seq, s.chain_hash, sha256(c.calc || s.content_hash)
  FROM c JOIN audit.log_seal s ON s.seq = c.seq + 1
)
SELECT count(*) AS sealed_rows,
       count(*) FILTER (WHERE calc <> stored) AS broken_links
FROM c;

-- ===================== Tamper test =====================

\echo == 4. Tamper test (rolled back afterwards) ==
BEGIN;

-- Attack 1: blame the dormant account for an analyst's query
UPDATE audit.usage_log
SET account = 'quinn_s'
WHERE log_id = (SELECT log_id FROM audit.usage_log
                WHERE account = 'amina_k' ORDER BY log_id OFFSET 20 LIMIT 1);

-- Attack 2: erase the leaver's first access after termination
DELETE FROM audit.usage_log
WHERE log_id = (SELECT min(log_id) FROM audit.usage_log
                WHERE account = 'peter_x' AND event_time >= '2026-07-01');

-- Attack 3: plant an event that never happened
INSERT INTO audit.usage_log (event_time, account, client_ip, table_name, action)
VALUES ('2026-09-01 10:00:00', 'tom_l', '10.20.4.15', 'salaries', 'SELECT');

SELECT log_id, seq, status
FROM audit.log_verification
WHERE status <> 'OK'
ORDER BY log_id;

SELECT (SELECT head_hash FROM audit.log_current_head)
     = (SELECT head_hash FROM audit.log_anchor ORDER BY sealed_at DESC LIMIT 1) AS head_matches;

ROLLBACK;

\echo == 5. After the rollback ==
SELECT status, count(*) AS n
FROM audit.log_verification
GROUP BY status
ORDER BY status;

SELECT (SELECT head_hash FROM audit.log_current_head)
     = (SELECT head_hash FROM audit.log_anchor ORDER BY sealed_at DESC LIMIT 1) AS head_matches;
