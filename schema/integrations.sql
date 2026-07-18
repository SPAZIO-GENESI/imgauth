-- P28: vetrina pubblica "Integrazioni e applicazioni" + listino pool B2B.
-- Stessa D1 di conventions.sql/pro.sql (imgauth-health).
-- ⚠️ Non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota ⛔), PRIMA del codice che legge le nuove tabelle
-- (vedi memoria imgauth-schema-before-deploy-order).

-- Una candidatura per email (stessa identità OAuth del resto del sistema).
-- status: pending | approved | rejected | removed. Ogni modifica dopo
-- l'approvazione riporta a pending (re-review) — vedi §4 del design.
CREATE TABLE IF NOT EXISTS integrations (
  id            TEXT PRIMARY KEY,          -- 'int_' + randomHex(4)
  owner_email   TEXT NOT NULL UNIQUE,      -- lowercase; '(rimosso)' dopo forget
  app_name      TEXT NOT NULL,
  url           TEXT NOT NULL,             -- https:// obbligatorio
  description   TEXT NOT NULL,             -- max 300 char, testo piano
  logo_key      TEXT,                      -- chiave R2 (integrations/<id>.<ext>), NULL = senza logo
  status        TEXT NOT NULL DEFAULT 'pending',
  submitted_at  INTEGER NOT NULL,
  reviewed_at   INTEGER,
  review_note   TEXT                       -- nota interna del gestore (mai pubblica)
);

-- Listino pool B2B (modello B, §2 del design): scaglioni pool mensile ↔
-- prezzo annuale, stesse regole temporali di pro_pricing (la riga attiva è
-- quella con valid_from più recente tra le valide). NON esposto pubblicamente
-- in v1 — uso interno/negoziale dal pannello admin.
CREATE TABLE IF NOT EXISTS pool_pricing (
  id            TEXT PRIMARY KEY,
  label         TEXT NOT NULL,             -- "Pool 500", "Pool 2000"
  monthly_pool  INTEGER NOT NULL,          -- attestazioni/mese incluse
  amount_cents  INTEGER NOT NULL,          -- prezzo ANNUALE in centesimi EUR
  valid_from    INTEGER NOT NULL,
  valid_to      INTEGER,
  created_at    INTEGER NOT NULL
);
