-- P25 (B): convenzioni per dominio email (accademie) + log copertura/contabilità.
-- Stessa D1 di dev_selfservice.sql (imgauth-health).
-- ⚠️ ALTER TABLE non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota ⛔), come dev_selfservice.sql.
ALTER TABLE agent_credentials ADD COLUMN convention_id TEXT;  -- NULL = non in convenzione

CREATE TABLE IF NOT EXISTS conventions (
  id                TEXT PRIMARY KEY,      -- slug ('accademia-aq')
  name              TEXT NOT NULL,         -- ragione sociale ente
  domains           TEXT NOT NULL,         -- domini email, lowercase, separati da virgola, SENZA @
  monthly_quota     INTEGER NOT NULL,      -- POOL mensile dell'ente, condiviso tra i membri
  member_cap        INTEGER NOT NULL DEFAULT 50,  -- tetto individuale/mese anti-drenaggio (0 = nessun tetto)
  persistence_years INTEGER,               -- 5 | 10 (valore contrattuale, informativo)
  starts_at         INTEGER NOT NULL,      -- epoch ms
  ends_at           INTEGER NOT NULL,      -- epoch ms → expires_at delle chiavi emesse
  active            INTEGER NOT NULL DEFAULT 1,
  created_at        TEXT NOT NULL
);

-- Log unico per copertura garanzia, contabilità pool e report per membro:
-- quale membro (email) ha attestato quale impronta, sotto quale convenzione,
-- da quale canale. SOLO emissioni in convenzione (minimizzazione: nessun log
-- per self-service individuali né per il percorso anonimo). Niente sweep dal
-- cron: la retention è la durata della garanzia (5-10 anni); l'email è
-- anonimizzabile prima su richiesta (il log sopravvive pseudonimo, vedi §4).
-- ym ridondante rispetto a ts ma indispensabile: le COUNT di pool/cap sono
-- sul mese Europe/Rome e devono restare a un indice di distanza.
CREATE TABLE IF NOT EXISTS convention_attestations (
  convention_id TEXT NOT NULL,
  member_email  TEXT NOT NULL,             -- lowercase; '(rimosso)' dopo forget
  credential_id TEXT,                      -- id chiave sg_k_ se via API, NULL se via voucher dal sito
  via           TEXT NOT NULL,             -- 'key' | 'site'
  sha256        TEXT NOT NULL,
  ym            TEXT NOT NULL,             -- 'YYYY-MM' Europe/Rome (stessa dayRome esistente)
  ts            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_convatt_pool   ON convention_attestations(convention_id, ym);
CREATE INDEX IF NOT EXISTS ix_convatt_member ON convention_attestations(convention_id, member_email, ym);
