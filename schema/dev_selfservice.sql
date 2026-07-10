-- P22: emissione self-service di API key con email verificata OAuth.
-- Stessa D1 di agent_access.sql (imgauth-health). Colonne owner_* valorizzate
-- SOLO per le chiavi self-service (NULL per quelle emesse a mano o dal device
-- flow). Vedi P22-DESIGN-selfservice-keys.md §2.1.
-- ⚠️ Gli ALTER TABLE non sono idempotenti in SQLite: applicare questo file
-- UNA SOLA VOLTA per database (locale in test, remota come one-shot ⛔).
ALTER TABLE agent_credentials ADD COLUMN owner_email TEXT;
ALTER TABLE agent_credentials ADD COLUMN owner_provider TEXT;  -- 'google' | 'microsoft'
ALTER TABLE agent_credentials ADD COLUMN revoked_at INTEGER;   -- epoch ms (retention FASE 2)

-- Un'email = una chiave attiva (garanzia a livello DB, oltre al check applicativo).
CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_owner_active
  ON agent_credentials(owner_email)
  WHERE owner_email IS NOT NULL AND revoked = 0;

-- Stato anti-CSRF del flusso OAuth: righe effimere (10 min), spazzate dal cron
-- (FASE 2). Niente nuovo segreto di firma: lo state È il record.
CREATE TABLE IF NOT EXISTS dev_oauth_state (
  state      TEXT PRIMARY KEY,   -- 32 hex casuali (randomHex(16) esistente)
  provider   TEXT NOT NULL,      -- 'google' | 'microsoft'
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL    -- created + 10 min
);
