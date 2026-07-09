-- agent_access: credenziali bearer per accesso agenti/client automatici (P21).
-- Stessa D1 di health_log (imgauth-health). Due tipi di credenziale, una tabella:
-- 'key' = API key per convenzioni (emessa a mano, quota mensile, non scade);
-- 'session' = token da device flow (quota totale, scade dopo 24h).
-- In D1 sta SOLO l'hash del secret (sha256), mai il secret in chiaro.
-- agent_authorizations supporta il device flow (FASE 2): righe effimere, spazzate
-- dal cron quando scadute.
CREATE TABLE IF NOT EXISTS agent_credentials (
  id          TEXT PRIMARY KEY,          -- 8 hex (keyid o session id)
  kind        TEXT NOT NULL,             -- 'key' | 'session'
  secret_hash TEXT NOT NULL,             -- sha256 hex del secret (mai il secret)
  label       TEXT,                      -- 'Convenzione Accademia X' | 'session'
  quota       INTEGER NOT NULL,          -- key: mensile · session: totale
  used        INTEGER NOT NULL DEFAULT 0,
  period      TEXT,                      -- 'YYYY-MM' corrente (solo kind=key: reset al cambio mese)
  expires_at  INTEGER,                   -- epoch ms (solo kind=session)
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_authorizations (
  code          TEXT PRIMARY KEY,        -- 16 hex casuali (device flow)
  status        TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|claimed|expired
  token_once    TEXT,                    -- token completo in chiaro SOLO tra approve e claim, poi NULL
  credential_id TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL         -- created + 10 min
);
