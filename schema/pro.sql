-- P27: fascia Professionale (abbonamento Stripe) + tracciamento canale di
-- produzione (web/api/mcp/telegram). Stessa D1 di conventions.sql/dev_selfservice.sql
-- (imgauth-health).
-- ⚠️ ALTER TABLE non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota ⛔), PRIMA del codice che legge le nuove colonne
-- (vedi memoria imgauth-schema-before-deploy-order).

-- Canale di produzione (P27 §5): 'api' è il default per le chiavi sg_k_ generiche;
-- le sessioni sg_s_ (device flow) sono SEMPRE 'mcp' calcolato in JS (non serve
-- leggerlo da qui); la chiave del bot Telegram va ritaggiata con l'UPDATE
-- una-tantum in fondo a questo file.
ALTER TABLE agent_credentials ADD COLUMN channel TEXT DEFAULT 'api';

-- Stesso log delle convenzioni: utile nei futuri report mensili agli enti
-- sapere da quale canale è arrivata ciascuna attestazione.
ALTER TABLE convention_attestations ADD COLUMN channel TEXT;

-- Listino (FASE 2+): il prezzo valido è la riga con valid_from <= now < valid_to
-- (valid_to NULL = aperta). Se più righe si sovrappongono vince quella con
-- valid_from più recente (regola deterministica; l'admin UI segnala comunque
-- l'anomalia). Importo ANNUALE, in centesimi EUR.
CREATE TABLE IF NOT EXISTS pro_pricing (
  id            TEXT PRIMARY KEY,
  label         TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'eur',
  valid_from    INTEGER NOT NULL,
  valid_to      INTEGER,
  created_at    INTEGER NOT NULL
);

-- Codici sconto (FASE 2+): percentuale O importo fisso (mai entrambi), finestra
-- di validità, opzionalmente riservati a UNA email, opzionalmente a uso limitato.
CREATE TABLE IF NOT EXISTS pro_discounts (
  id               TEXT PRIMARY KEY,
  code             TEXT NOT NULL UNIQUE,   -- salvato UPPER, confronto case-insensitive
  percent_off      INTEGER,
  amount_off_cents INTEGER,
  valid_from       INTEGER NOT NULL,
  valid_to         INTEGER,
  restricted_email TEXT,                   -- normalizzata lowercase; NULL = per tutti
  max_uses         INTEGER,
  used_count       INTEGER NOT NULL DEFAULT 0,
  revoked          INTEGER NOT NULL DEFAULT 0,
  note             TEXT,
  created_at       INTEGER NOT NULL
);

-- Abbonamenti: 1 attivo per email (indice UNIQUE parziale, stesso pattern delle
-- chiavi self-service P22). status: 'active' | 'past_due' | 'canceled'.
-- Colonne di profilazione facoltativa (decisione gestore 17/7): su consenso.
CREATE TABLE IF NOT EXISTS pro_subscriptions (
  id                     TEXT PRIMARY KEY,
  email                  TEXT NOT NULL,    -- normalizzata trim().toLowerCase()
  stripe_customer_id     TEXT NOT NULL,
  stripe_subscription_id TEXT NOT NULL UNIQUE,
  status                 TEXT NOT NULL,
  current_period_end     INTEGER NOT NULL, -- epoch ms, aggiornato dai webhook
  price_cents            INTEGER NOT NULL, -- prezzo effettivo bloccato all'acquisto
  pricing_id             TEXT,             -- riga di listino applicata (audit)
  discount_code          TEXT,             -- codice applicato (audit), NULL se nessuno
  segment                TEXT,             -- profilazione facoltativa (consenso)
  region                 TEXT,             -- profilazione facoltativa (consenso)
  profile_consent_at     INTEGER,
  created_at             INTEGER NOT NULL,
  canceled_at            INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pro_sub_active_email
  ON pro_subscriptions(email) WHERE status IN ('active','past_due');

-- Log ricariche/eventi ("log di ricarica della scadenza" richiesto dal gestore).
-- type: 'created' | 'renewed' | 'payment_failed' | 'canceled'.
CREATE TABLE IF NOT EXISTS pro_events (
  id              TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  ts              INTEGER NOT NULL,
  type            TEXT NOT NULL,
  detail          TEXT                     -- JSON: {period_end, amount_cents, invoice_id}
);
CREATE INDEX IF NOT EXISTS idx_pro_events_sub ON pro_events(subscription_id, ts);

-- Log attestazioni professionali: fonte di consumo mensile, archivio
-- consultabile e garanzia 5 anni. `ym` ridondante rispetto a `ts` ma
-- indispensabile: stesso pattern di convention_attestations, le COUNT del
-- mese devono restare a un indice di distanza (mese Europe/Rome).
CREATE TABLE IF NOT EXISTS pro_attestations (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  email   TEXT NOT NULL,
  sha256  TEXT NOT NULL,
  channel TEXT,                            -- 'web' | 'api' | 'mcp' | 'telegram'
  ym      TEXT NOT NULL,                   -- 'YYYY-MM' Europe/Rome
  ts      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pro_att_email ON pro_attestations(email, ym);

-- UPDATE una tantum da eseguire insieme allo schema (non uno "schema" in sé,
-- ma va applicato nello stesso giro): la chiave dedicata del bot Telegram
-- (P23, label 'telegram-bot') va ritaggiata col canale corretto. I session
-- token nuovi nascono già 'mcp' calcolato in JS, non serve un UPDATE per loro.
UPDATE agent_credentials SET channel = 'telegram' WHERE label = 'telegram-bot';
