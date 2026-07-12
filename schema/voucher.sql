-- P25 (C): distingue lo scopo dello stato OAuth transiente — 'key' (emissione
-- chiave self-service, P22) da 'attest' (percorso "attesta con la tua email"
-- dal sito, §2.7: nessuna chiave, solo un voucher stateless nel fragment).
-- Stessa tabella dev_oauth_state (P22), stessa D1 imgauth-health.
-- ⚠️ ALTER TABLE non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota ⛔), come dev_selfservice.sql/conventions.sql.
ALTER TABLE dev_oauth_state ADD COLUMN purpose TEXT NOT NULL DEFAULT 'key';
