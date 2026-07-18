-- P27 (18/7): profilazione facoltativa per la fascia Sviluppatore, richiesta
-- dal gestore per sapere internamente CHI e QUANTI sono i profili tecnici
-- attivi (applicazione, sistema operativo, ambiente di sviluppo). Stesso
-- principio della profilazione Professionale (segment/region su
-- pro_subscriptions): visibile solo al titolare della chiave e al gestore,
-- mai pubblica, sempre facoltativa e cancellabile dall'interessato.
-- Vive su agent_credentials (non una tabella a parte): è per-chiave, come
-- owner_email/owner_provider, non per-attestazione.
-- ⚠️ ALTER TABLE non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota), PRIMA del codice che legge le nuove colonne.
ALTER TABLE agent_credentials ADD COLUMN dev_app_name TEXT;
ALTER TABLE agent_credentials ADD COLUMN dev_os TEXT;
ALTER TABLE agent_credentials ADD COLUMN dev_environment TEXT;
ALTER TABLE agent_credentials ADD COLUMN dev_profile_consent_at INTEGER;
