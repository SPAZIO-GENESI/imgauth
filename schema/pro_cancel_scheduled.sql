-- P27: cessazione programmata a fine periodo (comportamento standard Stripe
-- Customer Portal per abbonamenti annuali pagati in anticipo — decisione
-- gestore 17/7, emersa durante il collaudo reale in produzione). Distinto da
-- `status`: l'abbonamento resta 'active' (la fascia Professionale continua
-- fino alla scadenza già pagata) finché Stripe non emette davvero
-- customer.subscription.deleted alla fine del periodo.
-- ⚠️ ALTER TABLE non idempotente: applicare UNA SOLA VOLTA per database
-- (locale → staging → remota), PRIMA del codice che legge la nuova colonna.
ALTER TABLE pro_subscriptions ADD COLUMN cancel_at_period_end INTEGER NOT NULL DEFAULT 0;
