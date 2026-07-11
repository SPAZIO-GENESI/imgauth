# DevOps — Ambienti e catena di rilascio · Spazio Genesi

**Documento operativo e pubblicabile.** Descrive come i servizi di Spazio
Genesi ETS (sistema di attestazione opere digitali e piattaforma RADART)
vengono sviluppati, verificati e rilasciati senza mettere a rischio l'unico
ambiente di produzione. Non contiene segreti né identificatori sensibili:
può essere pubblicato e citato come evidenza del processo di rilascio.

> Stato: **in implementazione progressiva** — vedi la tabella
> [Stato di attuazione](#8-stato-di-attuazione) in fondo. Pubblicato qui
> prima della chiusura completa (5 fasi su 8), per non dare l'impressione
> di un lavoro fermo: questa copia viene aggiornata ad ogni fase chiusa,
> non solo alla fine.
>
> **Versione HTML**: https://trust.spaziogenesi.org/devops.html (stile
> Trust Center, con schemi SVG di parti e flusso; linkata dal footer del
> Trust Center). Registrato nel [Genesis Trust Framework](https://trust.spaziogenesi.org)
> come `ADR-P24` e `CTL-cicd-pipeline` (controllo verificabile: i run di
> CI citati qui sono pubblici, chiunque può controllare che il processo
> dichiarato sia quello praticato).

---

## 1. Principi

1. **Un solo ambiente di produzione, mai un bundle non osservato.** Ogni
   modifica attraversa una replica (staging) o una preview a traffico zero
   della produzione stessa, prima che un utente la veda.
2. **Il gate è umano e tracciato.** Nessun rilascio in produzione senza
   approvazione esplicita del gestore, registrata su GitHub (environment
   `production` con required reviewer).
3. **Rollback in secondi, senza rebuild.** Cloudflare Workers conserva le
   versioni precedenti: `wrangler rollback` riporta indietro immediatamente.
4. **Lo staging non contiene mai dati reali.** I database di staging nascono
   dagli schemi versionati nel repo più dati sintetici. Copiare dati di
   produzione (che includono email di sviluppatori registrati) sarebbe un
   trattamento GDPR senza scopo: non si fa.
5. **I segreti di produzione non lasciano il loro perimetro.** Lo staging ha
   segreti propri, generati apposta. In particolare `HMAC_SECRET` — il
   segreto che firma le attestazioni, non ruotabile per progetto — esiste
   solo in produzione e nel caveau di escrow.
6. **Il config non può divergere.** Produzione e staging vivono nello stesso
   `wrangler.toml` (blocco `[env.staging]`): ogni modifica di configurazione
   tocca entrambi nello stesso commit, il drift è strutturalmente impossibile.

## 2. Mappa degli ambienti

| Componente | Produzione | Staging (replica) |
|---|---|---|
| imgauth (motore attestazione) | Worker `imgauth` · imgauth.spaziogenesi.org | Worker `imgauth-staging` · solo `*.workers.dev`, nessuna route su domini pubblici |
| — D1 (health, credenziali) | `imgauth-health` | `imgauth-health-staging` (da `schema/*.sql`, senza dati reali) |
| — R2 (archivio PDF, EU) | `imgauth-pdf-archive` (eu) | `imgauth-pdf-archive-staging` (eu, vuoto alla nascita) |
| — firma PDF (authart) | Azure `sgart` | non replicato in v1: in staging `SIGNER_URL` vuoto → PDF identico ma non firmato |
| — anti-bot Turnstile | chiavi reali | chiavi di test Cloudflare (passano sempre) |
| — notifiche Telegram | attive | assenti (staging silenzioso) |
| authweb (interfaccia) | GitHub Pages · attestazione.spaziogenesi.org | copia **generata** dal medesimo sorgente su un secondo sito Pages ([attestazione-staging](https://spazio-genesi.github.io/attestazione-staging/)), puntata a imgauth-staging |
| radart-api / graph / semantic / ingest | Worker con risorse proprie per modulo | gemelli `-staging` con D1/R2 propri; i service binding di staging puntano ai gemelli |
| radart-web | Cloudflare Pages (produzione) | preview per-branch native di Pages, con variabili "Preview" puntate a radart-api-staging |
| attest-mcp | pacchetto npm (client) | non ha ambiente: unit test in CI; per prove d'integrazione si punta allo staging via env |

Scelte deliberate: lo staging **non ha cron attivi** (niente rollup/allarmi
doppi) e **non ha route** su domini di zona (le route Cloudflare nuove
richiedono un passo manuale in dashboard: meglio non averne affatto fuori
dalla produzione).

## 3. Flusso di rilascio

```
sviluppo locale (wrangler dev)
        │  pull request
        ▼
   CI — check automatici          lint/sintassi · validazione contratto
        │  merge su main             OpenAPI · build dry-run
        ▼
   deploy STAGING automatico      + smoke test automatico:
        │                            ping · status · hash → cert → recupero
        │  job "deploy-production" resta IN ATTESA
        │  (nessuno step parte prima di questo punto)
        ▼
   approvazione del gestore       GitHub Environment "production",
        │                            required reviewer
        ▼
   versions upload + deploy       upload a 0% traffico, poi promozione
        │                            al 100% — v1: un solo job, un solo
        │                            gate (raffinabile in futuro con un
        │                            secondo gate tra upload e promozione)
        ▼
   smoke di sola lettura           /ping — mai attestazioni automatiche
        │
        └── in emergenza: wrangler rollback (secondi, senza rebuild)
```

Il tag git `vX.Y.Z` sul commit di rilascio resta la convenzione in vigore
(alimenta l'indicatore di integrità del Genesis Trust Framework).

## 4. Runbook

### Rilascio ordinario
1. PR con la modifica → i check devono essere verdi.
2. Merge su `main` → lo staging si aggiorna da solo; controllare lo smoke.
3. Prova manuale su staging se la modifica è UI/flusso (URL staging).
4. Approvare il job `production` su GitHub → preview a 0% → promozione.
5. Smoke di produzione: `/ping` (versione attesa), `/api/status` tutto verde.
6. Tag `vX.Y.Z` se c'è bump di versione; aggiornare doc secondo convenzione.

### Hotfix urgente
Identico al rilascio ordinario — la catena È la via veloce (staging
automatico + un click di approvazione). Saltare lo staging non è previsto:
se la produzione è già rotta, il rollback (sotto) è più rapido di qualunque
fix scritto di fretta.

### Rollback
```
npx wrangler rollback <version-id>          # non interattivo con --yes
```
Poi: smoke di produzione, issue/nota su cosa è andato storto, fix con calma
attraverso la catena normale. **Collaudato su staging** (2026-07-11, P24
FASE 4): due versioni deployate, rollback alla prima con
`wrangler rollback <id> --env staging --yes`, `/ping` verificato subito
dopo — tornato alla versione precedente senza rebuild, in pochi secondi.

### Aggiungere lo staging a un modulo nuovo
1. Creare D1/R2 `-staging` del modulo (stesse regole: EU dove pertinente).
2. Blocco `[env.staging]` nel `wrangler.toml` del modulo: **ridichiarare
   tutti i binding** (gli env di wrangler non ereditano dal top-level).
3. Schemi applicati alla D1 staging, secret nuovi con `--env staging`.
4. Smoke, poi CI come da modello (`ci.yml` di imgauth è il riferimento).

## 5. Segreti e credenziali (nomi, mai valori)

| Dove | Cosa | Nota |
|---|---|---|
| Worker produzione | `HMAC_SECRET`, `SIGN_SECRET`, `TURNSTILE_SECRET`, `ADMIN_SECRET`, `TELEGRAM_*`, `*_OAUTH_CLIENT_SECRET` | invariati; `HMAC_SECRET` non si ruota MAI |
| Worker staging | `HMAC_SECRET` (nuovo, diverso), `TURNSTILE_SECRET` (chiave di test), `ADMIN_SECRET` (nuovo) | mai copie dei valori di produzione |
| GitHub Actions | `CLOUDFLARE_API_TOKEN` (scoped Workers), `CLOUDFLARE_ACCOUNT_ID` | per i deploy CI; revocabile dalla dashboard in ogni momento |
| RADART staging | `INGEST_SECRET`/`GRAPH_SECRET`/`SEM_SECRET` di staging | devono combaciare tra chiamante e chiamato, come in produzione |

## 6. Verifiche standard (smoke)

Ogni deploy staging esegue automaticamente, e chiunque può ripetere a mano:

- `GET /ping` → `ok:true` e versione attesa;
- `GET /api/status` → `worker: ok` (include la sonda HMAC interna);
- giro completo `POST /api/hash` → `POST /api/cert-pdf` → `GET /api/cert`
  (su staging: Turnstile di test, PDF non firmato, archivio staging);
- per RADART: una chiamata che attraversa un service binding
  (api→graph), l'unica cosa che lo sviluppo locale non sa replicare.

## 7. Limiti dichiarati (onestà del processo)

- **authart (firma PDF) non ha replica in v1**: lo staging emette PDF non
  firmati, identici nel contenuto. La replica del firmatario (slot Azure o
  seconda Web App) è rinviata alla prossima modifica sostanziale di authart.
- **Lo staging RADART usa artisti-api di produzione in sola lettura**
  (risoluzione dei nomi): documentato, a basso rischio, rivedibile.
- **Il flusso OAuth self-service non è attivo in staging** (i provider
  richiederebbero redirect URI dedicati): i bottoni restano assenti per
  design fail-closed; il flusso si collauda in locale come da P22.
- La promozione v1 è 0% → 100% dopo approvazione; il rollout percentuale
  graduale è un raffinamento successivo.

## 8. Stato di attuazione

| Fase | Contenuto | Stato |
|---|---|---|
| 0 | Inventario e prerequisiti | ✅ 2026-07-11 |
| 1 | Codice imgauth pronto al multi-ambiente (CORS configurabile) | ✅ 2026-07-11 |
| 2 | Staging imgauth (D1/R2/secret/deploy) | ✅ 2026-07-11 |
| 3 | CI imgauth (check su PR, staging automatico + smoke) | ✅ 2026-07-11 |
| 4 | Gate di produzione (approvazione, versions, rollback provato) | ✅ 2026-07-11 |
| 5 | Staging RADART (4 worker + preview Pages) | ⏳ da eseguire |
| 6 | CI RADART | ⏳ da eseguire |
| 7 | authweb staging (sito Pages generato dal sorgente) | ✅ 2026-07-11 |
| 8 | Pubblicazione doc + registrazione nel Genesis Trust Framework | 🔶 in corso (questa pagina) |

*Questa tabella viene aggiornata alla chiusura di ogni fase (data + esito),
qui e nella copia interna (`DEVOPS.md`, hub) e nella versione HTML
([trust.spaziogenesi.org/devops.html](https://trust.spaziogenesi.org/devops.html)),
nello stesso giro.*
