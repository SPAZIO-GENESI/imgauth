ATTESTATORE DI OPERE
sistema di notarizzazione opere digitali

[![Genesis Trust Score](https://trust.spaziogenesi.org/badge.svg)](https://trust.spaziogenesi.org)

su cloudflare

uso tramite https://attestazione.spaziogenesi.org/ (github pages)

Dalla 1.15.0 il motore attesta un'impronta SHA-256 calcolata sul client
(full privacy: il file non lascia il dispositivo dell'utente); il campo
`image` (file inline base64) resta accettato per retrocompatibilità.

## Accesso per agenti e API key

Dalla 1.16.0, oltre al browser (protetto da Turnstile), `/api/hash` accetta
anche un bearer token che sblocca il *solo* bypass della challenge anti-bot —
HMAC, timestamp server e rate limiting per-IP restano invariati per tutti.

Due tipi di credenziale, stesso meccanismo (in D1 sta solo l'hash del secret):

- **API key** (`sg_k_…`) — per partner convenzionati, quota mensile, emessa a
  mano con `scripts/issue-agent-key.mjs`.
- **Session token** (`sg_s_…`) — per uso personale/agenti, ottenuto con un
  *device flow*: l'umano autorizza una volta nel browser (`/agent/authorize`,
  con Turnstile), l'agente polla `/api/agent/token` e riceve un token valido
  24h/20 attestazioni.

Client di riferimento: [attest-mcp](https://github.com/SPAZIO-GENESI/attest-mcp),
server MCP che espone il servizio agli agenti AI mantenendo la stessa full
privacy del sito (hash calcolato in locale, mai i byte del file).

### Chiave API self-service (dalla 1.19.0, LinkedIn dalla 1.20.0)

Terza via di emissione della stessa `sg_k_…` (non un terzo tipo di
credenziale): [`/developer/keys`](https://attestazione.spaziogenesi.org/developer/keys/)
emette una chiave in autonomia dopo aver verificato la tua email con un login
**one-shot** Google, Microsoft o LinkedIn (scope minimo `openid email` — non è
un account, non lasciamo cookie né token del provider: una sola chiamata per
leggere l'email, poi il token viene scartato). Quota 50 attestazioni/mese,
un'email = una chiave attiva (chiedere a `it@spaziogenesi.org` per revoca o
quote più alte). Le convenzioni con quote più alte restano manuali via email.

## Fascia Professionale (dalla 1.22.0)

Abbonamento annuale a pagamento (Stripe) per chi attesta con continuità:
200 attestazioni/mese, custodia del certificato garantita per almeno 5 anni.
Stessa identità "senza account e senza password" delle chiavi self-service —
la tua email verificata ti autentica, un voucher firmato stateless (mai un
cookie) vive solo nel browser. Attivazione, stato, log delle ricariche,
consumo del mese e archivio dei certificati (con il canale con cui ciascuno
è stato prodotto: sito, API, MCP, bot Telegram) su
[`/profilo`](https://attestazione.spaziogenesi.org/profilo/). Gestione
dell'abbonamento (fatture, metodo di pagamento, cessazione) interamente sul
Customer Portal Stripe — nessun dato di pagamento tocca mai questo Worker.

La catena di precedenza tra le fasce è **convenzione → professionale →
sviluppatore/base**: mai un blocco, solo un degrado esplicito a quota
esaurita o scaduta.

## Documentazione API

Contratto completo in formato OpenAPI 3.0: [`/openapi.json`](https://imgauth.spaziogenesi.org/openapi.json)
(machine-readable, importabile in Postman/Insomnia/Swagger UI) o
[`/docs`](https://attestazione.spaziogenesi.org/docs/) per la stessa documentazione
in una pagina leggibile — auto-ospitata, nessuna dipendenza di terze parti.

## Sicurezza

Segnalazioni di vulnerabilità → [`/sicurezza/`](https://attestazione.spaziogenesi.org/sicurezza/)
(policy di responsible disclosure, safe harbor per la ricerca in buona fede);
`security.txt` conforme RFC 9116 su
[`/.well-known/security.txt`](https://imgauth.spaziogenesi.org/.well-known/security.txt).

## Licenza

Copyright (C) 2026 Spazio Genesi ETS.

Questo software è rilasciato sotto licenza **GNU AGPL-3.0** (vedi [LICENSE](LICENSE)):
puoi usarlo, studiarlo, modificarlo e ridistribuirlo; se lo usi per offrire un
servizio in rete, devi rendere disponibile il codice sorgente delle tue modifiche.

Nota: la licenza copre il codice, non il servizio. I certificati emessi da
https://imgauth.spaziogenesi.org sono autenticati da segreti server-side
(HMAC, certificato di firma) che non fanno parte di questo repository:
un'istanza indipendente del codice non può emettere certificati che superino
la verifica del servizio ufficiale.
