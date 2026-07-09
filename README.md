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
