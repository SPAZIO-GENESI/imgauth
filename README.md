ATTESTATORE DI OPERE
sistema di notarizzazione opere digitali

[![Genesis Trust Score](https://trust.spaziogenesi.org/badge.svg)](https://trust.spaziogenesi.org)

su cloudflare

uso tramite https://attestazione.spaziogenesi.org/ (github pages)

Dalla 1.15.0 il motore attesta un'impronta SHA-256 calcolata sul client
(full privacy: il file non lascia il dispositivo dell'utente); il campo
`image` (file inline base64) resta accettato per retrocompatibilità.

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
