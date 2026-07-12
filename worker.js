/**
 * Spazio Genesi ETS — Hash & Verify Worker (JavaScript)
 * Endpoints:
 *   POST /api/hash      → attesta un'impronta SHA-256: accetta `sha256` calcolato
 *                         sul client (full privacy: il file non lascia il dispositivo)
 *                         o, retrocompat, il file inline in `image` (base64);
 *                         emette attestazione + HMAC
 *   POST /api/verify    → verifica hash dichiarato vs file; il file è FACOLTATIVO
 *                         (senza, verifica la sola firma HMAC: il confronto
 *                         hash/file avviene sul client)
 *   POST /api/cert-pdf  → compila certificato_opera_pdf_mod.pdf e restituisce il PDF;
 *                         salva copia in R2 sotto pdf/<sha256>/ (binding PDF_ARCHIVE)
 *   GET  /api/cert      → recupero certificato smarrito: restituisce dal R2 il PDF
 *                         archiviato per ?hash=<sha256> (prima emissione)
 *   GET  /c/<sha256>    → pagina pubblica "certificato verificabile online": impronta,
 *                         data, algoritmo, ancoraggio OpenTimestamps, QR (HTML, no auth)
 *   GET  /api/badge     → badge SVG "Opera attestata" per ?hash=<sha256> (embed
 *                         su siti/social); verde solo se l'hash è in archivio
 *   GET  /api/status    → stato semaforico dei servizi (worker, archivio R2,
 *                         firmatario authart, calendar OpenTimestamps); cachato 180s
 *   GET  /api/status-history → storico 90 giorni per componente (per la pagina /status)
 *   GET  /api/health-log → eventi fini di salute per un giorno (?day=YYYY-MM-DD) da
 *                         D1: errori, degradi e rallentamenti sotto soglia (drill-down /status)
 *   (cron) scheduled    → campiona lo stato e aggiorna il rollup giornaliero in R2
 *   GET  /ping          → health check
 *   POST /api/agent/*, GET /agent/authorize → accesso agenti (API key + device
 *                         flow, P21): bypass del solo Turnstile su /api/hash
 *   GET  /admin, /admin/api/keys → pannello gestione credenziali agente
 *                         (stopgap ADMIN_SECRET, vedi CLAUDE.md)
 *   GET  /openapi.json, /docs → contratto API machine-readable e pagina di
 *                         consultazione (self-hosted, nessuna dipendenza esterna)
 */

import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { encode as encodeQR } from "uqr";
import certTemplatePdf from "./certificato_opera_pdf_mod.pdf";
import pkg from "./package.json";
import openapiSpec from "./openapi.json";

// Versione del motore: sorgente di verità unica = package.json (vedi CLAUDE.md › Versioning).
// Compare in /ping e nel blocco attestazione del certificato PDF.
const APP_VERSION = pkg.version;

const MONTHS_IT = [
  "", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
  "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
];

const ALLOWED_ORIGIN = "https://attestazione.spaziogenesi.org";

// Origin CORS effettivo per la richiesta corrente (P24: multi-ambiente).
// Di default coincide con ALLOWED_ORIGIN (produzione, comportamento invariato
// senza la var); in staging env.ALLOWED_ORIGIN punta al frontend di staging.
// Valorizzato a inizio fetch() — corsHeaders() legge questa variabile invece
// della costante, così i tanti punti che la chiamano senza argomenti restano
// invariati.
let activeAllowedOrigin = ALLOWED_ORIGIN;

// Base pubblica della pagina "certificato verificabile online" (vedi handleCertPage)
// e dominio su cui vivono gli endpoint /api/* (download PDF, prova .ots, badge).
// La pagina /c/<sha256> è renderizzata dal Worker e va montata su
// attestazione.spaziogenesi.org/c/* tramite route Cloudflare (vedi wrangler.toml);
// finché la route non è attiva, la STESSA pagina è raggiungibile su
// imgauth.spaziogenesi.org/c/<sha256> (custom domain del Worker, già attivo).
const CERT_PAGE_BASE = "https://attestazione.spaziogenesi.org";
const API_BASE       = "https://imgauth.spaziogenesi.org";

// Limite dimensione opera per il percorso LEGACY (file inline in `image`):
// il percorso primario (1.15.0) riceve solo l'impronta `sha256` calcolata sul
// client, quindi non ha tetto lato server (il limite pratico è la memoria del
// browser che calcola il digest, dichiarato dall'interfaccia).
const MAX_BYTES = 100 * 1024 * 1024;

// Formati attesi per i campi vincolati crittograficamente (vedi handlePdf).
const HEX64  = /^[0-9a-f]{64}$/i;
const ISO_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ── Accesso agenti / device flow (P21) ──────────────────────────────────────
// Parametri tarabili (vedi P21-DESIGN §6).
const SESSION_QUOTA        = 20;                  // attestazioni totali per sessione (nessun reset)
const SESSION_TTL_MS       = 24 * 60 * 60 * 1000;  // durata del session token
const AUTH_CODE_TTL_MS     = 10 * 60 * 1000;       // validità del codice di autorizzazione device flow
const AUTH_POLL_INTERVAL_S = 3;                    // intervallo di poll suggerito all'MCP
const AGENT_403_ALERT_THRESHOLD = 10;               // avviso Telegram oltre N credenziali invalide/giorno
// Sitekey PUBBLICA del widget Turnstile (stessa di authweb, stesso hostname:
// attestazione.spaziogenesi.org). Non è un segreto: va nell'HTML servito.
const AGENT_TURNSTILE_SITEKEY = "0x4AAAAAADiPceBIwTz5n4hG";
const AUTH_CODE_RE = /^[0-9a-f]{16}$/i;

// ── Self-service API key con verifica email OAuth (P22) ─────────────────────
// Parametri tarabili (vedi P22-DESIGN-selfservice-keys.md §6). La quota vera
// viene da env.DEV_KEY_QUOTA ([vars] in wrangler.toml); questo è solo il
// fallback se la var manca (es. ambiente locale senza wrangler.toml aggiornato).
const DEV_OAUTH_STATE_TTL_MS  = 10 * 60 * 1000;             // 10 minuti, stato ad uso singolo
const DEV_KEY_QUOTA_DEFAULT   = 50;                          // attestazioni/mese
const DEV_OWNER_RETENTION_MS  = 180 * 24 * 60 * 60 * 1000;   // 180 giorni post-revoca (FASE 2)

// ── "Attesta con la tua email" — voucher stateless dal sito (P25 §2.7) ──────
// TTL del voucher firmato (fragment #sgv=, sessionStorage lato authweb, mai
// un cookie né una riga D1): 8 ore, come da design.
const VOUCHER_TTL_MS = 8 * 60 * 60 * 1000;

// Endpoint OAuth "verifica email one-shot" (authorization code, scope openid
// email): niente login/sessione, l'access token si usa per UNA chiamata a
// userinfo e si scarta (vedi invariante 4 nel design). clientIdVar/clientSecretVar
// puntano ai nomi delle env var/secret Cloudflare — se assenti il provider è
// considerato non configurato (bottone assente, endpoint 503, fail-closed parziale).
const DEV_PROVIDERS = {
  google: {
    label: "Google",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userinfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    clientIdVar: "GOOGLE_OAUTH_CLIENT_ID",
    clientSecretVar: "GOOGLE_OAUTH_CLIENT_SECRET",
  },
  microsoft: {
    label: "Microsoft",
    authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userinfoUrl: "https://graph.microsoft.com/oidc/userinfo",
    clientIdVar: "MS_OAUTH_CLIENT_ID",
    clientSecretVar: "MS_OAUTH_CLIENT_SECRET",
  },
  // LinkedIn ("Sign In with LinkedIn using OpenID Connect"): il prodotto
  // concede insieme openid+profile+email, va richiesto lo scope completo
  // (un sottoinsieme rischia invalid_scope) anche se ci serve solo l'email.
  linkedin: {
    label: "LinkedIn",
    authorizeUrl: "https://www.linkedin.com/oauth/v2/authorization",
    tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
    userinfoUrl: "https://api.linkedin.com/v2/userinfo",
    clientIdVar: "LINKEDIN_OAUTH_CLIENT_ID",
    clientSecretVar: "LINKEDIN_OAUTH_CLIENT_SECRET",
    scope: "openid profile email",
  },
};

// ── Helpers CORS ────────────────────────────────────────────────────────────

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": activeAllowedOrigin,
    "Access-Control-Allow-Methods": "POST, GET, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret, X-SG-Voucher",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
    },
  });
}

// Apre il CORS (origine *) per gli endpoint PUBBLICI di sola lettura (stato/salute):
// i dati sono già pubblici sulla pagina /status, quindi sono monitorabili/embeddabili
// da qualunque origine (cruscotti esterni, ecc.). Gli endpoint sensibili (hash, verify,
// cert-pdf, …) restano ristretti ad ALLOWED_ORIGIN.
function withPublicCors(resp) {
  const h = new Headers(resp.headers);
  h.set("Access-Control-Allow-Origin", "*");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

function pdfResponse(bytes) {
  return new Response(bytes, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      ...corsHeaders(),
    },
  });
}

// ── Rate limiting (anti-abuso/DoS) ───────────────────────────────────────────

function tooManyResponse() {
  return new Response(JSON.stringify({ error: "Troppe richieste. Riprova tra un minuto." }, null, 2), {
    status: 429,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Retry-After": "60",
      ...corsHeaders(),
    },
  });
}

// true = richiesta da bloccare. Fail-open se il binding manca (dev) o erra,
// per non rompere il servizio: la barriera HMAC resta comunque attiva.
async function isRateLimited(limiter, key) {
  if (!limiter) return false;
  try {
    const { success } = await limiter.limit({ key });
    return !success;
  } catch {
    return false;
  }
}

// ── Turnstile (anti-bot) ─────────────────────────────────────────────────────
// Verifica server-side del token prodotto dal widget in authweb. Ritorna l'esito
// di siteverify (true/false). RILANCIA in caso di errore di rete: il chiamante
// decide la politica (su /api/hash, endpoint primario, si fa fail-open).
async function verifyTurnstile(secret, token, ip) {
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form,
  });
  const data = await r.json();
  return data.success === true;
}

// ── Metadati dichiarati dall'autore ──────────────────────────────────────────
// Campi descrittivi FACOLTATIVI (titolo, autore, anno, note). Sono auto-
// dichiarazioni: non provano nulla di per sé, ma vengono vincolati al token
// HMAC, così non possono essere alterati dopo l'emissione dell'attestazione.
const META_FIELDS = [
  ["titolo", 150],
  ["autore", 100],
  ["anno",    50],
  ["note",   300],
];

// Normalizza un valore dichiarato: collassa qualsiasi whitespace (newline
// compresi) in spazi singoli, scarta i caratteri fuori da WinAnsi (i font
// standard del PDF non li codificano: meglio perderli QUI, prima della firma,
// che firmare un testo non stampabile), trim e tetto di lunghezza.
// La forma canonica prodotta qui è ciò che viene firmato, stampato e verificato.
function cleanMeta(v, max) {
  return String(v ?? "")
    .replace(/\s+/g, " ")
    .replace(/[^\x20-\x7E\xA0-\xFF€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function extractMeta(src) {
  const meta = {};
  for (const [k, max] of META_FIELDS) meta[k] = cleanMeta(src?.[k], max);
  return meta;
}

// Messaggio firmato dal token HMAC. SENZA metadati coincide con la sola
// stringa di attestazione → i certificati già emessi (e quelli senza dati
// dichiarati) restano verificabili con la logica precedente. CON metadati
// li accoda in forma canonica, vincolandoli alla firma.
function hmacMessage(attest, meta) {
  if (!META_FIELDS.some(([k]) => meta[k])) return attest;
  return attest + "\n" + META_FIELDS.map(([k]) => `${k}:${meta[k]}`).join("\n");
}

// ── Autenticazione agenti (bearer token D1-backed, P21) ─────────────────────
// Formato: "sg_k_<id>_<secret>" (API key per convenzioni, quota mensile) o
// "sg_s_<id>_<secret>" (session token da device flow, quota totale). In D1
// sta SOLO sha256(secret): una credenziale valida sblocca solamente il
// bypass del check Turnstile su /api/hash (vedi handleHash) — HMAC, timestamp
// server e rate-limit per-IP restano invariati. Fail-closed: header presente
// ma credenziale malformata/ignota/scaduta/senza quota → 403/429, mai un
// fallback silenzioso al percorso Turnstile (vedi CLAUDE.md P21 § invarianti).
const BEARER_RE = /^sg_(k|s)_([0-9a-f]{8,32})_([A-Za-z0-9_-]{16,64})$/;

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return bufToHex(buf);
}

// Confronto a tempo costante fra due hex string della stessa lunghezza attesa:
// evita che un timing attack riveli byte dell'hash del secret un carattere alla volta.
function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// N byte casuali crittograficamente sicuri, in esadecimale.
function randomHex(bytes) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return bufToHex(buf.buffer);
}

// N byte casuali in base64url (senza padding): alfabeto del secret delle credenziali.
function randomBase64Url(bytes) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Bytes arbitrari → base64url (senza padding): usato per il payload del
// voucher (P25 §2.7), che deve viaggiare in un fragment URL senza bisogno
// di ulteriore escaping.
function bytesToBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Invio Telegram best-effort (fail-safe: un errore qui non deve mai propagarsi).
// Usato dagli allarmi P21 §2.5; notifyCertProduced ha il proprio invio inline
// (comportamento pre-esistente, non toccato).
async function sendTelegram(env, text) {
  const token = env?.TELEGRAM_BOT_TOKEN, chat = env?.TELEGRAM_CHAT_ID;
  if (!token || !chat) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text, disable_web_page_preview: true }),
    });
  } catch { /* notifica best-effort */ }
}

// Contatore giornaliero (R2, come meta/cert-count) dei 403 su credenziali agente:
// oltre soglia, un solo avviso Telegram per giorno (non uno per tentativo).
async function recordAgent403(env) {
  if (!env?.PDF_ARCHIVE) return;
  const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD' UTC
  let state = { day: today, count: 0 };
  try {
    const obj = await env.PDF_ARCHIVE.get("meta/agent-403-count");
    if (obj) {
      const parsed = JSON.parse(await obj.text());
      if (parsed?.day === today) state = parsed;
    }
  } catch { /* contatore assente o illeggibile: si riparte da 0 */ }
  state.count += 1;
  state.day = today;
  try { await env.PDF_ARCHIVE.put("meta/agent-403-count", JSON.stringify(state)); } catch {}

  if (state.count === AGENT_403_ALERT_THRESHOLD + 1) {
    await sendTelegram(env,
      `⚠️ Spazio Genesi — più di ${AGENT_403_ALERT_THRESHOLD} credenziali agente non valide oggi (${state.count}). Possibile tentativo di abuso su /api/hash.`);
  }
}

// Notifica soglia quota (80%/100%) di una credenziale agente. Chiamata solo
// esattamente al momento del sorpasso (vedi authenticateAgent): non serve
// stato aggiuntivo per evitare ripetizioni nello stesso periodo.
async function notifyAgentQuota(env, id, kind, label, used, quota, pct) {
  await sendTelegram(env,
    `📊 Spazio Genesi — credenziale agente "${label || id}" (${kind}) al ${pct}% della quota (${used}/${quota}).`);
}

// Esito 403 di authenticateAgent: registra il tentativo (best-effort, non
// bloccante) e restituisce l'errore da rispondere al chiamante.
function rejectAgent(env, ctx, message) {
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(recordAgent403(env).catch(() => {}));
  }
  return { error: message, status: 403 };
}

// Verifica il bearer di `request` contro `agent_credentials`. Ritorna:
//  - null                → nessun header Authorization: percorso Turnstile invariato
//  - { error, status }   → credenziale presente ma respinta (403 invalida/scaduta/
//                           revocata, 429 quota esaurita)
//  - { ok: true }        → credenziale valida, quota già scalata (UPDATE atomico)
async function authenticateAgent(request, env, ctx) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.slice("Bearer ".length).trim();

  const m = BEARER_RE.exec(token);
  if (!m || !env?.DB) return rejectAgent(env, ctx, "Credenziale non valida.");
  const [, kindLetter, id, secret] = m;
  const kind = kindLetter === "k" ? "key" : "session";

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT id, kind, secret_hash, label, quota, used, period, expires_at, revoked, convention_id, owner_email
       FROM agent_credentials WHERE id = ?`
    ).bind(id).first();
  } catch {
    return rejectAgent(env, ctx, "Errore interno di autenticazione.");
  }
  if (!row || row.kind !== kind || row.revoked) {
    return rejectAgent(env, ctx, "Credenziale non valida.");
  }
  // P25 (B): esteso da "solo session" a entrambi i kind — le chiavi di
  // convenzione scadono con la convenzione (expires_at = ends_at); le key
  // manuali/self-service restano NULL, quindi retrocompatibile senza
  // regressioni sulle credenziali esistenti.
  if (row.expires_at != null && Date.now() > row.expires_at) {
    return rejectAgent(env, ctx, "Credenziale scaduta.");
  }

  const secretHash = await sha256Hex(secret);
  if (!timingSafeEqualHex(secretHash, row.secret_hash)) {
    return rejectAgent(env, ctx, "Credenziale non valida.");
  }

  // Quota: le 'key' si resettano al cambio di mese UTC; le 'session' hanno un
  // tetto totale fisso per tutta la durata del token (nessun reset).
  let used = row.used;
  if (kind === "key") {
    const currentPeriod = new Date().toISOString().slice(0, 7); // 'YYYY-MM'
    if (row.period !== currentPeriod) {
      used = 0;
      try {
        await env.DB.prepare(
          `UPDATE agent_credentials SET used = 0, period = ? WHERE id = ?`
        ).bind(currentPeriod, id).run();
      } catch {
        return rejectAgent(env, ctx, "Errore interno di autenticazione.");
      }
    }
  }
  if (used >= row.quota) {
    return { error: "Quota della credenziale esaurita.", status: 429 };
  }

  try {
    await env.DB.prepare(`UPDATE agent_credentials SET used = used + 1 WHERE id = ?`).bind(id).run();
  } catch {
    return rejectAgent(env, ctx, "Errore interno di autenticazione.");
  }

  // Allarme soglia quota (80%/100%, una volta sola: scatta solo esattamente al
  // sorpasso). Priorità al 100% per non doppio-notificare sulle quote piccole
  // dove le due soglie coincidono.
  const newUsed = used + 1;
  if (ctx && typeof ctx.waitUntil === "function") {
    if (newUsed === row.quota) {
      ctx.waitUntil(notifyAgentQuota(env, id, kind, row.label, newUsed, row.quota, 100).catch(() => {}));
    } else if (newUsed === Math.ceil(row.quota * 0.8)) {
      ctx.waitUntil(notifyAgentQuota(env, id, kind, row.label, newUsed, row.quota, 80).catch(() => {}));
    }
  }

  return { ok: true, id, conventionId: row.convention_id || null, ownerEmail: row.owner_email || null };
}

// ── Device flow (autorizzazione umana una-tantum per MCP, P21) ──────────────
// L'umano autorizza UNA volta nel browser (Turnstile, su questo Worker); l'MCP
// polla finché non riceve il session token, consegnato una sola volta.

// POST /api/agent/authorize — crea una richiesta di autorizzazione (no auth).
async function handleAgentAuthorize(env) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  const code = randomHex(8); // 16 caratteri esadecimali
  const now = Date.now();
  const expiresAt = now + AUTH_CODE_TTL_MS;
  try {
    await env.DB.prepare(
      `INSERT INTO agent_authorizations (code, status, token_once, credential_id, created_at, expires_at)
       VALUES (?, 'pending', NULL, NULL, ?, ?)`
    ).bind(code, now, expiresAt).run();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  return jsonResponse({
    code,
    verification_url: `${CERT_PAGE_BASE}/agent/authorize?code=${code}`,
    expires_in: Math.floor(AUTH_CODE_TTL_MS / 1000),
    interval: AUTH_POLL_INTERVAL_S,
  });
}

// GET /agent/authorize?code= — pagina servita dal Worker (stesso pattern di /c/*).
async function handleAgentAuthorizePage(url, env) {
  const code = url.searchParams.get("code") || "";
  if (!AUTH_CODE_RE.test(code)) {
    return htmlResponse(certPageShell("Codice non valido",
      `<p class="lead">Il codice di autorizzazione non è valido o è incompleto.</p>`), 400);
  }
  if (!env?.DB) {
    return htmlResponse(certPageShell("Servizio non disponibile",
      `<p class="lead">Il servizio di autorizzazione non è al momento raggiungibile. Riprova più tardi.</p>`), 503);
  }

  let row;
  try {
    row = await env.DB.prepare(`SELECT status, expires_at FROM agent_authorizations WHERE code = ?`).bind(code).first();
  } catch {
    return htmlResponse(certPageShell("Errore", `<p class="lead">Errore interno. Riprova.</p>`), 500);
  }
  if (!row || (Date.now() > row.expires_at && row.status !== "claimed")) {
    return htmlResponse(certPageShell("Richiesta scaduta",
      `<p class="lead">Questa richiesta di autorizzazione non è più valida. Torna all'app che l'ha generata e riprova da capo.</p>`), 410);
  }
  if (row.status !== "pending") {
    return htmlResponse(certPageShell("Autorizzato", agentAuthorizeSuccessBody()), 200);
  }
  return htmlResponse(agentAuthorizePageHtml(code), 200);
}

function agentAuthorizeSuccessBody() {
  return `<h1>Autorizzato ✓</h1>
    <p class="lead">Fatto. Torna all'app o all'agente che ha aperto questa pagina: rileverà l'autorizzazione da solo entro pochi secondi.</p>
    <p class="muted">Puoi chiudere questa scheda.</p>`;
}

function agentAuthorizePageHtml(code) {
  const bodyHtml = `<div id="agentBody">
    <h1>Autorizza un'app a emettere attestazioni</h1>
    <p class="lead">Un'app o un agente sul tuo dispositivo sta chiedendo di poter emettere fino a
    <b>${SESSION_QUOTA} attestazioni</b> nelle prossime <b>24 ore</b>, senza dover risolvere una
    verifica anti-bot a ogni attestazione.</p>
    <p class="muted">Autorizza solo se hai avviato tu questa richiesta, da un'app o un agente di cui ti fidi.</p>
    <div id="turnstileWidget" style="margin:1.2rem 0;"></div>
    <p id="agentMsg" class="muted" role="status" aria-live="polite"></p>
    <div class="actions">
      <button id="agentApproveBtn" class="btn primary" type="button" disabled>Autorizza</button>
    </div>
  </div>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
  <script>
    (function () {
      var CODE = ${JSON.stringify(code)};
      var SITEKEY = ${JSON.stringify(AGENT_TURNSTILE_SITEKEY)};
      var tsToken = "";
      window.onloadTurnstileCallback = function () {
        if (!window.turnstile) return;
        window.turnstile.render("#turnstileWidget", {
          sitekey: SITEKEY,
          action: "agent-authorize",
          callback: function (token) {
            tsToken = token;
            document.getElementById("agentApproveBtn").disabled = false;
          },
        });
      };
      document.getElementById("agentApproveBtn").addEventListener("click", async function () {
        var btn = this, msg = document.getElementById("agentMsg");
        btn.disabled = true;
        msg.textContent = "Autorizzazione in corso…";
        try {
          var res = await fetch("/api/agent/approve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: CODE, turnstile_token: tsToken }),
          });
          if (!res.ok) throw new Error("http " + res.status);
          document.getElementById("agentBody").innerHTML = ${JSON.stringify(agentAuthorizeSuccessBody())};
        } catch (e) {
          msg.textContent = "Autorizzazione non riuscita. Riprova.";
          btn.disabled = false;
          if (window.turnstile) window.turnstile.reset();
        }
      });
    })();
  </script>`;
  return certPageShell("Autorizza un'app", bodyHtml);
}

// POST /api/agent/approve {code, turnstile_token} — genera il session token.
async function handleAgentApprove(request, env, ctx) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Corpo non valido." }, 400); }
  const code = String(body?.code || "");
  const tsToken = String(body?.turnstile_token || "");
  if (!AUTH_CODE_RE.test(code)) return jsonResponse({ error: "Codice non valido." }, 400);
  if (!tsToken) return jsonResponse({ error: "Verifica anti-bot mancante." }, 400);

  let row;
  try {
    row = await env.DB.prepare(`SELECT status, expires_at FROM agent_authorizations WHERE code = ?`).bind(code).first();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  if (!row || Date.now() > row.expires_at) return jsonResponse({ error: "Richiesta scaduta." }, 410);
  if (row.status !== "pending") return jsonResponse({ error: "Richiesta già gestita." }, 409);

  // Stessa policy fail-open di /api/hash: un siteverify irraggiungibile non deve
  // bloccare l'unico punto umano dell'intero flusso agenti.
  let human = true;
  if (env?.TURNSTILE_SECRET) {
    try {
      human = await verifyTurnstile(env.TURNSTILE_SECRET, tsToken, request.headers.get("CF-Connecting-IP") || undefined);
    } catch {
      human = true;
    }
  }
  if (!human) return jsonResponse({ error: "Verifica anti-bot non superata. Riprova." }, 403);

  const id          = randomHex(4); // 8 caratteri esadecimali
  const secret      = randomBase64Url(32);
  const sessionToken = `sg_s_${id}_${secret}`;
  const secretHash  = await sha256Hex(secret);
  const now         = Date.now();
  const expiresAt   = now + SESSION_TTL_MS;
  const createdAt   = new Date(now).toISOString();

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO agent_credentials (id, kind, secret_hash, label, quota, used, period, expires_at, revoked, created_at)
         VALUES (?, 'session', ?, 'session', ?, 0, NULL, ?, 0, ?)`
      ).bind(id, secretHash, SESSION_QUOTA, expiresAt, createdAt),
      env.DB.prepare(
        `UPDATE agent_authorizations SET status = 'approved', token_once = ?, credential_id = ? WHERE code = ?`
      ).bind(sessionToken, id, code),
    ]);
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }

  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(sendTelegram(env,
      `🔑 Spazio Genesi — nuova sessione agente autorizzata (device flow). Quota ${SESSION_QUOTA} attestazioni, scade tra 24h.`
    ).catch(() => {}));
  }

  return jsonResponse({ ok: true });
}

// GET /api/agent/token?code= — polling dell'MCP: consegna il token una sola volta.
async function handleAgentToken(url, env) {
  const code = url.searchParams.get("code") || "";
  if (!AUTH_CODE_RE.test(code)) return jsonResponse({ error: "Codice non valido." }, 400);
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);

  let row;
  try {
    row = await env.DB.prepare(
      `SELECT status, token_once, expires_at FROM agent_authorizations WHERE code = ?`
    ).bind(code).first();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  if (!row) return jsonResponse({ status: "expired" }, 410);
  if (row.status === "claimed") return jsonResponse({ status: "claimed" });
  if (Date.now() > row.expires_at) return jsonResponse({ status: "expired" }, 410);
  if (row.status === "pending") return jsonResponse({ status: "pending" });

  // status === 'approved': consegna una sola volta, poi il token in chiaro
  // sparisce da D1 (vedi schema § token_once).
  try {
    await env.DB.prepare(
      `UPDATE agent_authorizations SET status = 'claimed', token_once = NULL WHERE code = ?`
    ).bind(code).run();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  return jsonResponse({ status: "approved", token: row.token_once });
}

// Spazzino righe scadute (device flow), agganciato al cron esistente: righe di
// autorizzazione scadute e session token scaduti (le 'key' non scadono mai).
// Dalla P22 FASE 2, anche: stato OAuth effimero scaduto e anonimizzazione del
// titolare delle chiavi self-service revocate da oltre 180 giorni (§2.5).
async function sweepExpiredAgentRows(env) {
  if (!env?.DB) return;
  const now = Date.now();
  try {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM agent_authorizations WHERE expires_at < ?`).bind(now),
      env.DB.prepare(`DELETE FROM agent_credentials WHERE kind = 'session' AND expires_at IS NOT NULL AND expires_at < ?`).bind(now),
      env.DB.prepare(`DELETE FROM dev_oauth_state WHERE expires_at < ?`).bind(now),
      env.DB.prepare(
        `UPDATE agent_credentials SET owner_email = '(rimosso)', owner_provider = NULL
         WHERE owner_email IS NOT NULL AND owner_email != '(rimosso)'
           AND revoked = 1 AND revoked_at IS NOT NULL AND revoked_at < ?`
      ).bind(now - DEV_OWNER_RETENTION_MS),
    ]);
  } catch (e) {
    console.error("[agent sweep failed]", e?.message);
  }
}

// ── Self-service API key con verifica email OAuth (P22, FASE 1) ─────────────
// Terza via di emissione della STESSA credenziale sg_k_… (non un terzo tipo):
// l'umano verifica la propria email con un OAuth one-shot (niente login/sessione,
// l'access token si usa solo per leggere l'email e si scarta), e riceve subito
// la chiave. Post-moderazione dal pannello /admin (FASE 2): Telegram a ogni
// emissione, revoca a un tap. Vedi P22-DESIGN-selfservice-keys.md.

// GET /developer/keys — pagina di ingresso: spiega il servizio, informativa
// privacy sintetica nel punto di raccolta, bottoni "Continua con …" solo per
// i provider effettivamente configurati (client id + secret presenti).
function devKeysPageHtml(env) {
  const quota = Number(env?.DEV_KEY_QUOTA) || DEV_KEY_QUOTA_DEFAULT;
  const buttons = Object.entries(DEV_PROVIDERS)
    .filter(([, cfg]) => env?.[cfg.clientIdVar] && env?.[cfg.clientSecretVar])
    .map(([key, cfg]) => `<a class="btn primary" href="/api/dev/oauth/start?provider=${key}">Continua con ${escHtml(cfg.label)}</a>`);

  const body = `<h1>Chiave API per sviluppatori</h1>
    <p class="lead">Verifica la tua email per ottenere subito una chiave <code>sg_k_…</code> con
    <b>${quota} attestazioni al mese</b>, da usare come bearer su <code>/api/hash</code> per saltare
    la verifica anti-bot (HMAC, marca temporale e limiti per-IP restano invariati).</p>
    <p class="muted">Cosa salviamo: la tua email, il provider scelto e la data di emissione — solo
    per erogare la chiave, moderarne l'uso (avviso e revoca in caso di abuso) e, su tua richiesta,
    cancellarli. Non conserviamo il token del provider, non creiamo una sessione, non facciamo
    marketing. Dettagli nella
    <a href="${CERT_PAGE_BASE}/privacy.html">informativa privacy</a>.</p>
    <div class="actions">${buttons.join("") || '<span class="muted">Nessun provider è al momento configurato.</span>'}</div>
    <p class="foot" style="margin-top:1.4rem;">Serve una quota più alta o un accesso via convenzione?
    Scrivi a <a href="mailto:it@spaziogenesi.org">it@spaziogenesi.org</a>.</p>`;
  return certPageShell("Chiave API sviluppatori", body);
}

// GET /api/dev/oauth/start?provider=google|microsoft|linkedin[&purpose=attest]
// — apre lo state anti-CSRF (riga effimera in D1, nessun nuovo segreto di
// firma: lo state È il record) e reindirizza all'authorize URL del provider.
// purpose='key' (default, P22) emette una chiave sg_k_…; purpose='attest'
// (P25 §2.7) non tocca agent_credentials, emette solo un voucher stateless
// nel fragment (vedi handleDevOAuthCallback).
async function handleDevOAuthStart(url, env) {
  const provider = url.searchParams.get("provider") || "";
  const purpose  = url.searchParams.get("purpose") === "attest" ? "attest" : "key";
  const cfg = DEV_PROVIDERS[provider];
  if (!cfg) return jsonResponse({ error: "Provider non valido." }, 400);
  const clientId = env?.[cfg.clientIdVar];
  const clientSecret = env?.[cfg.clientSecretVar];
  if (!clientId || !clientSecret || !env?.DB) {
    return jsonResponse({ error: "Provider non configurato." }, 503);
  }

  const state = randomHex(16);
  const now = Date.now();
  try {
    await env.DB.prepare(
      `INSERT INTO dev_oauth_state (state, provider, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`
    ).bind(state, provider, purpose, now, now + DEV_OAUTH_STATE_TTL_MS).run();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }

  const redirectUri = `${url.origin}/api/dev/oauth/callback/${provider}`;
  const authUrl = new URL(cfg.authorizeUrl);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", cfg.scope || "openid email");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("prompt", "select_account");
  return Response.redirect(authUrl.toString(), 302);
}

function devAlreadyActiveBody(id) {
  return `<h1>Hai già una chiave attiva</h1>
    <p class="lead">Il tuo indirizzo email ha già una chiave self-service attiva
    (id <span class="fingerprint">${escHtml(id)}</span>).</p>
    <p class="muted">Puoi continuare a usare quella chiave. Se l'hai persa, o vuoi revocarla per
    riceverne una nuova, scrivi a <a href="mailto:it@spaziogenesi.org">it@spaziogenesi.org</a>.</p>`;
}

function devKeyIssuedBody(key, quota, convention) {
  const convNote = convention
    ? `<p class="muted">Chiave emessa nell'ambito della convenzione con <strong>${escHtml(convention.name)}</strong> —
       valida fino al ${escHtml(new Date(convention.ends_at).toLocaleDateString("it-IT"))}; i certificati emessi
       con questa chiave godono della garanzia di persistenza prevista dalla convenzione.</p>`
    : "";
  return `<h1>Chiave creata ✓</h1>
    <p class="lead">Copiala ora: per motivi di sicurezza non potremo più mostrartela.</p>
    <div class="fingerprint" style="background:#fdf6e3;border:1px solid var(--oro);padding:.7rem .8rem;border-radius:8px;margin:1rem 0;">${escHtml(key)}</div>
    <p class="muted">Quota: ${quota} attestazioni al mese, come header
    <span class="fingerprint">Authorization: Bearer ${escHtml(key)}</span> su <code>POST /api/hash</code>.
    Se la perdi: scrivi a <a href="mailto:it@spaziogenesi.org">it@spaziogenesi.org</a> per la revoca,
    poi torna qui per riemetterne una nuova.</p>
    ${convNote}
    <div class="actions">
      <a class="btn primary" href="/docs">Documentazione API</a>
      <a class="btn" href="https://github.com/SPAZIO-GENESI/attest-mcp">Server MCP</a>
    </div>`;
}

// P25 (B): match dominio email → convenzione attiva. Domini elencati per
// esteso nella convenzione (niente sottodomini automatici); poche righe
// attese, il filtro finale in JS va benissimo. Fail-closed silenzioso:
// un errore D1 equivale a "nessuna convenzione" (percorso self-service
// normale), mai un 500 sul login.
async function matchConvention(env, email) {
  if (!env?.DB) return null;
  const domain = String(email).split("@")[1];
  if (!domain) return null;
  const now = Date.now();
  let rows;
  try {
    rows = await env.DB.prepare(
      `SELECT id, name, domains, monthly_quota, member_cap, persistence_years, ends_at
       FROM conventions WHERE active = 1 AND starts_at <= ? AND ends_at > ?`
    ).bind(now, now).all();
  } catch {
    return null;
  }
  for (const row of rows.results || []) {
    const domains = String(row.domains).split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
    if (domains.includes(domain)) return row;
  }
  return null;
}

// P25 (C): voucher stateless "attesta con la tua email" (§2.7). Formato
// `base64url(JSON{email,conv,exp}) + '.' + HMAC-SHA256(HMAC_SECRET,'VOUCHER:'+payload)`
// — riuso del segreto esistente con prefisso di dominio 'VOUCHER:', così un
// voucher non è mai confondibile con un token di attestazione (stesso pattern
// del messaggio "SHA-256:<hash>@<ts>"). `conv` è solo un HINT preso al momento
// dell'emissione: NON è fonte di verità (va sempre riletto da D1, vedi
// verifyVoucher/matchConvention in handleHash).
async function buildVoucher(env, email, convention) {
  const payload = { email, conv: convention ? convention.id : null, exp: Date.now() + VOUCHER_TTL_MS };
  const payloadB64 = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await signHmac(env.HMAC_SECRET, `VOUCHER:${payloadB64}`);
  return `${payloadB64}.${sig}`;
}

// Verifica firma + scadenza di un voucher. null = assente/manomesso/scaduto.
// Non dice nulla sullo stato attuale della convenzione: il chiamante deve
// rileggerla da D1 (matchConvention) prima di applicarne i vantaggi.
async function verifyVoucher(env, token) {
  if (!env?.HMAC_SECRET || typeof token !== "string") return null;
  const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const payloadB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
  } catch {
    return null;
  }
  if (!payload || typeof payload.email !== "string" || !Number.isFinite(payload.exp)) return null;
  let valid;
  try {
    valid = await verifyHmac(env.HMAC_SECRET, `VOUCHER:${payloadB64}`, sig);
  } catch {
    return null;
  }
  if (!valid || Date.now() > payload.exp) return null;
  return payload; // { email, conv, exp }
}

// P25 (B)+(C): contabilità pool/tetto individuale di una convenzione, condivisa
// fra i due canali di emissione — chiave API (`via:'key'`, credentialId = id
// della sg_k_…) e voucher dal sito (`via:'site'`, credentialId = null, nessuna
// riga in agent_credentials). Mai un blocco: pool o tetto esauriti degradano
// silenziosamente a fascia Base con motivo esplicito (vedi §1/§2.4 design).
// Ritorna { fascia: null, ... } se conventionId è assente/la convenzione non
// esiste più (D1 cancellata a mano) — il chiamante mantiene il proprio default.
async function accountConventionUsage(env, ctx, { conventionId, memberEmail, credentialId, via, sha256 }) {
  if (!conventionId || !env?.DB) return { fascia: null, fasciaMotivo: null, convenzioneInfo: null };
  const ym = dayRome().slice(0, 7); // 'YYYY-MM' Europe/Rome
  try {
    const conv = await env.DB.prepare(
      `SELECT id, name, monthly_quota, member_cap FROM conventions WHERE id = ?`
    ).bind(conventionId).first();
    if (!conv) return { fascia: null, fasciaMotivo: null, convenzioneInfo: null };

    const poolRow = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM convention_attestations WHERE convention_id = ? AND ym = ?`
    ).bind(conv.id, ym).first();
    const poolUsed = poolRow?.c || 0;

    let fasciaMotivo = null;
    if (poolUsed >= conv.monthly_quota) {
      fasciaMotivo = "pool_esaurito";
    } else if (conv.member_cap > 0) {
      const capRow = await env.DB.prepare(
        `SELECT COUNT(*) AS c FROM convention_attestations WHERE convention_id = ? AND member_email = ? AND ym = ?`
      ).bind(conv.id, memberEmail, ym).first();
      if ((capRow?.c || 0) >= conv.member_cap) fasciaMotivo = "tetto_individuale";
    }
    if (fasciaMotivo) return { fascia: "base", fasciaMotivo, convenzioneInfo: null };

    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(env.DB.prepare(
        `INSERT INTO convention_attestations (convention_id, member_email, credential_id, via, sha256, ym, ts)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(conv.id, memberEmail, credentialId || null, via, sha256, ym, Date.now()).run().catch(() => {}));
    }
    return { fascia: "convenzione", fasciaMotivo: null, convenzioneInfo: { id: conv.id, name: conv.name } };
  } catch {
    return { fascia: null, fasciaMotivo: null, convenzioneInfo: null }; // fail-open
  }
}

// GET /api/dev/oauth/callback/<provider>?code=&state= — scambia il code,
// legge l'email verificata da userinfo e scarta il token, poi emette (o
// rifiuta se già esiste) la chiave sg_k_… per quell'email.
async function handleDevOAuthCallback(url, provider, env, ctx) {
  const cfg = DEV_PROVIDERS[provider];
  if (!cfg) {
    return htmlResponse(certPageShell("Provider non valido",
      `<p class="lead">Provider OAuth non riconosciuto.</p>`), 400);
  }
  const clientId = env?.[cfg.clientIdVar];
  const clientSecret = env?.[cfg.clientSecretVar];
  if (!clientId || !clientSecret || !env?.DB) {
    return htmlResponse(certPageShell("Servizio non disponibile",
      `<p class="lead">Questo provider non è al momento configurato. Riprova più tardi o usa l'altro.</p>`), 503);
  }

  if (url.searchParams.get("error")) {
    return htmlResponse(certPageShell("Richiesta annullata",
      `<p class="lead">L'accesso non è stato completato. Torna alla pagina
      <a href="/developer/keys">Chiave API sviluppatori</a> e riprova quando vuoi.</p>`), 200);
  }

  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  if (!code || !state) {
    return htmlResponse(certPageShell("Richiesta non valida",
      `<p class="lead">Parametri mancanti. Riparti da <a href="/developer/keys">qui</a>.</p>`), 400);
  }

  // Stato anti-CSRF ad uso singolo: letto e cancellato subito, chiunque lo
  // riusi (replay) trova la riga già sparita.
  let stateRow;
  try {
    stateRow = await env.DB.prepare(`SELECT provider, expires_at, purpose FROM dev_oauth_state WHERE state = ?`).bind(state).first();
    if (stateRow) await env.DB.prepare(`DELETE FROM dev_oauth_state WHERE state = ?`).bind(state).run();
  } catch {
    return htmlResponse(certPageShell("Errore", `<p class="lead">Errore interno. Riprova.</p>`), 500);
  }
  if (!stateRow || stateRow.provider !== provider || Date.now() > stateRow.expires_at) {
    return htmlResponse(certPageShell("Sessione scaduta",
      `<p class="lead">Questa richiesta di accesso è scaduta o non è valida. Torna a
      <a href="/developer/keys">Chiave API sviluppatori</a> e riprova.</p>`), 400);
  }

  const redirectUri = `${url.origin}/api/dev/oauth/callback/${provider}`;
  const tokenBody = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });
  const tokenRes = await fetchWithTimeout(cfg.tokenUrl, 10000, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: tokenBody.toString(),
  });
  if (!tokenRes || !tokenRes.ok) {
    return htmlResponse(certPageShell("Accesso non riuscito",
      `<p class="lead">Non siamo riusciti a completare l'accesso con ${escHtml(cfg.label)}. Riprova.</p>`), 502);
  }
  let tokenJson;
  try { tokenJson = await tokenRes.json(); } catch {
    return htmlResponse(certPageShell("Accesso non riuscito", `<p class="lead">Risposta non valida dal provider. Riprova.</p>`), 502);
  }
  const accessToken = tokenJson?.access_token;
  if (!accessToken) {
    return htmlResponse(certPageShell("Accesso non riuscito", `<p class="lead">Il provider non ha restituito un token valido. Riprova.</p>`), 502);
  }

  const userRes = await fetchWithTimeout(cfg.userinfoUrl, 10000, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!userRes || !userRes.ok) {
    return htmlResponse(certPageShell("Accesso non riuscito",
      `<p class="lead">Non siamo riusciti a leggere l'email dal tuo account ${escHtml(cfg.label)}. Riprova.</p>`), 502);
  }
  let userJson;
  try { userJson = await userRes.json(); } catch {
    return htmlResponse(certPageShell("Accesso non riuscito", `<p class="lead">Risposta non valida dal provider. Riprova.</p>`), 502);
  }
  // Da qui in poi accessToken/tokenJson/userJson non sono più referenziati:
  // niente store, niente log (invariante 4 del design).

  if ((provider === "google" || provider === "linkedin") && userJson?.email_verified === false) {
    return htmlResponse(certPageShell("Email non verificata",
      `<p class="lead">Il tuo account ${escHtml(cfg.label)} non ha un'email verificata. Usa un altro account o un altro provider.</p>`), 403);
  }
  const rawEmail = userJson?.email;
  if (!rawEmail || typeof rawEmail !== "string") {
    return htmlResponse(certPageShell("Email non disponibile",
      `<p class="lead">Il tuo account non espone un indirizzo email leggibile. Prova con l'altro provider.</p>`), 403);
  }
  const email = rawEmail.trim().toLowerCase();

  // P25 (C): percorso "attesta con la tua email" dal sito (§2.7) — stessa
  // barriera OAuth di sopra (email verificata), ma nessuna chiave: solo un
  // voucher stateless che authweb allega su /api/hash. Il token/l'email non
  // sono mai persistiti oltre questo punto (invariante 2 del design).
  if (stateRow.purpose === "attest") {
    if (!env?.HMAC_SECRET) {
      return htmlResponse(certPageShell("Servizio non disponibile",
        `<p class="lead">Questo percorso non è al momento disponibile. Riprova più tardi.</p>`), 503);
    }
    const convention = await matchConvention(env, email);
    let voucher;
    try {
      voucher = await buildVoucher(env, email, convention);
    } catch {
      return htmlResponse(certPageShell("Errore", `<p class="lead">Errore interno. Riprova.</p>`), 500);
    }
    return Response.redirect(`${CERT_PAGE_BASE}/#sgv=${encodeURIComponent(voucher)}`, 302);
  }

  let existing;
  try {
    existing = await env.DB.prepare(`SELECT id FROM agent_credentials WHERE owner_email = ? AND revoked = 0`).bind(email).first();
  } catch {
    return htmlResponse(certPageShell("Errore", `<p class="lead">Errore interno. Riprova.</p>`), 500);
  }
  if (existing) {
    return htmlResponse(certPageShell("Chiave già attiva", devAlreadyActiveBody(existing.id)), 200);
  }

  // P25 (B): dominio dell'email ∈ convenzione attiva? Se sì, la chiave nasce
  // già taggata: quota = tetto individuale (member_cap, secondo argine sotto
  // il pool mensile dell'ente — vedi §2.4 in handleHash), expires_at = fine
  // convenzione. Nessun match → percorso self-service identico a prima.
  const convention = await matchConvention(env, email);

  const id          = randomHex(4); // 8 caratteri esadecimali
  const secret      = randomBase64Url(32);
  const key         = `sg_k_${id}_${secret}`;
  const secretHash  = await sha256Hex(secret);
  const createdAt   = new Date().toISOString();
  const period      = createdAt.slice(0, 7); // 'YYYY-MM'
  const quota       = convention ? (convention.member_cap || DEV_KEY_QUOTA_DEFAULT) : (Number(env?.DEV_KEY_QUOTA) || DEV_KEY_QUOTA_DEFAULT);
  const label       = convention ? `convenzione:${convention.id}` : "self-service";
  const expiresAt   = convention ? convention.ends_at : null;

  try {
    await env.DB.prepare(
      `INSERT INTO agent_credentials (id, kind, secret_hash, label, quota, used, period, expires_at, revoked, created_at, owner_email, owner_provider, convention_id)
       VALUES (?, 'key', ?, ?, ?, 0, ?, ?, 0, ?, ?, ?, ?)`
    ).bind(id, secretHash, label, quota, period, expiresAt, createdAt, email, provider, convention ? convention.id : null).run();
  } catch {
    // Corsa con l'indice UNIQUE parziale (ux_agent_owner_active): un'altra
    // richiesta concorrente per la stessa email ha vinto nel frattempo.
    let raced;
    try {
      raced = await env.DB.prepare(`SELECT id FROM agent_credentials WHERE owner_email = ? AND revoked = 0`).bind(email).first();
    } catch { /* raced resta undefined: si cade nell'errore generico sotto */ }
    if (raced) return htmlResponse(certPageShell("Chiave già attiva", devAlreadyActiveBody(raced.id)), 200);
    return htmlResponse(certPageShell("Errore", `<p class="lead">Errore interno. Riprova.</p>`), 500);
  }

  if (ctx && typeof ctx.waitUntil === "function") {
    const convNote = convention ? ` · convenzione ${convention.id}` : "";
    ctx.waitUntil(sendTelegram(env,
      `🔑 Spazio Genesi — chiave self-service emessa · ${email} via ${cfg.label}${convNote} · id ${id} · quota ${quota}/mese`
    ).catch(() => {}));
  }

  return htmlResponse(certPageShell("Chiave API sviluppatori", devKeyIssuedBody(key, quota, convention)));
}

// ── Pannello admin credenziali agente (P21 follow-up) ───────────────────────
// STOPGAP: protetto da un secret condiviso (env.ADMIN_SECRET, header
// X-Admin-Secret) — stesso pattern di X-Sign-Secret tra imgauth e authart.
// Da sostituire/affiancare con Cloudflare Access (Zero Trust) davanti a
// /admin/* appena configurato dalla dashboard (fuori dalla portata di un
// deploy: richiede permessi che questo Worker non ha). Il perimetro di
// azione è identico a scripts/issue-agent-key.mjs — solo esposto via HTTP
// invece che da CLI locale: crea/elenca/revoca/modifica quota di
// agent_credentials, MAI l'emissione di certificati (che resta governata
// solo da HMAC_SECRET, invariato).
async function verifyAdminSecret(request, env) {
  if (!env?.ADMIN_SECRET) return false;
  const header = request.headers.get("X-Admin-Secret") || "";
  if (!header) return false;
  const [a, b] = await Promise.all([sha256Hex(header), sha256Hex(env.ADMIN_SECRET)]);
  return timingSafeEqualHex(a, b);
}

function adminUnauthorized() {
  return jsonResponse({ error: "Non autorizzato." }, 403);
}

async function handleAdminKeysList(env) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, kind, label, quota, used, period, expires_at, revoked, created_at,
              owner_email, owner_provider, revoked_at
       FROM agent_credentials ORDER BY created_at DESC`
    ).all();
    return jsonResponse({ keys: results || [] });
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
}

async function handleAdminKeysIssue(request, env) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Corpo non valido." }, 400); }
  const label = String(body?.label ?? "").trim().slice(0, 200);
  const quota = Number(body?.quota);
  if (!label) return jsonResponse({ error: "Etichetta mancante." }, 400);
  if (!Number.isInteger(quota) || quota <= 0) return jsonResponse({ error: "Quota non valida." }, 400);

  const id = randomHex(4); // 8 caratteri esadecimali
  const secret = randomBase64Url(32);
  const key = `sg_k_${id}_${secret}`;
  const secretHash = await sha256Hex(secret);
  const createdAt = new Date().toISOString();
  const period = createdAt.slice(0, 7); // 'YYYY-MM'

  try {
    await env.DB.prepare(
      `INSERT INTO agent_credentials (id, kind, secret_hash, label, quota, used, period, expires_at, revoked, created_at)
       VALUES (?, 'key', ?, ?, ?, 0, ?, NULL, 0, ?)`
    ).bind(id, secretHash, label, quota, period, createdAt).run();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  // La chiave in chiaro esiste solo in questa risposta: non viene mai
  // salvata (in D1 sta solo secretHash), quindi non è recuperabile dopo.
  return jsonResponse({ id, key, label, quota }, 201);
}

async function handleAdminKeysUpdate(request, env, id) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  if (!/^[0-9a-f]{8}$/i.test(id)) return jsonResponse({ error: "id non valido." }, 400);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Corpo non valido." }, 400); }

  const sets = [], binds = [];
  if (typeof body?.revoked === "boolean") {
    sets.push("revoked = ?");
    binds.push(body.revoked ? 1 : 0);
    // revoked_at alimenta la retention email (P22 §2.5): valorizzato alla
    // revoca, azzerato se mai riattivata (nessuna traccia di una revoca che
    // non è più in vigore).
    sets.push("revoked_at = ?");
    binds.push(body.revoked ? Date.now() : null);
  }
  if (body?.quota !== undefined) {
    const q = Number(body.quota);
    if (!Number.isInteger(q) || q <= 0) return jsonResponse({ error: "Quota non valida." }, 400);
    sets.push("quota = ?");
    binds.push(q);
  }
  if (body?.forget === true) {
    // Cancellazione GDPR immediata su richiesta dell'interessato, senza
    // aspettare i 180 giorni di retention (P22 §2.5). Ammessa solo su una
    // chiave già revocata (in questa stessa chiamata o in precedenza):
    // altrimenti due chiavi "dimenticate" contemporaneamente attive
    // collidono sull'indice UNIQUE parziale su owner_email.
    const willBeRevoked = body?.revoked === true || (await env.DB.prepare(
      `SELECT revoked FROM agent_credentials WHERE id = ?`
    ).bind(id).first())?.revoked === 1;
    if (!willBeRevoked) return jsonResponse({ error: "Revoca la chiave prima di dimenticare il titolare." }, 400);
    sets.push("owner_email = '(rimosso)', owner_provider = NULL");
  }
  if (!sets.length) return jsonResponse({ error: "Nessuna modifica specificata." }, 400);
  binds.push(id);

  try {
    await env.DB.prepare(`UPDATE agent_credentials SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run();
    // P25 (B): il "forget" copre anche il log di convenzione — il log
    // sopravvive pseudonimo (copertura garanzia e totali del pool intatti,
    // attribuzione individuale rimossa). Match per credential_id: preciso,
    // non serve conoscere l'email originale.
    if (body?.forget === true) {
      await env.DB.prepare(
        `UPDATE convention_attestations SET member_email = '(rimosso)' WHERE credential_id = ?`
      ).bind(id).run();
    }
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  return jsonResponse({ ok: true });
}

// Eliminazione DEFINITIVA (a differenza di 'revoked', che è reversibile):
// pensata per pulire chiavi di test. Il log convention_attestations resta
// intatto (ha già il proprio credential_id/member_email, indipendente
// dall'esistenza della riga in agent_credentials — coerente con 'forget',
// che anonimizza invece di cancellare).
async function handleAdminKeysDelete(env, id) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  if (!/^[0-9a-f]{8}$/i.test(id)) return jsonResponse({ error: "id non valido." }, 400);
  try {
    const result = await env.DB.prepare(`DELETE FROM agent_credentials WHERE id = ?`).bind(id).run();
    if (!result.meta || result.meta.changes === 0) return jsonResponse({ error: "Credenziale non trovata." }, 404);
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  return jsonResponse({ ok: true });
}

// ── P25 (B): pannello admin convenzioni (CRUD + report) ─────────────────────
// Stessa protezione di /admin/api/keys (X-Admin-Secret, verifyAdminSecret già
// applicata dal router prima di chiamare questi handler).

const SLUG_RE = /^[a-z0-9-]{2,32}$/;

async function handleAdminConventionsList(env) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  const ym = dayRome().slice(0, 7);
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, domains, monthly_quota, member_cap, persistence_years, starts_at, ends_at, active, created_at
       FROM conventions ORDER BY created_at DESC`
    ).all();
    const conventions = [];
    for (const row of results || []) {
      const poolRow = await env.DB.prepare(
        `SELECT COUNT(*) AS attestations, COUNT(DISTINCT member_email) AS members
         FROM convention_attestations WHERE convention_id = ? AND ym = ?`
      ).bind(row.id, ym).first();
      const keysRow = await env.DB.prepare(
        `SELECT COUNT(*) AS total, SUM(CASE WHEN revoked = 0 THEN 1 ELSE 0 END) AS active_keys
         FROM agent_credentials WHERE convention_id = ?`
      ).bind(row.id).first();
      conventions.push({
        ...row,
        pool_used_month: poolRow?.attestations || 0,
        members_this_month: poolRow?.members || 0,
        keys_total: keysRow?.total || 0,
        keys_active: keysRow?.active_keys || 0,
      });
    }
    return jsonResponse({ conventions, ym });
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
}

async function handleAdminConventionsCreate(request, env) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Corpo non valido." }, 400); }

  const id = String(body?.id ?? "").trim().toLowerCase();
  const name = String(body?.name ?? "").trim().slice(0, 200);
  const domainsRaw = String(body?.domains ?? "").trim();
  const monthlyQuota = Number(body?.monthly_quota);
  const memberCap = body?.member_cap === undefined ? 50 : Number(body.member_cap);
  const persistenceYears = body?.persistence_years === undefined || body?.persistence_years === null
    ? null : Number(body.persistence_years);
  const startsAt = Number(body?.starts_at);
  const endsAt = Number(body?.ends_at);

  if (!SLUG_RE.test(id)) return jsonResponse({ error: "id non valido (a-z0-9-, 2-32 caratteri)." }, 400);
  if (!name) return jsonResponse({ error: "Nome mancante." }, 400);
  const domains = domainsRaw.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
  if (!domains.length || domains.some(d => d.includes("@") || /\s/.test(d))) {
    return jsonResponse({ error: "Domini non validi: elenco separato da virgole, senza '@' né spazi." }, 400);
  }
  if (!Number.isInteger(monthlyQuota) || monthlyQuota <= 0) return jsonResponse({ error: "monthly_quota non valida." }, 400);
  if (!Number.isInteger(memberCap) || memberCap < 0) return jsonResponse({ error: "member_cap non valido." }, 400);
  if (!Number.isInteger(startsAt) || !Number.isInteger(endsAt) || endsAt <= startsAt) {
    return jsonResponse({ error: "starts_at/ends_at non validi." }, 400);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO conventions (id, name, domains, monthly_quota, member_cap, persistence_years, starts_at, ends_at, active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    ).bind(id, name, domains.join(","), monthlyQuota, memberCap, persistenceYears, startsAt, endsAt, new Date().toISOString()).run();
  } catch {
    return jsonResponse({ error: "Errore interno (id già esistente?)." }, 500);
  }
  return jsonResponse({ id }, 201);
}

async function handleAdminConventionsUpdate(request, env, id) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  if (!SLUG_RE.test(id)) return jsonResponse({ error: "id non valido." }, 400);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Corpo non valido." }, 400); }

  const sets = [], binds = [];
  if (typeof body?.active === "boolean") { sets.push("active = ?"); binds.push(body.active ? 1 : 0); }
  if (body?.name !== undefined) { sets.push("name = ?"); binds.push(String(body.name).trim().slice(0, 200)); }
  if (body?.domains !== undefined) {
    const domains = String(body.domains).split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
    if (!domains.length) return jsonResponse({ error: "Domini non validi." }, 400);
    sets.push("domains = ?"); binds.push(domains.join(","));
  }
  if (body?.monthly_quota !== undefined) {
    const q = Number(body.monthly_quota);
    if (!Number.isInteger(q) || q <= 0) return jsonResponse({ error: "monthly_quota non valida." }, 400);
    sets.push("monthly_quota = ?"); binds.push(q);
  }
  if (body?.member_cap !== undefined) {
    const c = Number(body.member_cap);
    if (!Number.isInteger(c) || c < 0) return jsonResponse({ error: "member_cap non valido." }, 400);
    sets.push("member_cap = ?"); binds.push(c);
  }
  if (body?.ends_at !== undefined) {
    const e = Number(body.ends_at);
    if (!Number.isInteger(e)) return jsonResponse({ error: "ends_at non valido." }, 400);
    sets.push("ends_at = ?"); binds.push(e);
  }
  if (!sets.length) return jsonResponse({ error: "Nessuna modifica specificata." }, 400);
  binds.push(id);

  try {
    await env.DB.prepare(`UPDATE conventions SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run();
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
  return jsonResponse({ ok: true });
}

// Report per fattura/rinnovo: aggregato mensile + membri (visibile SOLO qui,
// nel pannello del gestore — verso l'ente il dato va condiviso in forma
// aggregata, mai l'elenco email→conteggio, salvo accordo scritto).
async function handleAdminConventionsReport(env, id) {
  if (!env?.DB) return jsonResponse({ error: "Servizio non disponibile." }, 503);
  if (!SLUG_RE.test(id)) return jsonResponse({ error: "id non valido." }, 400);
  try {
    const convention = await env.DB.prepare(`SELECT id, name FROM conventions WHERE id = ?`).bind(id).first();
    if (!convention) return jsonResponse({ error: "Convenzione non trovata." }, 404);
    const { results } = await env.DB.prepare(
      `SELECT ym, member_email, COUNT(*) AS count
       FROM convention_attestations WHERE convention_id = ?
       GROUP BY ym, member_email ORDER BY ym DESC, count DESC`
    ).bind(id).all();
    const byMonth = new Map();
    for (const row of results || []) {
      if (!byMonth.has(row.ym)) byMonth.set(row.ym, { ym: row.ym, attestations: 0, members: [] });
      const m = byMonth.get(row.ym);
      m.attestations += row.count;
      m.members.push({ email: row.member_email, count: row.count });
    }
    return jsonResponse({ convention, months: Array.from(byMonth.values()) });
  } catch {
    return jsonResponse({ error: "Errore interno." }, 500);
  }
}

// Pagina statica (nessun dato incorporato: legge tutto via fetch a /admin/api/keys
// con il secret inserito dall'operatore). Il secret sta solo in sessionStorage
// del browser — sparisce alla chiusura della scheda.
function adminPageHtml() {
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin credenziali agente — Spazio Genesi</title>
<meta name="robots" content="noindex">
<style>
  :root { --oro:#8B6914; --bg:#faf8f4; --card:#fff; --ink:#1f1d18; --muted:#6b6453; --line:#e7e1d4; --danger:#a33; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    line-height:1.5; padding:1.5rem; }
  .wrap { max-width:920px; margin:0 auto; }
  h1 { font-size:1.4rem; margin:.2rem 0 1.2rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:1.3rem 1.4rem; margin-bottom:1.2rem; box-shadow:0 1px 3px rgba(0,0,0,.04); }
  label { display:block; font-size:.82rem; color:var(--muted); margin-bottom:.25rem; }
  input { font:inherit; padding:.5rem .6rem; border:1px solid var(--line); border-radius:7px; width:100%; }
  .row { display:flex; gap:.8rem; flex-wrap:wrap; align-items:flex-end; }
  .row > div { flex:1 1 160px; }
  button { font:inherit; font-weight:600; padding:.55rem 1.1rem; border-radius:8px; border:1px solid var(--oro);
    background:var(--oro); color:#fff; cursor:pointer; }
  button.secondary { background:#fff; color:var(--ink); border-color:var(--line); }
  button.danger { background:#fff; color:var(--danger); border-color:var(--danger); }
  button:disabled { opacity:.5; cursor:default; }
  table { border-collapse:collapse; width:100%; font-size:.88rem; }
  th, td { border-bottom:1px solid var(--line); padding:.5rem .5rem; text-align:left; vertical-align:middle; }
  th { color:var(--muted); font-weight:600; font-size:.78rem; text-transform:uppercase; letter-spacing:.02em; }
  .pill { display:inline-block; font-size:.75rem; font-weight:600; padding:.15rem .55rem; border-radius:999px; }
  .pill.ok { background:#eef6ec; color:#2f6b2a; }
  .pill.revoked { background:#f7e9e9; color:var(--danger); }
  .msg { font-size:.85rem; margin-top:.6rem; }
  .msg.err { color:var(--danger); }
  .msg.ok { color:#2f6b2a; }
  .fingerprint { font-family:ui-monospace,Consolas,monospace; font-size:.82rem; word-break:break-all; }
  .newkey { font-family:ui-monospace,Consolas,monospace; font-size:.85rem; background:#fdf6e3;
    border:1px solid var(--oro); padding:.6rem .7rem; border-radius:8px; word-break:break-all; margin-top:.6rem; }
  input[type="number"] { width:5.5rem; }
  .qtybox { display:flex; gap:.4rem; align-items:center; }
  .tabbar { display:flex; gap:.4rem; margin-bottom:1rem; border-bottom:1px solid var(--line); }
  .tabbtn { font:inherit; font-weight:600; padding:.6rem 1rem; border:none; border-bottom:2px solid transparent;
    background:none; color:var(--muted); cursor:pointer; }
  .tabbtn.active { color:var(--oro); border-bottom-color:var(--oro); }
</style>
</head>
<body>
<div class="wrap">
  <h1>Admin credenziali agente <span style="color:var(--muted);font-weight:400;font-size:.9rem;">— Spazio Genesi</span></h1>

  <div class="card" id="loginCard">
    <label for="secretInput">Admin secret</label>
    <div class="row">
      <div><input type="password" id="secretInput" placeholder="X-Admin-Secret" autocomplete="off"></div>
      <div style="flex:0 0 auto;"><button class="secondary" id="toggleSecretBtn" type="button">Mostra</button></div>
      <div style="flex:0 0 auto;"><button id="loginBtn">Entra</button></div>
    </div>
    <p class="msg" id="loginMsg"></p>
  </div>

  <div id="app" style="display:none;">
    <div class="tabbar" role="tablist" aria-label="Sezioni pannello admin">
      <button class="tabbtn active" id="tabBtnKeys" role="tab" aria-selected="true">Chiavi API</button>
      <button class="tabbtn" id="tabBtnConventions" role="tab" aria-selected="false">Convenzioni</button>
    </div>

    <div id="tabKeys">
    <div class="card">
      <h2 style="font-size:1rem;margin:0 0 .8rem;">Nuova API key</h2>
      <div class="row">
        <div><label for="newLabel">Etichetta (partner)</label><input id="newLabel" placeholder="Convenzione Accademia X"></div>
        <div style="flex:0 0 120px;"><label for="newQuota">Quota/mese</label><input id="newQuota" type="number" value="200" min="1"></div>
        <div style="flex:0 0 auto;"><button id="issueBtn">Emetti</button></div>
      </div>
      <p class="msg" id="issueMsg"></p>
      <div class="newkey" id="newKeyBox" style="display:none;"></div>
    </div>

    <div class="card">
      <h2 style="font-size:1rem;margin:0 0 .8rem;">Credenziali esistenti <button class="secondary" id="refreshBtn" style="float:right;">Aggiorna</button></h2>
      <table>
        <thead><tr><th>Etichetta</th><th>Tipo</th><th>Titolare</th><th>Quota</th><th>Usate</th><th>Stato</th><th>Creata</th><th></th></tr></thead>
        <tbody id="keysBody"></tbody>
      </table>
      <p class="msg" id="listMsg"></p>
    </div>
    </div>

    <div id="tabConventions" style="display:none;">
    <div class="card">
      <h2 style="font-size:1rem;margin:0 0 .8rem;">Nuova convenzione</h2>
      <div class="row">
        <div style="flex:0 0 140px;"><label for="cvId">Id (slug)</label><input id="cvId" placeholder="accademia-aq"></div>
        <div><label for="cvName">Nome ente</label><input id="cvName" placeholder="Accademia di Belle Arti dell'Aquila"></div>
      </div>
      <div class="row" style="margin-top:.6rem;">
        <div><label for="cvDomains">Domini email (separati da virgola, senza @)</label><input id="cvDomains" placeholder="studenti.abaq.it, abaq.it"></div>
      </div>
      <div class="row" style="margin-top:.6rem;">
        <div style="flex:0 0 130px;"><label for="cvMonthlyQuota">Pool/mese</label><input id="cvMonthlyQuota" type="number" value="200" min="1"></div>
        <div style="flex:0 0 130px;"><label for="cvMemberCap">Tetto/membro</label><input id="cvMemberCap" type="number" value="50" min="0"></div>
        <div style="flex:0 0 130px;"><label for="cvPersistence">Anni custodia</label><input id="cvPersistence" type="number" value="5" min="1"></div>
      </div>
      <div class="row" style="margin-top:.6rem;">
        <div><label for="cvStarts">Inizio</label><input id="cvStarts" type="date"></div>
        <div><label for="cvEnds">Fine</label><input id="cvEnds" type="date"></div>
        <div style="flex:0 0 auto;"><button id="cvCreateBtn">Crea</button></div>
      </div>
      <p class="msg" id="cvCreateMsg"></p>
    </div>

    <div class="card">
      <h2 style="font-size:1rem;margin:0 0 .8rem;">Convenzioni <button class="secondary" id="cvRefreshBtn" style="float:right;">Aggiorna</button></h2>
      <table>
        <thead><tr><th>Ente</th><th>Domini</th><th>Pool mese</th><th>Membri</th><th>Chiavi</th><th>Stato</th><th></th></tr></thead>
        <tbody id="conventionsBody"></tbody>
      </table>
      <p class="msg" id="cvListMsg"></p>
      <div id="cvReportBox" style="display:none;margin-top:.8rem;">
        <h3 style="font-size:.9rem;margin:0 0 .5rem;">Report <span id="cvReportTitle"></span></h3>
        <div id="cvReportContent" style="font-size:.85rem;"></div>
      </div>
    </div>
    </div>
  </div>
</div>

<script>
(function () {
  var secretKey = "sg_admin_secret";
  var loginCard = document.getElementById("loginCard");
  var app = document.getElementById("app");
  var loginMsg = document.getElementById("loginMsg");

  function getSecret() { return sessionStorage.getItem(secretKey) || ""; }
  function setSecret(v) { sessionStorage.setItem(secretKey, v); }
  function clearSecret() { sessionStorage.removeItem(secretKey); }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "X-Admin-Secret": getSecret() }, opts.headers || {});
    return fetch(path, opts).then(function (res) {
      if (res.status === 403) {
        clearSecret();
        showLogin("Secret non valido o scaduto.");
        throw new Error("unauthorized");
      }
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
        return body;
      });
    });
  }

  function showLogin(msg) {
    loginCard.style.display = "";
    app.style.display = "none";
    loginMsg.textContent = msg || "";
    loginMsg.className = "msg err";
  }

  function showApp() {
    loginCard.style.display = "none";
    app.style.display = "";
    loadKeys();
    loadConventions();
  }

  function showTab(name) {
    var isKeys = name === "keys";
    document.getElementById("tabKeys").style.display = isKeys ? "" : "none";
    document.getElementById("tabConventions").style.display = isKeys ? "none" : "";
    document.getElementById("tabBtnKeys").classList.toggle("active", isKeys);
    document.getElementById("tabBtnKeys").setAttribute("aria-selected", String(isKeys));
    document.getElementById("tabBtnConventions").classList.toggle("active", !isKeys);
    document.getElementById("tabBtnConventions").setAttribute("aria-selected", String(!isKeys));
  }
  document.getElementById("tabBtnKeys").addEventListener("click", function () { showTab("keys"); });
  document.getElementById("tabBtnConventions").addEventListener("click", function () { showTab("conventions"); });

  function fmtDate(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" }); } catch (e) { return iso; }
  }

  function escHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function rowHtml(k) {
    var statusPill = k.revoked
      ? '<span class="pill revoked">revocata</span>'
      : '<span class="pill ok">attiva</span>';
    var kindLabel = k.kind === "key" ? "API key" : "sessione";
    var owner = k.owner_email
      ? escHtml(k.owner_email) + (k.owner_provider ? ' <span style="color:var(--muted);">(' + escHtml(k.owner_provider) + ')</span>' : '')
      : '—';
    var actions = '';
    if (k.kind === "key") {
      actions += '<button class="secondary qty-btn" data-id="' + k.id + '" style="margin-right:.4rem;">Modifica quota</button>';
      if (!k.revoked) actions += '<button class="danger revoke-btn" data-id="' + k.id + '">Revoca</button>';
      if (k.revoked && k.owner_email && k.owner_email !== "(rimosso)") {
        actions += '<button class="secondary forget-btn" data-id="' + k.id + '" style="margin-left:.4rem;">Dimentica titolare</button>';
      }
    } else if (!k.revoked) {
      actions += '<button class="danger revoke-btn" data-id="' + k.id + '">Revoca</button>';
    }
    actions += '<button class="danger delete-btn" data-id="' + k.id + '" data-label="' + escHtml(k.label || k.id) + '" style="margin-left:.4rem;">Elimina</button>';
    return '<tr>' +
      '<td>' + escHtml(k.label || '—') + '</td>' +
      '<td>' + kindLabel + '</td>' +
      '<td>' + owner + '</td>' +
      '<td>' + k.quota + '</td>' +
      '<td>' + k.used + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + fmtDate(k.created_at) + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  function loadKeys() {
    var listMsg = document.getElementById("listMsg");
    listMsg.textContent = "Carico…";
    listMsg.className = "msg";
    api("/admin/api/keys").then(function (data) {
      var body = document.getElementById("keysBody");
      body.innerHTML = (data.keys || []).map(rowHtml).join("") || '<tr><td colspan="7">Nessuna credenziale.</td></tr>';
      listMsg.textContent = "";
      Array.prototype.forEach.call(document.querySelectorAll(".revoke-btn"), function (btn) {
        btn.addEventListener("click", function () {
          if (!confirm("Revocare questa credenziale?")) return;
          api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ revoked: true }) })
            .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "msg err"; });
        });
      });
      Array.prototype.forEach.call(document.querySelectorAll(".qty-btn"), function (btn) {
        btn.addEventListener("click", function () {
          var q = prompt("Nuova quota mensile:");
          if (!q) return;
          api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ quota: parseInt(q, 10) }) })
            .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "msg err"; });
        });
      });
      Array.prototype.forEach.call(document.querySelectorAll(".forget-btn"), function (btn) {
        btn.addEventListener("click", function () {
          if (!confirm("Rimuovere l'email del titolare da questa credenziale? Non si può annullare.")) return;
          api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ forget: true }) })
            .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "msg err"; });
        });
      });
      Array.prototype.forEach.call(document.querySelectorAll(".delete-btn"), function (btn) {
        btn.addEventListener("click", function () {
          if (!confirm('Eliminare DEFINITIVAMENTE la credenziale ' + btn.dataset.label + '? A differenza di Revoca, non si può annullare.')) return;
          api("/admin/api/keys/" + btn.dataset.id, { method: "DELETE" })
            .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "msg err"; });
        });
      });
    }).catch(function (e) {
      if (e.message !== "unauthorized") { listMsg.textContent = e.message; listMsg.className = "msg err"; }
    });
  }

  document.getElementById("loginBtn").addEventListener("click", function () {
    var v = document.getElementById("secretInput").value.trim();
    if (!v) return;
    setSecret(v);
    api("/admin/api/keys").then(function () { showApp(); }).catch(function (e) {
      if (e.message === "unauthorized") return;
      loginMsg.textContent = e.message; loginMsg.className = "msg err";
    });
  });

  document.getElementById("toggleSecretBtn").addEventListener("click", function () {
    var input = document.getElementById("secretInput");
    var showing = input.type === "text";
    input.type = showing ? "password" : "text";
    this.textContent = showing ? "Mostra" : "Nascondi";
  });

  document.getElementById("refreshBtn").addEventListener("click", function (e) { e.preventDefault(); loadKeys(); });

  document.getElementById("issueBtn").addEventListener("click", function () {
    var label = document.getElementById("newLabel").value.trim();
    var quota = parseInt(document.getElementById("newQuota").value, 10);
    var issueMsg = document.getElementById("issueMsg");
    var box = document.getElementById("newKeyBox");
    box.style.display = "none";
    if (!label) { issueMsg.textContent = "Serve un'etichetta."; issueMsg.className = "msg err"; return; }
    issueMsg.textContent = "Emissione…"; issueMsg.className = "msg";
    api("/admin/api/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label: label, quota: quota }) })
      .then(function (data) {
        issueMsg.textContent = "Fatto. Copia la chiave ora — non sarà più recuperabile.";
        issueMsg.className = "msg ok";
        box.textContent = data.key;
        box.style.display = "";
        document.getElementById("newLabel").value = "";
        loadKeys();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { issueMsg.textContent = e.message; issueMsg.className = "msg err"; } });
  });

  // ── P25 (B): Convenzioni ──────────────────────────────────────────────
  function dateToMs(inputId) {
    var v = document.getElementById(inputId).value;
    if (!v) return null;
    return new Date(v + "T00:00:00Z").getTime();
  }

  function cvRowHtml(c) {
    var statusPill = c.active ? '<span class="pill ok">attiva</span>' : '<span class="pill revoked">disattivata</span>';
    var actions = '<button class="secondary cv-report-btn" data-id="' + c.id + '" style="margin-right:.4rem;">Report</button>' +
      '<button class="secondary cv-toggle-btn" data-id="' + c.id + '" data-active="' + (c.active ? '1' : '0') + '">' +
      (c.active ? 'Disattiva' : 'Riattiva') + '</button>';
    return '<tr>' +
      '<td>' + escHtml(c.name) + '<div style="color:var(--muted);font-size:.78rem;">' + escHtml(c.id) + '</div></td>' +
      '<td>' + escHtml(c.domains) + '</td>' +
      '<td>' + c.pool_used_month + ' / ' + c.monthly_quota + '</td>' +
      '<td>' + c.members_this_month + '</td>' +
      '<td>' + c.keys_active + ' / ' + c.keys_total + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  function loadConventions() {
    var listMsg = document.getElementById("cvListMsg");
    listMsg.textContent = "Carico…";
    listMsg.className = "msg";
    api("/admin/api/conventions").then(function (data) {
      var body = document.getElementById("conventionsBody");
      body.innerHTML = (data.conventions || []).map(cvRowHtml).join("") || '<tr><td colspan="7">Nessuna convenzione.</td></tr>';
      listMsg.textContent = "";
      Array.prototype.forEach.call(document.querySelectorAll(".cv-toggle-btn"), function (btn) {
        btn.addEventListener("click", function () {
          var nowActive = btn.dataset.active === "1";
          if (!confirm((nowActive ? "Disattivare" : "Riattivare") + " questa convenzione? Le chiavi già emesse non vengono revocate.")) return;
          api("/admin/api/conventions/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ active: !nowActive }) })
            .then(loadConventions).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "msg err"; });
        });
      });
      Array.prototype.forEach.call(document.querySelectorAll(".cv-report-btn"), function (btn) {
        btn.addEventListener("click", function () { showReport(btn.dataset.id); });
      });
    }).catch(function (e) {
      if (e.message !== "unauthorized") { listMsg.textContent = e.message; listMsg.className = "msg err"; }
    });
  }

  function showReport(id) {
    var box = document.getElementById("cvReportBox");
    var title = document.getElementById("cvReportTitle");
    var content = document.getElementById("cvReportContent");
    box.style.display = "";
    title.textContent = id;
    content.textContent = "Carico…";
    api("/admin/api/conventions/" + id + "/report").then(function (data) {
      title.textContent = data.convention.name + " (" + data.convention.id + ")";
      if (!data.months.length) { content.textContent = "Nessuna emissione registrata."; return; }
      var html = '<table><thead><tr><th>Mese</th><th>Attestazioni</th><th>Membri</th></tr></thead><tbody>';
      data.months.forEach(function (m) {
        html += '<tr><td>' + escHtml(m.ym) + '</td><td>' + m.attestations + '</td><td>' + m.members.length + '</td></tr>';
      });
      html += '</tbody></table>';
      content.innerHTML = html;
    }).catch(function (e) { content.textContent = e.message; });
  }

  document.getElementById("cvRefreshBtn").addEventListener("click", function (e) { e.preventDefault(); loadConventions(); });

  document.getElementById("cvCreateBtn").addEventListener("click", function () {
    var msg = document.getElementById("cvCreateMsg");
    var payload = {
      id: document.getElementById("cvId").value.trim().toLowerCase(),
      name: document.getElementById("cvName").value.trim(),
      domains: document.getElementById("cvDomains").value.trim(),
      monthly_quota: parseInt(document.getElementById("cvMonthlyQuota").value, 10),
      member_cap: parseInt(document.getElementById("cvMemberCap").value, 10),
      persistence_years: parseInt(document.getElementById("cvPersistence").value, 10),
      starts_at: dateToMs("cvStarts"),
      ends_at: dateToMs("cvEnds"),
    };
    if (!payload.id || !payload.name || !payload.domains || !payload.starts_at || !payload.ends_at) {
      msg.textContent = "Compila tutti i campi."; msg.className = "msg err"; return;
    }
    msg.textContent = "Creazione…"; msg.className = "msg";
    api("/admin/api/conventions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then(function () {
        msg.textContent = "Fatto."; msg.className = "msg ok";
        ["cvId", "cvName", "cvDomains"].forEach(function (fid) { document.getElementById(fid).value = ""; });
        loadConventions();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { msg.textContent = e.message; msg.className = "msg err"; } });
  });

  if (getSecret()) {
    api("/admin/api/keys").then(function () { showApp(); }).catch(function () {});
  }
})();
</script>
</body>
</html>`;
}

// ── Documentazione API (OpenAPI + Swagger UI auto-ospitata) ──────────────────
// GET /openapi.json serve lo spec OpenAPI 3.0 (openapi.json nel repo, sorgente
// di verità del contratto machine-readable). GET /docs serve la Swagger UI
// UFFICIALE (swagger-ui-dist, Apache-2.0) — nessun CDN di terze parti, stesso
// principio già seguito per pdf.js. Gli asset (bundle.js, preset.js, css)
// sono Static Assets (public/docs/, vedi [assets] in wrangler.toml), NON
// import in worker.js: un tentativo di importarli come modulo "Text" dava
// contenuto troncato/tipizzato male in wrangler dev per file oltre ~250KB
// (limite/bug del loader). Gli asset statici hanno priorità automatica sul
// Worker per i path che combaciano; /docs stesso resta dinamico (nessun
// index.html in public/docs/, quindi cade qui sotto). Lo spec puntato è
// sempre /openapi.json, stesso dominio — nessuna chiamata a host esterni.
function swaggerUiHtml() {
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API — imgauth</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/docs/swagger-ui.css">
<style>body { margin:0; } .topbar { display:none; }</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="/docs/swagger-ui-bundle.js" charset="UTF-8"></script>
<script src="/docs/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
<script>
window.onload = function () {
  window.ui = SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: "StandaloneLayout",
  });
};
</script>
</body>
</html>`;
}

// ── Entry point ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    // P24: origin CORS per ambiente (staging usa env.ALLOWED_ORIGIN; produzione,
    // senza la var, resta identica alla costante — vedi definizione sopra).
    activeAllowedOrigin = env?.ALLOWED_ORIGIN || ALLOWED_ORIGIN;

    const method = request.method.toUpperCase();
    const url    = new URL(request.url);
    const path   = url.pathname;

    // Preflight CORS — prima di tutto
    if (method === "OPTIONS") {
      return new Response("", { status: 204, headers: corsHeaders() });
    }

    // Rate limiting per-IP, tarato sul costo dell'endpoint (vedi wrangler.toml).
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (method === "POST" && path === "/api/cert-pdf") {
      if (await isRateLimited(env.RL_CERT, ip)) return tooManyResponse();
    } else if (method === "POST" && (path === "/api/hash" || path === "/api/verify" || path === "/api/agent/authorize" || path === "/api/agent/approve")) {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    } else if (method === "GET" && (path === "/api/ots" || path === "/api/cert" || path === "/api/badge" || path === "/api/agent/token")) {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    } else if (method === "GET" && (path === "/developer/keys" || path === "/api/dev/oauth/start" || path.startsWith("/api/dev/oauth/callback/"))) {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    } else if (path.startsWith("/admin/api/")) {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    }

    if (method === "GET"  && path === "/ping")        return handlePing(request);
    if (method === "POST" && path === "/api/hash")     return handleHash(request, env, ctx);
    if (method === "POST" && path === "/api/verify")   return handleVerify(request, env);
    if (method === "POST" && path === "/api/cert-pdf") return handlePdf(request, env, ctx);
    if (method === "GET"  && path === "/api/ots")      return handleOts(url, env);
    if (method === "GET"  && path === "/api/cert")     return handleCert(url, env);
    if (method === "GET"  && path === "/api/badge")    return handleBadge(url, env);
    if (method === "GET"  && path === "/api/status")   return withPublicCors(await handleStatus(env, ctx));
    if (method === "GET"  && path === "/api/status-history") return withPublicCors(await handleStatusHistory(env, ctx));
    if (method === "GET"  && path === "/api/health-log") return withPublicCors(await handleHealthLog(url, env));
    if (method === "GET"  && path.startsWith("/c/"))   return handleCertPage(path, env);
    if (method === "POST" && path === "/api/agent/authorize") return handleAgentAuthorize(env);
    if (method === "POST" && path === "/api/agent/approve")   return handleAgentApprove(request, env, ctx);
    if (method === "GET"  && path === "/api/agent/token")     return handleAgentToken(url, env);
    if (method === "GET"  && path === "/agent/authorize")     return handleAgentAuthorizePage(url, env);
    if (method === "GET"  && path === "/developer/keys")      return htmlResponse(devKeysPageHtml(env));
    if (method === "GET"  && path === "/api/dev/oauth/start") return handleDevOAuthStart(url, env);
    if (method === "GET"  && path.startsWith("/api/dev/oauth/callback/")) {
      const provider = path.slice("/api/dev/oauth/callback/".length);
      return handleDevOAuthCallback(url, provider, env, ctx);
    }
    if (method === "GET"  && path === "/openapi.json")          return withPublicCors(jsonResponse(openapiSpec));
    if (method === "GET"  && path === "/docs")                  return htmlResponse(swaggerUiHtml());
    if (method === "GET"  && path === "/admin")                return htmlResponse(adminPageHtml());
    if (method === "GET"  && path === "/admin/api/keys")       return (await verifyAdminSecret(request, env)) ? handleAdminKeysList(env) : adminUnauthorized();
    if (method === "POST" && path === "/admin/api/keys")       return (await verifyAdminSecret(request, env)) ? handleAdminKeysIssue(request, env) : adminUnauthorized();
    if (method === "PATCH" && path.startsWith("/admin/api/keys/")) {
      const id = path.slice("/admin/api/keys/".length);
      return (await verifyAdminSecret(request, env)) ? handleAdminKeysUpdate(request, env, id) : adminUnauthorized();
    }
    if (method === "DELETE" && path.startsWith("/admin/api/keys/")) {
      const id = path.slice("/admin/api/keys/".length);
      return (await verifyAdminSecret(request, env)) ? handleAdminKeysDelete(env, id) : adminUnauthorized();
    }
    if (method === "GET"  && path === "/admin/api/conventions") return (await verifyAdminSecret(request, env)) ? handleAdminConventionsList(env) : adminUnauthorized();
    if (method === "POST" && path === "/admin/api/conventions") return (await verifyAdminSecret(request, env)) ? handleAdminConventionsCreate(request, env) : adminUnauthorized();
    if (method === "GET"  && path.startsWith("/admin/api/conventions/") && path.endsWith("/report")) {
      const id = path.slice("/admin/api/conventions/".length, -"/report".length);
      return (await verifyAdminSecret(request, env)) ? handleAdminConventionsReport(env, id) : adminUnauthorized();
    }
    if (method === "PATCH" && path.startsWith("/admin/api/conventions/")) {
      const id = path.slice("/admin/api/conventions/".length);
      return (await verifyAdminSecret(request, env)) ? handleAdminConventionsUpdate(request, env, id) : adminUnauthorized();
    }

    return jsonResponse({ error: "Endpoint non trovato", path }, 404);
  },

  // Cron trigger (vedi wrangler.toml › [triggers]): campiona lo stato e aggiorna
  // il rollup giornaliero in R2, così la pagina /status ha dati anche senza visite;
  // spazza anche le righe scadute del device flow agenti (P21).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sampleAndRecord(env).catch(() => {}));
    ctx.waitUntil(sweepExpiredAgentRows(env).catch(() => {}));
  },
};

// ── /ping ────────────────────────────────────────────────────────────────────

function handlePing(request) {
  return jsonResponse({ ok: true, version: APP_VERSION, origin: request.headers.get("Origin") });
}

// ── /api/hash ────────────────────────────────────────────────────────────────

async function handleHash(request, env, ctx) {
  try {
    const data       = await request.json();
    const b64        = data.image;   // percorso legacy: file inline (pre-1.15.0)
    const clientHash = data.sha256;  // percorso primario: impronta calcolata sul client
    const name       = data.name  ?? "opera";
    const mime       = data.type  ?? "application/octet-stream";

    if (!b64 && !clientHash) {
      return jsonResponse({ error: "Campo 'sha256' (o 'image') mancante." }, 400);
    }

    // Pre-check economico del formato (percorso client): un hash malformato non
    // deve costare una challenge Turnstile né, dalla P21, una quota agente —
    // il ricalcolo pieno più sotto resta invariato. Il percorso legacy (`image`)
    // non è toccato: il decode+hash costoso resta dopo Turnstile, come prima.
    if (!b64 && !HEX64.test(String(clientHash).trim())) {
      return jsonResponse({ error: "Campo 'sha256' malformato (attesi 64 caratteri esadecimali)." }, 400);
    }

    // ── Autenticazione agenti (bearer, opzionale — vedi P21) ────────────────
    // Una credenziale valida bypassa SOLO la challenge Turnstile qui sotto:
    // timestamp server, HMAC e rate-limit per-IP restano invariati. Nessun
    // header → percorso Turnstile identico a prima (agentAuth resta null).
    const agentAuth = await authenticateAgent(request, env, ctx);
    if (agentAuth && agentAuth.error) {
      return jsonResponse({ error: agentAuth.error }, agentAuth.status);
    }

    // ── Voucher "attesta con la tua email" (P25 §2.7, solo se non c'è già un
    // bearer valido) ────────────────────────────────────────────────────────
    // Stesso principio di bypass delle credenziali agente: l'OAuth one-shot è
    // una barriera più forte del Turnstile. Header presente ma non valido
    // (firma rotta o scaduto) → fail-closed, mai un fallback silenzioso al
    // percorso Turnstile (coerente con l'invariante 1 del design P21/P25).
    let voucherAuth = null;
    if (!agentAuth) {
      const voucherToken = request.headers.get("X-SG-Voucher") || "";
      if (voucherToken) {
        const payload = await verifyVoucher(env, voucherToken);
        if (!payload) {
          return jsonResponse({ error: "voucher_scaduto" }, 403);
        }
        // Il voucher NON è fonte di verità sullo stato della convenzione:
        // rilettura fresca da D1 a ogni uso (può essere stata disattivata
        // dopo l'emissione del voucher).
        const conv = await matchConvention(env, payload.email);
        voucherAuth = { email: payload.email, conventionId: conv ? conv.id : null };
      }
    }

    // ── Anti-bot Turnstile ─────────────────────────────────────────────────────
    // La challenge è qui, all'emissione dell'attestazione: nessun token HMAC viene
    // rilasciato (né per il .txt né per il PDF) senza un umano verificato — o,
    // dalla P21, senza una credenziale agente valida (agentAuth.ok), o dalla
    // P25, senza un voucher email valido (voucherAuth).
    // Fail-open se siteverify è irraggiungibile: è l'endpoint primario e un
    // disservizio Turnstile non deve impedire il calcolo dell'hash.
    if (!agentAuth && !voucherAuth && env?.TURNSTILE_SECRET) {
      const tsToken = String(data.turnstile_token ?? "");
      if (!tsToken) {
        return jsonResponse({ error: "Verifica anti-bot mancante." }, 400);
      }
      let human;
      try {
        human = await verifyTurnstile(env.TURNSTILE_SECRET, tsToken, request.headers.get("CF-Connecting-IP") || undefined);
      } catch {
        human = true; // siteverify irraggiungibile → non bloccare il servizio primario
      }
      if (!human) {
        return jsonResponse({ error: "Verifica anti-bot non superata. Riprova." }, 403);
      }
    }

    let digest, size;
    if (b64) {
      // ── Percorso legacy: il file arriva inline, l'hash lo calcola il server ──
      // Tetto di dimensione (difesa DoS/memoria): scarta payload oltre il limite
      // prima ancora di decodificarlo. base64 ≈ 4/3 dei byte grezzi.
      if (typeof b64 !== "string" || b64.length > Math.ceil(MAX_BYTES / 3) * 4 + 64) {
        return jsonResponse({ error: "File troppo grande (max 100 MB)." }, 413);
      }

      // Decodifica base64 → ArrayBuffer
      const raw = base64ToBytes(b64);
      if (raw.byteLength > MAX_BYTES) {
        return jsonResponse({ error: "File troppo grande (max 100 MB)." }, 413);
      }

      const hashBuf = await crypto.subtle.digest("SHA-256", raw);
      digest = bufToHex(hashBuf);
      size   = raw.byteLength;
    } else {
      // ── Percorso primario (1.15.0): impronta calcolata sul client ────────────
      // Il file non lascia mai il dispositivo dell'utente. Il server attesta
      // l'esistenza dell'impronta all'istante del SUO timestamp: la garanzia
      // anti-retrodatazione resta intatta (timestamp + HMAC nascono qui).
      // Ciò che il server smette di verificare è che l'impronta derivi da byte
      // reali — irrilevante per la proof-of-existence: un'impronta inventata
      // non è la preimmagine di nulla e produce un certificato inutilizzabile,
      // mentre dimensione e MIME erano già campi descrittivi non vincolati.
      digest = String(clientHash).trim().toLowerCase();
      if (!HEX64.test(digest)) {
        return jsonResponse({ error: "Campo 'sha256' malformato (attesi 64 caratteri esadecimali)." }, 400);
      }
      const declaredSize = Number(data.size);
      size = Number.isFinite(declaredSize) && declaredSize >= 0 ? Math.floor(declaredSize) : null;
    }

    // Timestamp UTC
    const now      = new Date();
    const tsIso    = now.toISOString().replace(/\.\d{3}Z$/, "Z");
    const tsHuman  = humanTs(now);

    const attestazione = `SHA-256:${digest}@${tsIso}`;
    const issuer       = "Spazio Genesi ETS — Attestazione Opere";

    // Metadati dichiarati (facoltativi): normalizzati qui e VINCOLATI al token
    // HMAC, così non sono alterabili dopo l'emissione. Restituiti nella risposta
    // nella forma canonica firmata (il client li round-trippa a /api/cert-pdf).
    const meta = extractMeta(data);

    // HMAC opzionale
    let hmacSig = null;
    if (env?.HMAC_SECRET) {
      hmacSig = await signHmac(env.HMAC_SECRET, hmacMessage(attestazione, meta));
    }

    // ── P25 (B)+(C): fascia + contabilità convenzione ───────────────────────
    // Stessa timing della quota individuale (authenticateAgent): l'emissione
    // dell'attestazione è il momento in cui il "consumo" avviene, non la
    // successiva generazione del PDF. Nessuna credenziale/voucher → fascia
    // Base (percorso anonimo); chiave senza convenzione → Sviluppatore;
    // voucher senza convenzione → Base (nessun vantaggio proprio, il canale
    // da solo non dà fascia — vedi §2.7 design); chiave O voucher con
    // convenzione → pool/tetto individuale via accountConventionUsage, mai
    // un blocco: esaurito uno dei due argini, l'emissione degrada
    // silenziosamente a Base con motivo esplicito (mai negata, vedi §1).
    let fascia = "base";
    let fasciaMotivo = null;
    let convenzioneInfo = null;
    if (agentAuth && agentAuth.ok) {
      fascia = "sviluppatore";
      if (agentAuth.conventionId) {
        const acc = await accountConventionUsage(env, ctx, {
          conventionId: agentAuth.conventionId,
          memberEmail:  agentAuth.ownerEmail,
          credentialId: agentAuth.id,
          via:          "key",
          sha256:       digest,
        });
        if (acc.fascia) {
          fascia = acc.fascia;
          fasciaMotivo = acc.fasciaMotivo;
          convenzioneInfo = acc.convenzioneInfo;
        }
      }
    } else if (voucherAuth) {
      fascia = "base";
      if (voucherAuth.conventionId) {
        const acc = await accountConventionUsage(env, ctx, {
          conventionId: voucherAuth.conventionId,
          memberEmail:  voucherAuth.email,
          credentialId: null,
          via:          "site",
          sha256:       digest,
        });
        if (acc.fascia) {
          fascia = acc.fascia;
          fasciaMotivo = acc.fasciaMotivo;
          convenzioneInfo = acc.convenzioneInfo;
        }
      }
    }

    return jsonResponse({
      opera:               name,
      dimensione_bytes:    size,
      tipo_mime:           mime,
      ...meta,
      sha256:              digest,
      timestamp_iso:       tsIso,
      timestamp_leggibile: tsHuman,
      attestazione,
      emesso_da:           issuer,
      hmac:                hmacSig,
      fascia,
      fascia_motivo:       fasciaMotivo,
      convenzione:         convenzioneInfo,
    });
  } catch {
    return jsonResponse({ error: "Errore interno del server." }, 500);
  }
}

// ── /api/verify ──────────────────────────────────────────────────────────────

async function handleVerify(request, env) {
  try {
    const form        = await request.formData();
    const file        = form.get("image");
    const claimed     = form.get("hash");
    const attestazione = form.get("attestazione");
    const hmacClaimed  = form.get("hmac");

    if (!claimed) {
      return jsonResponse({ error: "Richiesto 'hash'." }, 400);
    }

    // Il file è FACOLTATIVO (dalla 1.15.0): il client full-privacy confronta
    // hash e file in locale e chiede qui solo la verifica della firma HMAC.
    // Se il file c'è (client legacy/diretti), l'hash si ricalcola come prima.
    let digest = null;
    if (file && typeof file.arrayBuffer === "function") {
      const raw     = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest("SHA-256", raw);
      digest = bufToHex(hashBuf);
    }
    const normalized = String(claimed).trim().toLowerCase();

    let hmac_valido = null;
    if (attestazione && hmacClaimed && env?.HMAC_SECRET) {
      // Se il certificato riportava dati dichiarati (titolo, autore, …) la firma
      // li copre: vanno forniti identici per la verifica. Senza, il messaggio
      // coincide con la sola attestazione (compatibile coi certificati storici).
      const meta = extractMeta({
        titolo: form.get("titolo"),
        autore: form.get("autore"),
        anno:   form.get("anno"),
        note:   form.get("note"),
      });
      const message = hmacMessage(String(attestazione).trim(), meta);
      hmac_valido = await verifyHmac(env.HMAC_SECRET, message, String(hmacClaimed).trim());
    }

    return jsonResponse({
      hash_dichiarato: normalized,
      hash_calcolato:  digest,                              // null se il file non è stato inviato
      coincide:        digest ? digest === normalized : null, // null = confronto fatto sul client
      hmac_valido,
    });
  } catch {
    return jsonResponse({ error: "Errore interno del server." }, 500);
  }
}

// ── /api/cert-pdf ─────────────────────────────────────────────────────────────

function certFilenameStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

async function fillCertificatePdf(d, meta, otsUrl) {
  const doc = await PDFDocument.load(certTemplatePdf);
  const form = doc.getForm();

  form.getTextField("TITOLO").setText(String(d.opera ?? ""));
  form.getTextField("DIMENSIONE").setText(String(d.dimensione_bytes ?? ""));
  form.getTextField("MIME").setText(String(d.tipo_mime ?? ""));
  form.getTextField("SHA-256").setText(String(d.sha256 ?? ""));
  form.getTextField("TIMEISO").setText(String(d.timestamp_iso ?? ""));
  form.getTextField("TIMELEG").setText(String(d.timestamp_leggibile ?? ""));

  // Il box ATTESTAZIONE del template è alto ~32pt (≈3 righe a font 9): contiene
  // SOLO etichetta + stringa. Le righe che in passato vi venivano accodate
  // (firma HMAC, emesso da, versione) risultavano TAGLIATE e invisibili: oggi
  // vivono nel blocco "Dettagli tecnici" disegnato a runtime in fondo pagina.
  const attestField = form.getTextField("ATTESTAZIONE");
  attestField.enableMultiline();
  attestField.setText(`Stringa di attestazione:\n${String(d.attestazione ?? "")}`);

  form.flatten();

  // ── QR code dinamico ────────────────────────────────────────────────────────
  // Copre il QR statico del template (Im0: x=438.1 y=673.7 79.4×79.4 pt)
  // e disegna il nuovo QR come rettangoli vettoriali con pdf-lib.
  // Il QR apre la PAGINA di verifica permanente /c/<hash> (impronta, data,
  // ancoraggio, QR, + pulsante "verifica col file"): superset della vecchia
  // destinazione ?hash=, che resta nel link testuale del footer.
  const page = doc.getPages()[0];
  const verifyUrl  = `${CERT_PAGE_BASE}?hash=${d.sha256 ?? ""}`;
  const certPageUrl = `${CERT_PAGE_BASE}/c/${d.sha256 ?? ""}`;
  const QR_X = 438.1, QR_Y = 666.0, QR_SIZE = 100;

  const qr = encodeQR(certPageUrl, { ecc: "L" });
  const mod = QR_SIZE / qr.size;

  // Quiet zone + copertura QR statico
  page.drawRectangle({ x: QR_X - 3, y: QR_Y - 3, width: QR_SIZE + 6, height: QR_SIZE + 6, color: rgb(1, 1, 1), borderWidth: 0 });
  for (let row = 0; row < qr.size; row++) {
    for (let col = 0; col < qr.size; col++) {
      if (qr.data[row][col]) {
        page.drawRectangle({
          x: QR_X + col * mod,
          y: QR_Y + (qr.size - 1 - row) * mod,
          width: mod,
          height: mod,
          color: rgb(0, 0, 0),
        });
      }
    }
  }

  // ── Footer: indirizzo + URL di verifica ─────────────────────────────────────
  // I testi ERRATI ereditati dal template originale (vecchio indirizzo "Centro
  // Commerciale L'Aquilone" e URL "…workers.dev") sono stati rimossi UNA VOLTA dal
  // content stream del template con scripts/patch-template.mjs. Qui ridisegniamo i
  // testi corretti nelle stesse coordinate/colori/corpo del template (Times 7pt).
  // Niente rettangoli di copertura: è testo normale, selezionabile e copia-incollabile.
  const font   = await doc.embedFont(StandardFonts.TimesRoman);
  const grigio = rgb(0.478, 0.439, 0.376); // colore testo grigio del footer template
  const oro    = rgb(0.545, 0.412, 0.078); // colore "oro" dei link/accent del template
  const pageW  = page.getWidth();          // 595.276 pt (A4)

  // Helper: disegna testo centrato orizzontalmente sulla pagina
  const drawCentered = (text, y, size, color) => {
    const w = font.widthOfTextAtSize(text, size);
    page.drawText(text, { x: (pageW - w) / 2, y, size, font, color });
  };

  // Dati dell'ente su due righe: C.F., iscrizione RUNTS e sede legale (Roma),
  // poi sede operativa (L'Aquila). La riga inferiore scende a y=296.5 per non
  // toccare il credito "Realizzato da tangram" del template (~y 285).
  // Larghezze @7pt Times: riga 1 = 441.8pt, riga 2 = 431.2pt (utile ~505pt).
  drawCentered(
    "Spazio Genesi ETS — Codice fiscale 96602450585 — RUNTS rep. n. 174701 (15/06/2026) — Sede legale: Via Francesco Caracciolo 14, 00167 Roma (RM)",
    306.5, 7, grigio
  );
  drawCentered(
    "Sede operativa: Galleria Commerciale Via Roma 215, primo piano, L'Aquila (AQ) — Documento generato automaticamente, non richiede firma manuale.",
    296.5, 7, grigio
  );

  // URL nel footer: la pagina di verifica con l'hash già precompilato (stessa
  // destinazione del QR). Chi copia o clicca il link atterra sulla verifica con
  // l'impronta inserita, senza doverla digitare a mano.
  drawCentered(verifyUrl, 324.358, 7, oro);

  // ── Blocchi in fondo pagina ─────────────────────────────────────────────────
  // Lo spazio libero sotto il credito "tangram" (~y 280) fino al bordo ospita:
  //  1. "Dati dichiarati dall'autore" — leggibile (8pt, scuro): titolo/autore/
  //     anno/note. Il box AcroForm DATI DELL'OPERA del template è fisso (solo
  //     file/dimensione/MIME), quindi i dati dichiarati vivono qui, ben visibili.
  //  2. "Dettagli tecnici" — fine print (6.5pt grigio): firma HMAC, emittente,
  //     versione motore, nome file, link sito.
  // A-capo a misura di parola; le parole oltre-larghezza vengono spezzate.
  const BLOCK_X = 56.4, BLOCK_W = 482.3;
  const nero = rgb(0.12, 0.12, 0.12); // testo scuro leggibile per i dati dichiarati
  let blockY = 270;
  const drawWrapped = (text, size, color) => {
    let line = "";
    const flush = () => {
      if (!line) return;
      page.drawText(line, { x: BLOCK_X, y: blockY, size, font, color });
      blockY -= size * 1.35;
      line = "";
    };
    for (let word of text.split(" ")) {
      while (font.widthOfTextAtSize(word, size) > BLOCK_W) {
        flush();
        let cut = word.length;
        while (cut > 1 && font.widthOfTextAtSize(word.slice(0, cut), size) > BLOCK_W) cut--;
        line = word.slice(0, cut); flush();
        word = word.slice(cut);
      }
      const candidate = line ? `${line} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) > BLOCK_W) { flush(); line = word; }
      else line = candidate;
    }
    flush();
  };

  // 1) Dati dichiarati dall'autore — leggibili, solo se presenti
  const hasDeclared = meta && (meta.titolo || meta.autore || meta.anno || meta.note);
  if (hasDeclared) {
    drawWrapped("Dati dichiarati dall'autore", 8.5, oro);
    blockY -= 2;
    if (meta.titolo) drawWrapped(`Titolo: ${meta.titolo}`, 8, nero);
    if (meta.autore) drawWrapped(`Autore: ${meta.autore}`, 8, nero);
    if (meta.anno)   drawWrapped(`Anno/versione: ${meta.anno}`, 8, nero);
    if (meta.note)   drawWrapped(`Note: ${meta.note}`, 8, nero);
    drawWrapped("Dati forniti dall'autore al momento dell'attestazione e vincolati alla firma HMAC: non modificabili dopo l'emissione. Non costituiscono prova di paternità dell'opera.", 6.5, grigio);
    blockY -= 5;
  }

  // 2) Dettagli tecnici — fine print
  drawWrapped("Dettagli tecnici", 7.5, oro);
  blockY -= 1;
  if (d.hmac) drawWrapped(`Firma HMAC (server): ${String(d.hmac)}`, 6.5, grigio);
  drawWrapped(`Emesso da: ${String(d.emesso_da ?? "Spazio Genesi ETS — Attestazione Opere")} — Motore: imgauth v${APP_VERSION} — File: ${String(d.opera ?? "")}`, 6.5, grigio);
  // Pagina permanente di verifica online: stessa impronta, consultabile da chiunque
  // riceva il certificato (impronta, data, algoritmo, ancoraggio OTS, QR).
  drawWrapped(`Certificato verificabile online: ${CERT_PAGE_BASE}/c/${d.sha256 ?? ""}`, 6.5, oro);
  if (otsUrl) {
    drawWrapped(`Ancoraggio blockchain (OpenTimestamps, Bitcoin): prova scaricabile da ${otsUrl} — verifica su https://opentimestamps.org`, 6.5, grigio);
  }
  drawWrapped("Sito dell'associazione: https://spaziogenesi.org", 6.5, oro);

  const bytes = await doc.save();
  return new Uint8Array(bytes);
}

// P25 (B): lookup READ-ONLY della credenziale bearer, usato SOLO per taggare
// la fascia nel sidecar /c/<hash> — a differenza di authenticateAgent non
// tocca `used` né fa controlli di quota (già applicati a /api/hash, che è il
// momento reale del "consumo"; qui servirebbe solo a duplicarli). Verifica
// comunque il secret (constant-time): un Authorization header non deve poter
// rivendicare una convenzione senza possedere davvero la credenziale.
async function peekAgentCredential(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ") || !env?.DB) return null;
  const token = auth.slice("Bearer ".length).trim();
  const m = BEARER_RE.exec(token);
  if (!m) return null;
  const [, kindLetter, id, secret] = m;
  const kind = kindLetter === "k" ? "key" : "session";
  let row;
  try {
    row = await env.DB.prepare(
      `SELECT id, kind, secret_hash, revoked, convention_id FROM agent_credentials WHERE id = ?`
    ).bind(id).first();
  } catch { return null; }
  if (!row || row.kind !== kind || row.revoked) return null;
  const secretHash = await sha256Hex(secret);
  if (!timingSafeEqualHex(secretHash, row.secret_hash)) return null;
  return { id: row.id, conventionId: row.convention_id || null };
}

// Equivalente di peekAgentCredential per il voucher dal sito (P25 §2.7): sola
// lettura, nessun consumo di quota (già applicato in handleHash). Rilegge la
// convenzione fresca da D1, stesso principio di verifyVoucher in handleHash.
async function peekVoucherConvention(request, env) {
  const token = request.headers.get("X-SG-Voucher") || "";
  if (!token) return null;
  const payload = await verifyVoucher(env, token);
  if (!payload) return null;
  const conv = await matchConvention(env, payload.email);
  return { conventionId: conv ? conv.id : null };
}

async function handlePdf(request, env, ctx) {
  try {
    const d = await request.json();

    // ── Autenticità del contenuto ────────────────────────────────────────────
    // Il certificato può essere emesso SOLO a partire da un'attestazione
    // realmente prodotta da /api/hash: verifichiamo il token HMAC che lega
    // hash + timestamp al segreto del server. Senza questo controllo chiunque
    // potrebbe far firmare crittograficamente contenuti arbitrari (hash falsi,
    // date retrodatate), svuotando di valore probatorio l'intero servizio.
    if (!env?.HMAC_SECRET) {
      return jsonResponse({ error: "Servizio non configurato per l'emissione di certificati." }, 503);
    }
    const sha256 = String(d.sha256 ?? "");
    const tsIso  = String(d.timestamp_iso ?? "");
    const attest = String(d.attestazione ?? "");
    const hmac   = String(d.hmac ?? "");

    if (!HEX64.test(sha256) || !ISO_TS.test(tsIso) || !attest || !hmac) {
      return jsonResponse({ error: "Attestazione incompleta o malformata." }, 400);
    }
    // L'attestazione firmata deve corrispondere ESATTAMENTE ai campi hash e
    // timestamp che finiranno stampati sul certificato: così il token non può
    // essere riusato con un hash o una data diversi da quelli che ha autenticato.
    if (attest !== `SHA-256:${sha256}@${tsIso}`) {
      return jsonResponse({ error: "Attestazione non coerente con hash e timestamp." }, 400);
    }
    // I metadati dichiarati entrano nel messaggio firmato: un titolo o un autore
    // diversi da quelli autenticati da /api/hash invalidano la firma → 403.
    const meta = extractMeta(d);
    const tokenOk = await verifyHmac(env.HMAC_SECRET, hmacMessage(attest, meta), hmac);
    if (!tokenOk) {
      return jsonResponse({ error: "Firma dell'attestazione non valida: certificato non emettibile." }, 403);
    }
    // Anti-bot: la challenge Turnstile è a monte, su /api/hash. Qui il token HMAC
    // garantisce già che l'attestazione provenga da una sessione umana verificata;
    // il costo è ulteriormente limitato dal rate-limit per-IP (RL_CERT).

    // Ancoraggio blockchain PRIMA di costruire il PDF: così l'URL della prova
    // viene stampato solo se la prova esiste davvero. Fail-open: senza calendar
    // il certificato esce comunque, semplicemente senza la riga OpenTimestamps.
    const otsUrl = await ensureOtsProof(sha256, env);

    const pdfBytes = await fillCertificatePdf(d, meta, otsUrl);

    let finalBytes = pdfBytes;

    if (env?.SIGNER_URL) {
      const signHeaders = { "Content-Type": "application/pdf" };
      if (env?.SIGN_SECRET) signHeaders["X-Sign-Secret"] = env.SIGN_SECRET;
      // Timeout esplicito (a differenza dell'health check, qui una connessione
      // che resta appesa durante un riavvio Azure non deve lasciare l'utente
      // in attesa indefinita): 20s, generoso per un cold-start reale ma limitato.
      const signRes = await fetchWithTimeout(env.SIGNER_URL, 20000, {
        method: "POST",
        headers: signHeaders,
        body: pdfBytes,
      });
      if (!signRes || !signRes.ok) {
        // Non propagare mai il corpo grezzo di authart al client: durante un
        // deploy Azure (redeploy, riavvio, cold-start rotto) può essere una
        // pagina HTML della piattaforma o un traceback interno — incomprensibile
        // e potenzialmente rumoroso. Il dettaglio resta nei log del Worker
        // (visibile via wrangler tail), il chiamante vede solo un messaggio
        // onesto e azionabile. 503 (non 502): l'invito è "riprova", non un
        // errore del client.
        const msg = signRes ? await signRes.text().catch(() => String(signRes.status)) : "nessuna risposta (timeout o connessione rifiutata)";
        console.error("[signer error]", signRes ? signRes.status : "no-response", msg.slice(0, 500));
        return jsonResponse({
          error: "Firma del certificato temporaneamente non disponibile (aggiornamento della piattaforma in corso). Riprova tra qualche minuto.",
        }, 503);
      }
      finalBytes = new Uint8Array(await signRes.arrayBuffer());
    }

    // Chiave R2 con l'hash come prefisso: rende il certificato recuperabile da
    // GET /api/cert?hash= (recupero certificato smarrito). I certificati emessi
    // prima di questo schema (pdf/certificato_<stamp>.pdf) restano in archivio
    // ma non sono indicizzati per hash.
    const stamp = certFilenameStamp();
    const key = `pdf/${sha256.toLowerCase()}/certificato_${stamp}.pdf`;

    if (env?.PDF_ARCHIVE) {
      await env.PDF_ARCHIVE.put(key, finalBytes, {
        httpMetadata: { contentType: "application/pdf" },
      });
      // Sidecar JSON per la pagina pubblica /c/<hash> (handleCertPage): solo i dati
      // già stampati e vincolati. Best-effort e idempotente — scritto SOLO alla
      // prima emissione, così la pagina riflette la data più antica (coerente con
      // /api/cert e la prova .ots). Un errore qui non compromette l'emissione.
      // P25 (B)+(C): tier ricalcolato dalla credenziale bearer O dal voucher
      // inviati su QUESTA richiesta (peekAgentCredential/peekVoucherConvention,
      // sola lettura) — mai da un campo `fascia` nel JSON del client, stesso
      // principio del token HMAC. Approssimazione nota: riflette l'appartenenza
      // STATICA della credenziale/voucher alla convenzione, non l'esito
      // pool/tetto calcolato al momento di /api/hash (quello resta la fonte
      // di verità per contabilità e log).
      const cred = await peekAgentCredential(request, env);
      let tier, tierConventionId;
      if (cred) {
        tier = cred.conventionId ? "convenzione" : "sviluppatore";
        tierConventionId = cred.conventionId || null;
      } else {
        const voucherConv = await peekVoucherConvention(request, env);
        tier = voucherConv?.conventionId ? "convenzione" : "base";
        tierConventionId = voucherConv?.conventionId || null;
      }
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(writeCertMeta(env, sha256.toLowerCase(), d, meta, tier, tierConventionId));
      }
    }

    // Notifica Telegram "nuovo certificato" (post-risposta, fail-safe): non blocca
    // né fa fallire l'emissione. Vedi notifyCertProduced / env CERT_NOTIFY_EVERY.
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(notifyCertProduced(env, sha256, meta, d.timestamp_leggibile));
    }

    return pdfResponse(finalBytes);
  } catch {
    return jsonResponse({ error: "Errore interno durante la generazione del certificato." }, 500);
  }
}

// ── Utility: base64 → Uint8Array ─────────────────────────────────────────────

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// ── Utility: ArrayBuffer → hex string ────────────────────────────────────────

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Utility: timestamp leggibile in italiano ──────────────────────────────────

function humanTs(d) {
  const day  = String(d.getUTCDate()).padStart(2, "0");
  const mon  = MONTHS_IT[d.getUTCMonth() + 1];
  const year = d.getUTCFullYear();
  const hh   = String(d.getUTCHours()).padStart(2, "0");
  const mm   = String(d.getUTCMinutes()).padStart(2, "0");
  const ss   = String(d.getUTCSeconds()).padStart(2, "0");
  return `${day} ${mon} ${year} — ${hh}:${mm}:${ss} UTC`;
}

// ── Utility: HMAC-SHA256 con Web Crypto ───────────────────────────────────────

async function signHmac(secret, message) {
  const enc    = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", keyMat, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
}

async function verifyHmac(secret, message, sigBase64) {
  const enc    = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["verify"]
  );
  const sigBytes = Uint8Array.from(atob(sigBase64), c => c.charCodeAt(0));
  return crypto.subtle.verify("HMAC", keyMat, sigBytes, enc.encode(message));
}

// ── OpenTimestamps ────────────────────────────────────────────────────────────
// Prova di esistenza decentralizzata: l'hash dell'opera viene ancorato in
// Bitcoin tramite i calendar server pubblici del protocollo OpenTimestamps
// (gratuiti, nessuna criptovaluta da gestire). La prova .ots emessa qui è
// "pending": matura in poche ore con la conferma on-chain ed è verificabile
// (e aggiornabile) da chiunque su https://opentimestamps.org o col client ots.
// Terza àncora indipendente accanto a firma HMAC e marca temporale TSA.

// I quattro calendar pubblici di default del client OpenTimestamps. Più calendar =
// più ridondanza: la prova è valida con UNA sola risposta (fail-open), quindi serve
// che cadano TUTTI insieme perché un'attestazione resti senza àncora. La .ots con
// più rami è regolare (più conferme indipendenti).
const OTS_CALENDARS = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.opentimestamps.org",
  "https://btc.calendar.catallaxy.com",
];

// Timeout per la singola POST a un calendar in emissione: interrogati in parallelo,
// così un calendar lento/appeso non blocca né rallenta l'emissione del certificato.
const OTS_SUBMIT_TIMEOUT = 8000;

// \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94
const OTS_MAGIC = new Uint8Array([
  0x00,0x4f,0x70,0x65,0x6e,0x54,0x69,0x6d,0x65,0x73,0x74,0x61,0x6d,0x70,0x73,
  0x00,0x00,0x50,0x72,0x6f,0x6f,0x66,0x00,0xbf,0x89,0xe2,0xe8,0x84,0xe8,0x92,0x94,
]);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// varuint LEB128 a 7 bit (bit alto = continuazione), come da serializzazione OTS
function otsVaruint(n) {
  const out = [];
  while (n > 0x7f) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return new Uint8Array(out);
}

const otsVarbytes = (b) => concatBytes(otsVaruint(b.length), b);

// Crea la prova .ots per un digest sha256 (hex). Come il client ufficiale,
// ai calendar non si invia il digest nudo ma sha256(digest‖nonce): privacy.
// Ritorna null se nessun calendar risponde (fail-open a carico del chiamante).
async function createOtsProof(sha256hex) {
  const digest = hexToBytes(sha256hex);
  const nonce  = crypto.getRandomValues(new Uint8Array(16));
  const m1 = new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(digest, nonce)));

  // Interroga TUTTI i calendar in PARALLELO, ognuno con il proprio timeout: averne
  // di più aumenta la ridondanza (basta una risposta) senza rallentare l'emissione,
  // perché un calendar lento non blocca gli altri. L'ordine delle risposte non conta:
  // ciascuna è un ramo indipendente dell'albero della prova.
  const settled = await Promise.all(OTS_CALENDARS.map(async (cal) => {
    const res = await fetchWithTimeout(`${cal}/digest`, OTS_SUBMIT_TIMEOUT, {
      method: "POST",
      headers: { Accept: "application/vnd.opentimestamps.v1", "User-Agent": "imgauth-ots" },
      body: m1,
    });
    if (res && res.ok) {
      try { return new Uint8Array(await res.arrayBuffer()); } catch { return null; }
    }
    return null;
  }));
  const responses = settled.filter(Boolean);
  if (responses.length === 0) return null;

  // DetachedTimestampFile: MAGIC + version + op sha256 (0x08) + digest, poi
  // l'albero: append(nonce) [0xf0] → sha256 [0x08] → risposte dei calendar
  // (rami multipli: ogni ramo non-ultimo è preceduto dal tag 0xff).
  // Formato validato contro la libreria python-opentimestamps.
  const parts = [OTS_MAGIC, otsVaruint(1), new Uint8Array([0x08]), digest,
                 new Uint8Array([0xf0]), otsVarbytes(nonce), new Uint8Array([0x08])];
  for (let i = 0; i < responses.length - 1; i++) parts.push(new Uint8Array([0xff]), responses[i]);
  parts.push(responses[responses.length - 1]);
  return concatBytes(...parts);
}

// Garantisce la presenza della prova .ots in R2 per l'hash dato; idempotente
// (la prima prova è anche la più antica: non va sovrascritta). Ritorna l'URL
// pubblico di download oppure null (fail-open: mai bloccare l'emissione).
async function ensureOtsProof(sha256hex, env) {
  if (!env?.PDF_ARCHIVE) return null;
  const hash = sha256hex.toLowerCase();
  const key  = `ots/${hash}.ots`;
  const url  = `https://imgauth.spaziogenesi.org/api/ots?hash=${hash}`;
  try {
    if (await env.PDF_ARCHIVE.head(key)) return url;
    const proof = await createOtsProof(hash);
    if (!proof) return null;
    await env.PDF_ARCHIVE.put(key, proof, {
      httpMetadata: { contentType: "application/vnd.opentimestamps.ots" },
    });
    return url;
  } catch {
    return null;
  }
}

async function handleOts(url, env) {
  const hash = String(url.searchParams.get("hash") ?? "").toLowerCase();
  if (!HEX64.test(hash)) {
    return jsonResponse({ error: "Parametro hash mancante o non valido." }, 400);
  }
  if (!env?.PDF_ARCHIVE) {
    return jsonResponse({ error: "Archivio non configurato." }, 503);
  }
  const obj = await env.PDF_ARCHIVE.get(`ots/${hash}.ots`);
  if (!obj) {
    return jsonResponse({ error: "Nessuna prova OpenTimestamps per questo hash." }, 404);
  }
  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": "application/vnd.opentimestamps.ots",
      "Content-Disposition": `attachment; filename="${hash}.ots"`,
      ...corsHeaders(),
    },
  });
}

// ── /api/cert — recupero certificato smarrito ────────────────────────────────
// Restituisce dal R2 il certificato PDF archiviato per l'hash richiesto.
// Modello di fiducia identico al QR/?hash=: il certificato è ottenibile solo da
// chi conosce l'hash, cioè da chi possiede il file o il certificato stesso.
// Se per la stessa opera esistono più emissioni, si restituisce la PIÙ ANTICA:
// è quella con la data più probante, coerente con la prova OTS (anch'essa la
// prima e non sovrascrivibile). I nomi timestampati ordinano cronologicamente.

async function handleCert(url, env) {
  const hash = String(url.searchParams.get("hash") ?? "").toLowerCase();
  if (!HEX64.test(hash)) {
    return jsonResponse({ error: "Parametro hash mancante o non valido." }, 400);
  }
  if (!env?.PDF_ARCHIVE) {
    return jsonResponse({ error: "Archivio non configurato." }, 503);
  }
  const listed = await env.PDF_ARCHIVE.list({ prefix: `pdf/${hash}/` });
  const keys = (listed?.objects ?? []).map(o => o.key).sort();
  if (keys.length === 0) {
    return jsonResponse({ error: "Nessun certificato in archivio per questo hash." }, 404);
  }
  const obj = await env.PDF_ARCHIVE.get(keys[0]);
  if (!obj) {
    return jsonResponse({ error: "Nessun certificato in archivio per questo hash." }, 404);
  }
  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="certificato-${hash.slice(0, 12)}.pdf"`,
      ...corsHeaders(),
    },
  });
}

// ── /c/<sha256> — certificato verificabile online ────────────────────────────
// Pagina pubblica e permanente per ogni opera attestata: impronta SHA-256, data,
// algoritmo, ancoraggio OpenTimestamps (Bitcoin) e QR code. È renderizzata dal
// Worker (HTML, HTTP 200) e va montata su attestazione.spaziogenesi.org/c/* via
// route Cloudflare; nel frattempo risponde anche su imgauth.spaziogenesi.org/c/.
// Stesso modello di fiducia di /api/cert: la pagina esiste solo se l'opera è in
// archivio, ottenibile solo da chi conosce l'impronta (cioè possiede file/cert).

// Sidecar di metadati per la pagina /c/<hash>: i soli campi già stampati sul
// certificato. Idempotente: preserva la PRIMA emissione. Best-effort.
async function writeCertMeta(env, hash, d, meta, tier, conventionId) {
  const key = `meta/cert/${hash}.json`;
  try {
    if (await env.PDF_ARCHIVE.head(key)) return;
    const payload = {
      sha256: hash,
      algoritmo: "SHA-256",
      timestamp_iso: String(d.timestamp_iso ?? ""),
      timestamp_leggibile: String(d.timestamp_leggibile ?? ""),
      dimensione_bytes: d.dimensione_bytes ?? null,
      tipo_mime: String(d.tipo_mime ?? ""),
      opera: String(d.opera ?? ""),
      titolo: meta?.titolo || "",
      autore: meta?.autore || "",
      anno: meta?.anno || "",
      note: meta?.note || "",
      tier: tier || "base",
      convention_id: conventionId || null,
    };
    await env.PDF_ARCHIVE.put(key, JSON.stringify(payload), {
      httpMetadata: { contentType: "application/json; charset=utf-8" },
    });
  } catch { /* best-effort: la pagina ha un fallback sulla chiave del PDF */ }
}

// Ricostruisce l'ISO dell'emissione dal nome della chiave R2 (fallback per i
// certificati senza sidecar): pdf/<hash>/certificato_<stamp>.pdf, dove lo stamp è
// l'ISO con ":" e "." sostituiti da "-" (vedi certFilenameStamp).
function stampFromKey(key) {
  const m = String(key).match(/certificato_(.+)\.pdf$/);
  if (!m) return "";
  const s = m[1].replace(/T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/, "T$1:$2:$3.$4Z");
  const dt = new Date(s);
  return isNaN(dt.getTime()) ? "" : dt.toISOString();
}

function escHtml(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function formatDateIT(iso) {
  const dt = new Date(iso);
  if (isNaN(dt.getTime())) return "";
  const hh = String(dt.getUTCHours()).padStart(2, "0");
  const mm = String(dt.getUTCMinutes()).padStart(2, "0");
  return `${dt.getUTCDate()} ${MONTHS_IT[dt.getUTCMonth() + 1]} ${dt.getUTCFullYear()}, ore ${hh}:${mm} UTC`;
}

// QR come SVG vettoriale (nessuna dipendenza esterna): codifica l'URL passato.
function qrSvg(text, px = 188) {
  const qr = encodeQR(text, { ecc: "M" });
  const n = qr.size;
  let rects = "";
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++)
      if (qr.data[r][c]) rects += `<rect x="${c}" y="${r}" width="1" height="1"/>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="QR del certificato"><rect width="${n}" height="${n}" fill="#fff"/><g fill="#1a1a1a">${rects}</g></svg>`;
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Un certificato esistente è stabile → cache lunga; una pagina "non trovata"
      // può diventare valida appena l'opera viene archiviata → cache breve.
      "Cache-Control": status === 200 ? "public, max-age=3600" : "public, max-age=60",
    },
  });
}

async function handleCertPage(path, env) {
  const hash = decodeURIComponent(path.slice(3).split("/")[0] || "").toLowerCase();
  if (!HEX64.test(hash)) {
    return htmlResponse(certPageShell("Impronta non valida",
      `<p class="lead">L'indirizzo non contiene un'impronta SHA-256 valida (64 caratteri esadecimali).</p>`), 404);
  }
  if (!env?.PDF_ARCHIVE) {
    return htmlResponse(certPageShell("Servizio non disponibile",
      `<p class="lead">L'archivio dei certificati non è al momento raggiungibile. Riprova più tardi.</p>`), 503);
  }

  let hasCert = false, hasOts = false, metaObj = null, certIso = "";
  try {
    const listed = await env.PDF_ARCHIVE.list({ prefix: `pdf/${hash}/` });
    const keys = (listed?.objects ?? []).map(o => o.key).sort();
    hasCert = keys.length > 0;
    if (hasCert) certIso = stampFromKey(keys[0]);
    hasOts = !!(await env.PDF_ARCHIVE.head(`ots/${hash}.ots`));
    const m = await env.PDF_ARCHIVE.get(`meta/cert/${hash}.json`);
    if (m) metaObj = JSON.parse(await m.text());
  } catch { /* fall through: trattato come non trovato */ }

  if (!hasCert && !hasOts) {
    return htmlResponse(certPageShell("Attestazione non trovata",
      `<p class="lead">Nessuna attestazione risulta in archivio per questa impronta.</p>
       <p class="muted">Se hai appena emesso il certificato, attendi qualche istante e ricarica. Per attestare una nuova opera vai su <a href="${CERT_PAGE_BASE}">attestazione.spaziogenesi.org</a>.</p>
       <p class="fingerprint">${escHtml(hash)}</p>`), 404);
  }

  return htmlResponse(certPageHtml(hash, metaObj, certIso, hasCert, hasOts), 200);
}

// Guscio HTML comune (stessa identità visiva per pagina valida e stati d'errore).
function certPageShell(title, bodyHtml, headExtra = "") {
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(title)} — Spazio Genesi</title>
<meta name="robots" content="noindex">
${headExtra}
<style>
  :root { --oro:#8B6914; --bg:#faf8f4; --card:#fff; --ink:#1f1d18; --muted:#6b6453; --line:#e7e1d4; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    line-height:1.6; padding:1.5rem; }
  .wrap { max-width:640px; margin:1.5rem auto; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:1.6rem 1.7rem; box-shadow:0 1px 3px rgba(0,0,0,.04); }
  .brand { display:flex; align-items:center; gap:.55rem; font-size:.82rem;
    letter-spacing:.04em; text-transform:uppercase; color:var(--muted); margin-bottom:1rem; }
  .brand b { color:var(--oro); font-weight:700; letter-spacing:.02em; text-transform:none; font-size:.95rem; }
  h1 { font-size:1.45rem; margin:.2rem 0 1rem; }
  .lead { font-size:1.02rem; }
  .muted { color:var(--muted); font-size:.9rem; }
  a { color:var(--oro); }
  .pill { display:inline-flex; align-items:center; gap:.4rem; font-size:.82rem; font-weight:600;
    padding:.28rem .7rem; border-radius:999px; background:#eef6ec; color:#2f6b2a; border:1px solid #cfe6ca; }
  .grid { margin:1.3rem 0; border-top:1px solid var(--line); }
  .row { display:flex; flex-wrap:wrap; gap:.2rem .9rem; padding:.75rem 0; border-bottom:1px solid var(--line); }
  .row .k { flex:0 0 9.5rem; color:var(--muted); font-size:.85rem; }
  .row .v { flex:1 1 14rem; min-width:0; }
  .fingerprint { font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
    font-size:.84rem; word-break:break-all; line-height:1.5; }
  .qr { text-align:center; margin:1.4rem 0 .4rem; }
  .qr svg { width:188px; height:188px; border:1px solid var(--line); border-radius:10px; padding:8px; background:#fff; }
  .qr .cap { color:var(--muted); font-size:.8rem; margin-top:.5rem; }
  .actions { display:flex; flex-wrap:wrap; gap:.6rem; margin-top:1.3rem; }
  .btn { display:inline-flex; align-items:center; gap:.45rem; text-decoration:none; font-size:.9rem;
    font-weight:600; padding:.6rem 1rem; border-radius:9px; border:1px solid var(--line); color:var(--ink); }
  .btn.primary { background:var(--oro); color:#fff; border-color:var(--oro); }
  .foot { margin-top:1.5rem; color:var(--muted); font-size:.78rem; line-height:1.6; }
  .copy { cursor:pointer; border:none; background:none; color:var(--oro); font-size:.8rem; padding:0; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="brand">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8B6914" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-8 8.5-4.5-1-8-3.5-8-8.5V6l8-3 8 3z"/><path d="m9 12 2 2 4-4"/></svg>
        <b>Spazio Genesi</b> · Attestazione opere
      </div>
      ${bodyHtml}
      <div class="foot">
        Spazio Genesi ETS — Codice fiscale 96602450585 — <a href="${CERT_PAGE_BASE}">attestazione.spaziogenesi.org</a><br>
        L'attestazione prova l'esistenza e l'integrità del file a una certa data; non costituisce di per sé prova di paternità dell'opera.
      </div>
    </div>
  </div>
</body>
</html>`;
}

function certPageHtml(hash, m, certIso, hasCert, hasOts) {
  const permaUrl = `${CERT_PAGE_BASE}/c/${hash}`;
  const dateIso  = (m && m.timestamp_iso) || certIso || "";
  const dateText = (m && m.timestamp_leggibile) || formatDateIT(dateIso) || "data non disponibile";
  const otsUrl   = `${API_BASE}/api/ots?hash=${hash}`;
  const certUrl  = `${API_BASE}/api/cert?hash=${hash}`;
  const verifyUrl = `${CERT_PAGE_BASE}?hash=${hash}`;

  // Riga dati dichiarati (solo se presenti): sono auto-dichiarazioni vincolate alla firma.
  const declared = [];
  if (m?.titolo) declared.push(["Titolo", m.titolo]);
  if (m?.autore) declared.push(["Autore", m.autore]);
  if (m?.anno)   declared.push(["Anno/versione", m.anno]);
  if (m?.note)   declared.push(["Note", m.note]);
  const declaredRows = declared
    .map(([k, v]) => `<div class="row"><span class="k">${escHtml(k)}</span><span class="v">${escHtml(v)}</span></div>`)
    .join("");

  const otsRow = hasOts
    ? `<div class="row"><span class="k">Ancoraggio Bitcoin</span><span class="v">OpenTimestamps · <a href="${otsUrl}">scarica prova .ots</a> · <a href="https://opentimestamps.org" target="_blank" rel="noopener">verifica</a></span></div>`
    : `<div class="row"><span class="k">Ancoraggio Bitcoin</span><span class="v muted">non disponibile per questa impronta</span></div>`;

  const headExtra =
    `<meta property="og:title" content="Certificato verificabile — Spazio Genesi">
<meta property="og:description" content="Attestazione di esistenza e integrità di un'opera digitale. Impronta SHA-256, data, ancoraggio Bitcoin.">
<meta property="og:type" content="website">
<meta property="og:url" content="${permaUrl}">
<meta property="og:image" content="${CERT_PAGE_BASE}/og.png">
<link rel="canonical" href="${permaUrl}">`;

  const body = `
      <span class="pill">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
        Opera attestata
      </span>
      <h1>Certificato verificabile</h1>
      <p class="muted">Questa pagina certifica che il file con l'impronta qui sotto è stato attestato da Spazio Genesi ETS alla data indicata.</p>

      <div class="grid">
        <div class="row"><span class="k">Impronta (SHA-256)</span><span class="v fingerprint">${escHtml(hash)} <button class="copy" type="button" onclick="navigator.clipboard&&navigator.clipboard.writeText('${hash}').then(()=>{this.textContent='copiato'})">copia</button></span></div>
        <div class="row"><span class="k">Algoritmo</span><span class="v">${escHtml((m && m.algoritmo) || "SHA-256")}</span></div>
        <div class="row"><span class="k">Data attestazione</span><span class="v">${escHtml(dateText)}</span></div>
        ${m?.tipo_mime ? `<div class="row"><span class="k">Tipo file</span><span class="v">${escHtml(m.tipo_mime)}</span></div>` : ""}
        ${otsRow}
        ${declaredRows ? `<div class="row" style="border:none;padding-bottom:.2rem"><span class="k" style="flex-basis:100%;color:var(--oro);font-weight:600">Dati dichiarati dall'autore</span></div>${declaredRows}` : ""}
      </div>

      <div class="qr">
        ${qrSvg(permaUrl)}
        <div class="cap">Inquadra per riaprire questa pagina</div>
      </div>

      <div class="actions">
        ${hasCert ? `<a class="btn primary" href="${certUrl}">Scarica il certificato PDF</a>` : ""}
        <a class="btn" href="${verifyUrl}">Verifica con il file originale</a>
        ${hasOts ? `<a class="btn" href="${otsUrl}">Prova blockchain (.ots)</a>` : ""}
      </div>`;

  return certPageShell("Certificato verificabile", body, headExtra);
}

// ── /api/badge — badge SVG "Opera attestata" ─────────────────────────────────
// Badge a due segmenti (stile shields) incorporabile via <img> su siti e social.
// Mostra "opera attestata" (oro) SOLO se per quell'hash esiste davvero qualcosa
// in archivio (certificato o prova OpenTimestamps); altrimenti "non attestata"
// (grigio). Così il badge non è falsificabile: riflette lo stato reale e, cliccato,
// porta alla pagina di verifica dove il visitatore conferma con il file originale.

function badgeSvg(value, valueColor) {
  const LW = 86, VW = 120, H = 28, W = LW + VW;
  // Font generico (no dipendenze esterne); testo controllato (niente input utente).
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" role="img" aria-label="Spazio Genesi: ${value}">
  <rect width="${W}" height="${H}" rx="4" fill="#1f1f1f"/>
  <path d="M${LW} 0h${VW - 4}a4 4 0 0 1 4 4v${H - 8}a4 4 0 0 1-4 4H${LW}z" fill="${valueColor}"/>
  <g font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" fill="#fff" text-anchor="middle">
    <text x="${LW / 2}" y="18">Spazio Genesi</text>
    <text x="${LW + VW / 2}" y="18">${value}</text>
  </g>
</svg>`;
}

function badgeResponse(svg, maxAge = 60) {
  return new Response(svg, {
    status: 200,
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      // Cache differenziata per stato: il badge "non attestata" deve poter
      // diventare "attestata" in fretta (max-age breve) — altrimenti una richiesta
      // fatta prima che l'opera sia archiviata resterebbe grigia a lungo. Il verde,
      // invece, non torna più indietro: si può cachare a lungo.
      "Cache-Control": `public, max-age=${maxAge}`,
      ...corsHeaders(),
    },
  });
}

async function handleBadge(url, env) {
  const hash = String(url.searchParams.get("hash") ?? "").toLowerCase();
  // Per un <img> non si restituisce mai un errore HTTP (mostrerebbe l'icona rotta):
  // a hash malformato si risponde con un badge grigio esplicativo.
  if (!HEX64.test(hash)) {
    return badgeResponse(badgeSvg("hash non valido", "#9aa0a6"), 300);
  }
  let attested = false;
  if (env?.PDF_ARCHIVE) {
    try {
      // Prova OpenTimestamps (dalla 1.7) o certificato indicizzato (dalla 1.8):
      // basta una delle due per considerare l'opera attestata.
      if (await env.PDF_ARCHIVE.head(`ots/${hash}.ots`)) {
        attested = true;
      } else {
        const listed = await env.PDF_ARCHIVE.list({ prefix: `pdf/${hash}/`, limit: 1 });
        attested = (listed?.objects?.length ?? 0) > 0;
      }
    } catch {
      attested = false;
    }
  }
  // Verde: cache lunga (lo stato "attestata" non torna indietro). Grigio: cache
  // breve, così si auto-aggiorna a verde appena l'opera viene archiviata.
  return attested
    ? badgeResponse(badgeSvg("✓ opera attestata", "#8B6914"), 86400)
    : badgeResponse(badgeSvg("non attestata", "#9aa0a6"), 60);
}

// ── /api/status — stato semaforico dei servizi ────────────────────────────────
// Aggrega lo stato delle dipendenze raggiungibili dal worker. Esito cachato 180s
// (per-isolate, best-effort) con stale-while-revalidate: dopo la scadenza si
// restituisce subito il valore vecchio e si aggiorna in background (ctx.waitUntil),
// così la pagina resta reattiva e Azure non viene svegliato a ogni visita.
// Valori per componente: "ok" | "down" | "degraded" | "n/d".

let _statusCache = null; // { data, ts }
const STATUS_TTL = 180000; // 180s: traffico basso → meno risvegli di Azure

async function fetchWithTimeout(url, ms, opts = {}) {
  try {
    return await fetch(url, { ...opts, signal: AbortSignal.timeout(ms) });
  } catch {
    return null;
  }
}

// Soglie di latenza per check (ms). "watch": lento ma il servizio NON degrada →
// si registra un evento (status 'ok', cause 'slow') utile all'analisi, mentre la
// barra del giorno resta verde. "degraded": oltre questa soglia il servizio è
// considerato degradato (status 'degraded'). Tarabili.
// ⚙️ Watch volutamente BASSI (fase di osservazione qualità fornitori, dal 2026-06-19):
// servono a far emergere i rallentamenti per misurarne frequenza/durata. Si rialzano
// una volta capito il baseline. Le soglie degraded restano alte (la barra pubblica non
// va in giallo per lentezze minori).
const HEALTH_WATCH    = { archive: 300,  signer: 1200, anchor: 1000 };
const HEALTH_DEGRADED = { archive: 1000, signer: 5000, anchor: 4000 };

// Esegue i check delle dipendenze MISURANDO la latenza. Ritorna un campione per
// check: { check, up, status, latency, cause, detail }, con `status` in forma D1
// ('ok'|'degraded'|'error'). Il mapping allo stato semaforico è in summarizeStatus.
async function runChecks(env) {
  const samples = [];

  // Capacità di emissione (sonda interna, 1.15.1): HMAC_SECRET presente e
  // funzionante — round-trip firma+verifica su una stringa fissa (~1 ms).
  // Confluisce nel componente `worker`: verde = "il motore sa firmare", non
  // solo "risponde all'HTTP". Senza segreto le attestazioni uscirebbero prive
  // di firma (hmac null) e /api/cert-pdf risponderebbe 503: è un guasto vero,
  // e prima di questa sonda restava invisibile (status verde, monitor muto).
  // NB: NON rileva una rotazione errata del segreto (firma e verifica
  // userebbero lo stesso valore nuovo) — per quella serve il canary esterno
  // su /api/verify (P17, monitor).
  {
    const t0 = Date.now();
    if (!env?.HMAC_SECRET) {
      samples.push({ check: "worker", up: false, status: "error", latency: 0,
        cause: "hmac_secret_missing", detail: null });
    } else {
      try {
        const probe = "status-probe";
        const sig = await signHmac(env.HMAC_SECRET, probe);
        const ok  = await verifyHmac(env.HMAC_SECRET, probe, sig);
        if (ok) samples.push({ check: "worker", up: true, status: "ok", latency: Date.now() - t0, cause: null, detail: null });
        else samples.push({ check: "worker", up: false, status: "error", latency: Date.now() - t0,
          cause: "hmac_roundtrip_failed", detail: null });
      } catch (e) {
        samples.push({ check: "worker", up: false, status: "error", latency: Date.now() - t0,
          cause: "hmac_error", detail: { message: String(e?.message || e).slice(0, 200) } });
      }
    }
  }

  // Archivio R2: una list minima.
  if (env?.PDF_ARCHIVE) {
    const t0 = Date.now();
    try {
      await env.PDF_ARCHIVE.list({ limit: 1 });
      samples.push(gradeSample("archive", true, Date.now() - t0));
    } catch (e) {
      samples.push({ check: "archive", up: false, status: "error", latency: Date.now() - t0,
        cause: "r2_error", detail: { message: String(e?.message || e).slice(0, 200) } });
    }
  }

  // Firmatario authart: health su GET <base>/ (senza auth). Timeout generoso per
  // assorbire il cold-start di Azure ed evitare falsi "down".
  if (env?.SIGNER_URL) {
    const base = String(env.SIGNER_URL).replace(/\/sign\/?$/, "/");
    const t0 = Date.now();
    const r = await fetchWithTimeout(base, 8000, { method: "GET" });
    const latency = Date.now() - t0;
    if (r && r.ok) samples.push(gradeSample("signer", true, latency));
    else samples.push({ check: "signer", up: false, status: "error", latency,
      cause: r ? `http_${r.status}` : "timeout", detail: r ? { http: r.status } : null });
  }

  // Calendar OpenTimestamps: l'ancoraggio reale (ensureOtsProof) ha bisogno che
  // UNO solo dei calendar risponda (fail-open). Misuriamo quindi il tempo del PRIMO
  // a rispondere (Promise.any), non del più lento: così un singolo calendar lento non
  // fa più apparire l'àncora "degradata" quando in realtà l'attestazione viene ancorata
  // bene dagli altri. "degraded" (informativo) solo se cadono TUTTI. Timeout 6s ciascuno.
  {
    const t0 = Date.now();
    let firstUp = false;
    try {
      await Promise.any(OTS_CALENDARS.map(async (c) => {
        const r = await fetchWithTimeout(c, 6000, { method: "GET" });
        if (r) return true;             // raggiungibile → soddisfa Promise.any
        throw new Error("unreachable"); // non raggiungibile → rigetta
      }));
      firstUp = true;
    } catch { firstUp = false; }       // tutti rigettati → AggregateError
    const latency = Date.now() - t0;
    if (firstUp) samples.push(gradeSample("anchor", true, latency));
    else samples.push({ check: "anchor", up: false, status: "degraded", latency,
      cause: "all_unreachable", detail: null });
  }

  return samples;
}

// Campione per i check ANDATI A BUON FINE: 'degraded' oltre la soglia degraded,
// altrimenti 'ok' (con cause 'slow' se comunque oltre la soglia watch).
function gradeSample(check, up, latency) {
  let status = "ok", cause = null;
  if (latency >= HEALTH_DEGRADED[check]) { status = "degraded"; cause = "slow"; }
  else if (latency >= HEALTH_WATCH[check]) { cause = "slow"; }
  return { check, up, status, latency, cause, detail: null };
}

// Mappa i campioni allo stato semaforico per componente (compat con la pagina
// /status e il rollup R2): 'ok' | 'degraded' | 'down' | 'n/d'. Un check fallito è
// 'down' (archive/signer) o 'degraded' (anchor, fail-open).
function summarizeStatus(samples) {
  const status = {
    worker: "ok",          // default "rispondiamo"; la sonda HMAC di runChecks lo porta a "down" se il motore non sa firmare
    archive: "n/d",
    signer: "n/d",
    anchor: "n/d",
    checked_at: new Date().toISOString(),
  };
  for (const s of samples) {
    if (s.up) status[s.check] = s.status === "degraded" ? "degraded" : "ok";
    else status[s.check] = s.check === "anchor" ? "degraded" : "down";
  }
  return status;
}

// Sommario semaforico (compat: se servisse altrove lo stato senza il log).
async function computeStatus(env) {
  return summarizeStatus(await runChecks(env));
}

// Campiona lo stato, aggiorna la cache, registra il rollup giornaliero (R2) e
// logga su D1 gli eventi notevoli (errori, degradi, rallentamenti ≥ soglia watch).
async function sampleAndRecord(env) {
  const samples = await runChecks(env);
  const s = summarizeStatus(samples);
  _statusCache = { data: s, ts: Date.now() };
  try { await recordHistory(env, s); } catch {}
  // Si scrive solo se l'evento è "notevole" (non ok-veloce): un giorno tutto liscio
  // non lascia rumore nel log. La scrittura è non-blocking (try/catch in logHealth).
  for (const smp of samples) {
    const notable = smp.status !== "ok" || (smp.latency != null && smp.latency >= HEALTH_WATCH[smp.check]);
    if (notable) await logHealth(env, smp);
  }
  return s;
}

// Scrittura su D1 dell'evento di salute (non-blocking: un errore di log NON
// interrompe il Worker). NB: colonna `check_name` perché `check` è parola
// riservata in SQLite.
async function logHealth(env, { status, latency, check, cause, detail }) {
  if (!env?.DB) return;
  try {
    await env.DB.prepare(
      `INSERT INTO health_log (ts, status, latency, check_name, cause, detail)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      Date.now(), status, latency ?? null, check,
      cause ?? null, detail ? JSON.stringify(detail) : null
    ).run();
  } catch (e) {
    console.error("[health_log write failed]", e?.message);
  }
}

async function handleStatus(env, ctx) {
  const now = Date.now();
  if (_statusCache) {
    if (now - _statusCache.ts < STATUS_TTL) {
      return jsonResponse(_statusCache.data);
    }
    // Stale: restituisci subito il vecchio e aggiorna in background (+ storico).
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(sampleAndRecord(env).catch(() => {}));
    }
    return jsonResponse(_statusCache.data);
  }
  // Prima chiamata (cache vuota): calcola in sincrono.
  const s = await sampleAndRecord(env);
  return jsonResponse(s);
}

// ── Storico stato (per la pagina /status, barre a 90 giorni) ──────────────────
// Rollup GIORNALIERO per componente in R2 (status/history.json): per ogni giorno
// si conserva lo stato PEGGIORE osservato. Alimentato dal cron del Worker (anche
// senza visitatori) e dai refresh di /api/status. Finestra a scorrimento 90 giorni.
const HISTORY_KEY = "status/history.json";
const HISTORY_DAYS = 90;
const HIST_COMPONENTS = ["worker", "signer", "archive", "anchor"];
const SEV = { nodata: 0, ok: 1, degraded: 2, down: 3 };
// I giorni dello storico (barre /status) e del log sono ancorati al fuso italiano
// (Europe/Rome), NON a UTC: così barre ed eventi cadono nel giorno "giusto", in
// particolare appena dopo la mezzanotte (Roma è UTC+1/+2). Il `ts` resta epoch assoluto.
const ROME_TZ = "Europe/Rome";
function dayRome(ms = Date.now()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: ROME_TZ, year: "numeric", month: "2-digit", day: "2-digit",
  }).format(new Date(ms)); // en-CA → "YYYY-MM-DD"
}
// Offset (ms) da aggiungere a UTC per ottenere l'ora di parete a Roma in quell'istante.
function romeOffsetMs(ms) {
  const p = new Intl.DateTimeFormat("en-US", {
    timeZone: ROME_TZ, hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(ms)).reduce((a, x) => ((a[x.type] = x.value), a), {});
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - ms;
}
// Istante UTC (ms) della mezzanotte di Roma per la data YYYY-MM-DD (auto-correzione DST).
function romeMidnight(dayStr) {
  const guess = Date.parse(dayStr + "T00:00:00Z");
  return guess - romeOffsetMs(guess - romeOffsetMs(guess));
}
// Data calendario precedente/successiva (aritmetica pura su YYYY-MM-DD, indip. dal fuso).
function prevDay(s) { const [y, m, d] = s.split("-").map(Number); return new Date(Date.UTC(y, m - 1, d) - 86400000).toISOString().slice(0, 10); }
function nextDay(s) { const [y, m, d] = s.split("-").map(Number); return new Date(Date.UTC(y, m - 1, d) + 86400000).toISOString().slice(0, 10); }

async function recordHistory(env, s) {
  if (!env?.PDF_ARCHIVE) return;
  const today = dayRome();
  let hist = {};
  try { const o = await env.PDF_ARCHIVE.get(HISTORY_KEY); if (o) hist = JSON.parse(await o.text()) || {}; } catch {}
  let changed = false;
  for (const k of HIST_COMPONENTS) {
    const v = (s[k] === "ok" || s[k] === "down" || s[k] === "degraded") ? s[k] : "nodata";
    if (v === "nodata") continue;
    hist[k] = hist[k] || {};
    const prev = hist[k][today] || "nodata";
    const next = SEV[v] > SEV[prev] ? v : prev;
    if (next !== prev) { hist[k][today] = next; changed = true; }
  }
  // Potatura oltre i 90 giorni (confronto lessicografico su YYYY-MM-DD)
  const cutoff = dayRome(Date.now() - HISTORY_DAYS * 86400000);
  for (const k of HIST_COMPONENTS) {
    if (!hist[k]) continue;
    for (const d of Object.keys(hist[k])) if (d < cutoff && d !== "_updated") { delete hist[k][d]; changed = true; }
  }
  // Scrive se lo stato è cambiato OPPURE se l'ultimo controllo è più vecchio di 5
  // minuti: così `_updated` riflette l'ULTIMO CONTROLLO (non l'ultimo cambiamento) e
  // avanza regolarmente, senza però riscrivere a ogni richiesta sotto traffico.
  const prevUpdated = hist._updated ? Date.parse(hist._updated) : 0;
  const stale = (Date.now() - prevUpdated) > 5 * 60 * 1000;
  if (changed || stale) {
    hist._updated = new Date().toISOString();
    try { await env.PDF_ARCHIVE.put(HISTORY_KEY, JSON.stringify(hist)); } catch {}
  }
}

async function handleStatusHistory(env, ctx) {
  // Auto-guarigione: se lo storico è vecchio (>10 min), campiona in background.
  // Così la pagina /status resta fresca anche indipendentemente dal cron.
  if (ctx && typeof ctx.waitUntil === "function" && env?.PDF_ARCHIVE) {
    try {
      const head = await env.PDF_ARCHIVE.get(HISTORY_KEY);
      const upd = head ? (JSON.parse(await head.text())._updated || 0) : 0;
      if (Date.now() - Date.parse(upd || 0) > 10 * 60 * 1000) {
        ctx.waitUntil(sampleAndRecord(env).catch(() => {}));
      }
    } catch {}
  }
  const labels = {
    worker: "Generazione dell'attestazione",
    signer: "Firma del certificato (PDF)",
    archive: "Archivio e recupero certificati",
    anchor: "Ancoraggio blockchain",
  };
  let hist = {};
  if (env?.PDF_ARCHIVE) {
    try { const o = await env.PDF_ARCHIVE.get(HISTORY_KEY); if (o) hist = JSON.parse(await o.text()) || {}; } catch {}
  }
  // Sequenza di date CALENDARIO in ora di Roma (oldest→newest), robusta ai cambi DST
  // (decremento per data, non per 24h fisse).
  const days = [];
  { let d = dayRome(); const seq = [d]; for (let i = 1; i < HISTORY_DAYS; i++) { d = prevDay(d); seq.push(d); } days.push(...seq.reverse()); }

  const components = HIST_COMPONENTS.map((k) => {
    const hk = hist[k] || {};
    const arr = days.map((d) => ({ d, s: hk[d] || "nodata" }));
    const withData = arr.filter((x) => x.s !== "nodata");
    const ok = withData.filter((x) => x.s === "ok").length;
    const uptime = withData.length ? Math.round((ok / withData.length) * 1000) / 10 : null;
    return { key: k, label: labels[k], current: arr[arr.length - 1].s, uptime, days: arr };
  });

  let overall = "ok";
  for (const c of components) {
    if (!["worker", "signer", "archive"].includes(c.key)) continue;
    if (c.current === "down") overall = "down";
    else if (c.current === "degraded" && overall !== "down") overall = "degraded";
    else if (c.current === "nodata" && overall === "ok") overall = "nodata";
  }

  return jsonResponse({ updated: hist._updated || null, window_days: HISTORY_DAYS, overall, components });
}

// ── /api/health-log — eventi fini di salute per un giorno (da D1) ─────────────
// Restituisce gli eventi registrati in health_log per una data (?day=YYYY-MM-DD,
// default oggi UTC): errori, degradi e rallentamenti sotto soglia. Alimenta il
// drill-down "esplora il giorno" della pagina /status — utile anche quando la
// barra del giorno resta verde (rallentamenti che non degradano il servizio).
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

function safeJsonParse(s) { try { return JSON.parse(s); } catch { return s; } }

async function handleHealthLog(url, env) {
  const day = url.searchParams.get("day") || dayRome();
  if (!DAY_RE.test(day)) {
    return jsonResponse({ error: "Parametro 'day' non valido (atteso YYYY-MM-DD)" }, 400);
  }
  if (!env?.DB) return jsonResponse({ day, count: 0, events: [], note: "D1 non configurato" });

  // Giorno = data CALENDARIO in ora di Roma: finestra da mezzanotte di Roma alla
  // mezzanotte di Roma successiva (gestisce l'offset CET/CEST, DST inclusa).
  const start = romeMidnight(day);
  const end = romeMidnight(nextDay(day));
  try {
    const { results } = await env.DB.prepare(
      `SELECT ts, status, latency, check_name, cause, detail
         FROM health_log
        WHERE ts >= ? AND ts < ?
        ORDER BY ts ASC
        LIMIT 1000`
    ).bind(start, end).all();
    const events = (results || []).map((r) => ({
      ts: r.ts,
      iso: new Date(r.ts).toISOString(),
      status: r.status,
      latency: r.latency,
      check: r.check_name,
      cause: r.cause,
      detail: r.detail ? safeJsonParse(r.detail) : null,
    }));
    return jsonResponse({ day, count: events.length, events });
  } catch (e) {
    console.error("[health-log read failed]", e?.message);
    return jsonResponse({ day, count: 0, events: [], error: "Lettura storico non riuscita" });
  }
}

// ── Notifica Telegram: nuovo certificato emesso ───────────────────────────────
// Avvisa il gestore (chat Telegram) alla produzione di un certificato. Frequenza
// configurabile via env CERT_NOTIFY_EVERY (1 = ogni certificato; es. 5 = un avviso
// ogni 5). Contatore persistente in R2 (meta/cert-count). Tutto best-effort e
// post-risposta (ctx.waitUntil): un errore qui non blocca l'emissione.
// Segreti TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID come Cloudflare secrets.
async function notifyCertProduced(env, sha256, meta, tsHuman) {
  const token = env?.TELEGRAM_BOT_TOKEN, chat = env?.TELEGRAM_CHAT_ID;
  if (!token || !chat || !env?.PDF_ARCHIVE) return;
  const every = Math.max(1, parseInt(env.CERT_NOTIFY_EVERY || "1", 10) || 1);

  // Contatore in R2 (read-modify-write; a basso traffico le race sono trascurabili).
  let count = 0;
  try {
    const obj = await env.PDF_ARCHIVE.get("meta/cert-count");
    if (obj) count = parseInt(await obj.text(), 10) || 0;
  } catch { /* contatore assente o illeggibile: si riparte da 0 */ }
  count += 1;
  try { await env.PDF_ARCHIVE.put("meta/cert-count", String(count)); } catch {}

  if (count % every !== 0) return; // avvisa solo ogni N

  const righe = ["📄 Spazio Genesi — nuovo certificato emesso", ""];
  if (meta?.titolo) righe.push(`Titolo: ${meta.titolo}`);
  if (meta?.autore) righe.push(`Autore: ${meta.autore}`);
  righe.push(`Impronta: ${sha256.slice(0, 12)}…`);
  righe.push(`Totale emessi: ${count}${every > 1 ? ` · avviso ogni ${every}` : ""}`);
  righe.push("", `🕓 ${tsHuman || new Date().toISOString()}`);

  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text: righe.join("\n"), disable_web_page_preview: true }),
    });
  } catch { /* notifica best-effort */ }
}

