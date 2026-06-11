/**
 * Spazio Genesi ETS — Hash & Verify Worker (JavaScript)
 * Endpoints:
 *   POST /api/hash      → genera hash SHA-256 + attestazione + HMAC
 *   POST /api/verify    → verifica hash dichiarato vs file
 *   POST /api/cert-pdf  → compila certificato_opera_pdf_mod.pdf e restituisce il PDF;
 *                         salva copia in R2 sotto pdf/ (binding PDF_ARCHIVE)
 *   GET  /ping          → health check
 */

import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { encode as encodeQR } from "uqr";
import certTemplatePdf from "./certificato_opera_pdf_mod.pdf";
import pkg from "./package.json";

// Versione del motore: sorgente di verità unica = package.json (vedi CLAUDE.md › Versioning).
// Compare in /ping e nel blocco attestazione del certificato PDF.
const APP_VERSION = pkg.version;

const MONTHS_IT = [
  "", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
  "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
];

const ALLOWED_ORIGIN = "https://attestazione.spaziogenesi.org";

// Limite dimensione opera: coerente con i 100 MB dichiarati dall'interfaccia.
const MAX_BYTES = 100 * 1024 * 1024;

// Formati attesi per i campi vincolati crittograficamente (vedi handlePdf).
const HEX64  = /^[0-9a-f]{64}$/i;
const ISO_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ── Helpers CORS ────────────────────────────────────────────────────────────

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
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

// ── Entry point ──────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
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
    } else if (method === "POST" && (path === "/api/hash" || path === "/api/verify")) {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    } else if (method === "GET" && path === "/api/ots") {
      if (await isRateLimited(env.RL_API, ip)) return tooManyResponse();
    }

    if (method === "GET"  && path === "/ping")        return handlePing(request);
    if (method === "POST" && path === "/api/hash")     return handleHash(request, env);
    if (method === "POST" && path === "/api/verify")   return handleVerify(request, env);
    if (method === "POST" && path === "/api/cert-pdf") return handlePdf(request, env);
    if (method === "GET"  && path === "/api/ots")      return handleOts(url, env);

    return jsonResponse({ error: "Endpoint non trovato", path }, 404);
  },
};

// ── /ping ────────────────────────────────────────────────────────────────────

function handlePing(request) {
  return jsonResponse({ ok: true, version: APP_VERSION, origin: request.headers.get("Origin") });
}

// ── /api/hash ────────────────────────────────────────────────────────────────

async function handleHash(request, env) {
  try {
    const data  = await request.json();
    const b64   = data.image;
    const name  = data.name  ?? "opera";
    const mime  = data.type  ?? "application/octet-stream";

    if (!b64) return jsonResponse({ error: "Campo 'image' mancante." }, 400);

    // ── Anti-bot Turnstile ─────────────────────────────────────────────────────
    // La challenge è qui, all'emissione dell'attestazione: nessun token HMAC viene
    // rilasciato (né per il .txt né per il PDF) senza un umano verificato.
    // Fail-open se siteverify è irraggiungibile: è l'endpoint primario e un
    // disservizio Turnstile non deve impedire il calcolo dell'hash.
    if (env?.TURNSTILE_SECRET) {
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

    // SHA-256
    const hashBuf = await crypto.subtle.digest("SHA-256", raw);
    const digest  = bufToHex(hashBuf);
    const size    = raw.byteLength;

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

    if (!file || !claimed) {
      return jsonResponse({ error: "Richiesti 'image' e 'hash'." }, 400);
    }

    const raw     = await file.arrayBuffer();
    const hashBuf = await crypto.subtle.digest("SHA-256", raw);
    const digest  = bufToHex(hashBuf);
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
      hash_calcolato:  digest,
      coincide:        digest === normalized,
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
  const page = doc.getPages()[0];
  const verifyUrl = `https://attestazione.spaziogenesi.org?hash=${d.sha256 ?? ""}`;
  const QR_X = 438.1, QR_Y = 666.0, QR_SIZE = 100;

  const qr = encodeQR(verifyUrl, { ecc: "L" });
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

  // Dati dell'ente su due righe: C.F. e sede legale (Roma), poi sede operativa
  // (L'Aquila). La riga inferiore scende a y=296.5 per non toccare il credito
  // "Realizzato da tangram" del template (~y 285).
  drawCentered(
    "Spazio Genesi ETS — Codice fiscale 96602450585 — Sede legale: Via Francesco Caracciolo 14, 00167 Roma (RM)",
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
  if (otsUrl) {
    drawWrapped(`Ancoraggio blockchain (OpenTimestamps, Bitcoin): prova scaricabile da ${otsUrl} — verifica su https://opentimestamps.org`, 6.5, grigio);
  }
  drawWrapped("Sito dell'associazione: https://spaziogenesi.org", 6.5, oro);

  const bytes = await doc.save();
  return new Uint8Array(bytes);
}

async function handlePdf(request, env) {
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
      const signRes = await fetch(env.SIGNER_URL, {
        method: "POST",
        headers: signHeaders,
        body: pdfBytes,
      });
      if (!signRes.ok) {
        const msg = await signRes.text().catch(() => signRes.status);
        return jsonResponse({ error: `Errore firma crittografica: ${msg}` }, 502);
      }
      finalBytes = new Uint8Array(await signRes.arrayBuffer());
    }

    const stamp = certFilenameStamp();
    const key = `pdf/certificato_${stamp}.pdf`;

    if (env?.PDF_ARCHIVE) {
      await env.PDF_ARCHIVE.put(key, finalBytes, {
        httpMetadata: { contentType: "application/pdf" },
      });
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

const OTS_CALENDARS = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
];

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

  const responses = [];
  for (const cal of OTS_CALENDARS) {
    try {
      const res = await fetch(`${cal}/digest`, {
        method: "POST",
        headers: { Accept: "application/vnd.opentimestamps.v1", "User-Agent": "imgauth-ots" },
        body: m1,
      });
      if (res.ok) responses.push(new Uint8Array(await res.arrayBuffer()));
    } catch { /* calendar irraggiungibile: si prosegue con gli altri */ }
  }
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

