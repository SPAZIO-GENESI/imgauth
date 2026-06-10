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
    }

    if (method === "GET"  && path === "/ping")        return handlePing(request);
    if (method === "POST" && path === "/api/hash")     return handleHash(request, env);
    if (method === "POST" && path === "/api/verify")   return handleVerify(request, env);
    if (method === "POST" && path === "/api/cert-pdf") return handlePdf(request, env);

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

    // HMAC opzionale
    let hmacSig = null;
    if (env?.HMAC_SECRET) {
      hmacSig = await signHmac(env.HMAC_SECRET, attestazione);
    }

    return jsonResponse({
      opera:               name,
      dimensione_bytes:    size,
      tipo_mime:           mime,
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
      hmac_valido = await verifyHmac(env.HMAC_SECRET, String(attestazione).trim(), String(hmacClaimed).trim());
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

async function fillCertificatePdf(d) {
  const doc = await PDFDocument.load(certTemplatePdf);
  const form = doc.getForm();

  form.getTextField("TITOLO").setText(String(d.opera ?? ""));
  form.getTextField("DIMENSIONE").setText(String(d.dimensione_bytes ?? ""));
  form.getTextField("MIME").setText(String(d.tipo_mime ?? ""));
  form.getTextField("SHA-256").setText(String(d.sha256 ?? ""));
  form.getTextField("TIMEISO").setText(String(d.timestamp_iso ?? ""));
  form.getTextField("TIMELEG").setText(String(d.timestamp_leggibile ?? ""));

  const attestField = form.getTextField("ATTESTAZIONE");
  attestField.enableMultiline();

  const attestLines = [];
  attestLines.push("Stringa di attestazione:");
  attestLines.push(String(d.attestazione ?? ""));
  if (d.hmac) {
    attestLines.push("");
    attestLines.push("Firma HMAC (server):");
    attestLines.push(String(d.hmac));
  }
  if (d.emesso_da) {
    attestLines.push("");
    attestLines.push("Emesso da:");
    attestLines.push(String(d.emesso_da));
  }
  attestLines.push("");
  attestLines.push("Versione motore:");
  attestLines.push(`imgauth v${APP_VERSION}`);
  attestField.setText(attestLines.join("\n"));

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

  drawCentered(
    "Spazio Genesi ETS – Galleria Commerciale Via Roma, 215, primo piano, L'Aquila (AQ) – Documento generato automaticamente — non richiede firma manuale.",
    302.854, 7, grigio
  );

  // URL nel footer: pagina di verifica generica (corta, centrata). L'hash specifico
  // viaggia nel QR (verifyUrl, sopra) e nel campo SHA-256: nessuno digita a mano un
  // hash di 64 caratteri.
  drawCentered("https://attestazione.spaziogenesi.org", 324.358, 7, oro);

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
    const tokenOk = await verifyHmac(env.HMAC_SECRET, attest, hmac);
    if (!tokenOk) {
      return jsonResponse({ error: "Firma dell'attestazione non valida: certificato non emettibile." }, 403);
    }

    const pdfBytes = await fillCertificatePdf(d);

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

