/**
 * Spazio Genesi ETS — Hash & Verify Worker (JavaScript)
 * Endpoints:
 *   POST /api/hash      → genera hash SHA-256 + attestazione + HMAC
 *   POST /api/verify    → verifica hash dichiarato vs file
 *   POST /api/cert-pdf  → compila certificato_opera_pdf_mod.pdf e restituisce il PDF;
 *                         salva copia in R2 sotto pdf/ (binding PDF_ARCHIVE)
 *   GET  /ping          → health check
 */

import { PDFDocument } from "pdf-lib";
import certTemplatePdf from "./certificato_opera_pdf_mod.pdf";

const MONTHS_IT = [
  "", "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
  "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre",
];

// ── Helpers CORS ────────────────────────────────────────────────────────────

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "*",
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

    if (method === "GET"  && path === "/ping")        return handlePing(request);
    if (method === "POST" && path === "/api/hash")     return handleHash(request, env);
    if (method === "POST" && path === "/api/verify")   return handleVerify(request);
    if (method === "POST" && path === "/api/cert-pdf") return handlePdf(request, env);

    return jsonResponse({ error: "Endpoint non trovato", path }, 404);
  },
};

// ── /ping ────────────────────────────────────────────────────────────────────

function handlePing(request) {
  return jsonResponse({ ok: true, origin: request.headers.get("Origin") });
}

// ── /api/hash ────────────────────────────────────────────────────────────────

async function handleHash(request, env) {
  try {
    const data  = await request.json();
    const b64   = data.image;
    const name  = data.name  ?? "opera";
    const mime  = data.type  ?? "application/octet-stream";

    if (!b64) return jsonResponse({ error: "Campo 'image' mancante." }, 400);

    // Decodifica base64 → ArrayBuffer
    const raw = base64ToBytes(b64);

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
  } catch (e) {
    return jsonResponse({ error: `Errore interno: ${e.message}` }, 500);
  }
}

// ── /api/verify ──────────────────────────────────────────────────────────────

async function handleVerify(request) {
  try {
    const form    = await request.formData();
    const file    = form.get("image");
    const claimed = form.get("hash");

    if (!file || !claimed) {
      return jsonResponse({ error: "Richiesti 'image' e 'hash'." }, 400);
    }

    const raw    = await file.arrayBuffer();
    const hashBuf = await crypto.subtle.digest("SHA-256", raw);
    const digest  = bufToHex(hashBuf);
    const normalized = String(claimed).trim().toLowerCase();

    return jsonResponse({
      hash_dichiarato: normalized,
      hash_calcolato:  digest,
      coincide:        digest === normalized,
    });
  } catch (e) {
    return jsonResponse({ error: `Errore interno: ${e.message}` }, 500);
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
  attestField.setText(attestLines.join("\n"));

  form.flatten();
  const bytes = await doc.save();
  return new Uint8Array(bytes);
}

async function handlePdf(request, env) {
  try {
    const d = await request.json();
    const pdfBytes = await fillCertificatePdf(d);

    const stamp = certFilenameStamp();
    const key = `pdf/certificato_${stamp}.pdf`;

    if (env?.PDF_ARCHIVE) {
      await env.PDF_ARCHIVE.put(key, pdfBytes, {
        httpMetadata: { contentType: "application/pdf" },
      });
    }

    return pdfResponse(pdfBytes);
  } catch (e) {
    return jsonResponse({ error: `Errore interno PDF: ${e.message}` }, 500);
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
  const enc     = new TextEncoder();
  const keyMat  = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sigBuf  = await crypto.subtle.sign("HMAC", keyMat, enc.encode(message));
  // base64
  return btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
}

