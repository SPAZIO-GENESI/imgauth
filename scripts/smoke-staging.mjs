// Smoke test dell'ambiente di staging (P24 FASE 2/3). Ripete i criteri di
// accettazione della FASE 2 (vedi P24-DESIGN-devops-cicd.md): ping, status,
// giro completo hash → cert-pdf → recupero. Esce non-zero al primo fallimento.
// Uso: `node scripts/smoke-staging.mjs` (URL di default) oppure
// `STAGING_URL=https://... node scripts/smoke-staging.mjs`.
//
// Presuppone che env.staging.vars.TURNSTILE_SECRET sia la chiave di TEST
// Cloudflare (passa sempre) — mai eseguibile contro la produzione per come
// è scritto: usa un token Turnstile fittizio che in produzione fallirebbe.

import { createHash } from "node:crypto";

const BASE = process.env.STAGING_URL || "https://imgauth-staging.it-e3f.workers.dev";
const TURNSTILE_TEST_TOKEN = "smoke-test-token"; // valido solo con la chiave di test

function fail(step, detail) {
  console.error(`✗ ${step}: ${detail}`);
  process.exit(1);
}

function ok(step, detail = "") {
  console.log(`✓ ${step}${detail ? " — " + detail : ""}`);
}

async function main() {
  // 1) /ping
  const pingRes = await fetch(`${BASE}/ping`);
  const ping = await pingRes.json().catch(() => null);
  if (!pingRes.ok || !ping?.ok) fail("GET /ping", JSON.stringify(ping));
  ok("GET /ping", `version ${ping.version}`);

  // 2) /api/status — worker e archive devono essere ok (signer resta n/d: authart
  // non è replicato in staging, D7).
  const statusRes = await fetch(`${BASE}/api/status`);
  const status = await statusRes.json().catch(() => null);
  if (!statusRes.ok || status?.worker !== "ok" || status?.archive !== "ok") {
    fail("GET /api/status", JSON.stringify(status));
  }
  ok("GET /api/status", `worker=${status.worker} archive=${status.archive} signer=${status.signer}`);

  // 3) POST /api/hash — impronta di prova, unica per run (timestamp nel testo).
  const sha256 = createHash("sha256").update(`smoke-staging-${Date.now()}`).digest("hex");
  const hashRes = await fetch(`${BASE}/api/hash`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sha256,
      name: "smoke.txt",
      type: "text/plain",
      size: 21,
      turnstile_token: TURNSTILE_TEST_TOKEN,
    }),
  });
  const hashBody = await hashRes.json().catch(() => null);
  if (!hashRes.ok || !hashBody?.hmac) fail("POST /api/hash", JSON.stringify(hashBody));
  ok("POST /api/hash", "hmac ricevuto");

  // 4) POST /api/cert-pdf — il PDF nasce non firmato in staging (SIGNER_URL
  // assente, D7): basta che sia un PDF valido.
  const certRes = await fetch(`${BASE}/api/cert-pdf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(hashBody),
  });
  const certBytes = new Uint8Array(await certRes.arrayBuffer());
  const magic = Buffer.from(certBytes.slice(0, 5)).toString("ascii");
  if (!certRes.ok || magic !== "%PDF-") {
    fail("POST /api/cert-pdf", `HTTP ${certRes.status}, magic="${magic}"`);
  }
  ok("POST /api/cert-pdf", `${certBytes.length} bytes`);

  // 5) GET /api/cert?hash= — recupero dall'archivio staging.
  const recoverRes = await fetch(`${BASE}/api/cert?hash=${sha256}`);
  if (!recoverRes.ok) fail("GET /api/cert", `HTTP ${recoverRes.status}`);
  ok("GET /api/cert", "certificato recuperato dall'archivio");

  console.log("\nSmoke test staging: tutto verde.");
}

main().catch((e) => fail("errore imprevisto", e.stack || e.message || String(e)));
