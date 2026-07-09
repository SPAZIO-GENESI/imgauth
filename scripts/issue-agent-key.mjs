#!/usr/bin/env node
// Emette una nuova API key agente ("convenzione"), vedi P21-DESIGN §2.4.
//
// Uso:
//   node scripts/issue-agent-key.mjs --label "Convenzione Accademia X" [--quota 200] [--apply] [--remote]
//
// Senza --apply: stampa solo la chiave e l'SQL da eseguire a mano.
// Con --apply (senza --remote): scrive subito sulla D1 LOCALE (sicuro per test
// con `wrangler dev`). Con --apply --remote: scrive sulla D1 di PRODUZIONE —
// non lanciarlo senza conferma esplicita dell'utente (vedi CLAUDE.md).
//
// La chiave (sg_k_<id>_<secret>) è stampata UNA SOLA VOLTA: non è recuperabile
// in seguito, in D1 finisce solo il suo hash. Se persa, va revocata e riemessa:
//   wrangler d1 execute imgauth-health --remote --command \
//     "UPDATE agent_credentials SET revoked=1 WHERE id='<id>'"

import { randomBytes, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function parseArgs(argv) {
  const out = { quota: 200, apply: false, remote: false, label: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--label") out.label = argv[++i];
    else if (a === "--quota") out.quota = parseInt(argv[++i], 10);
    else if (a === "--apply") out.apply = true;
    else if (a === "--remote") out.remote = true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.label) {
  console.error('Uso: node scripts/issue-agent-key.mjs --label "Convenzione X" [--quota 200] [--apply] [--remote]');
  process.exit(1);
}
if (!Number.isFinite(args.quota) || args.quota <= 0) {
  console.error("--quota deve essere un intero positivo.");
  process.exit(1);
}

const id        = randomBytes(4).toString("hex");       // 8 hex
const secret    = randomBytes(32).toString("base64url"); // 32 byte
const key       = `sg_k_${id}_${secret}`;
const secretHash = createHash("sha256").update(secret).digest("hex");
const createdAt = new Date().toISOString();
const period    = createdAt.slice(0, 7); // 'YYYY-MM', per il reset mensile della quota

const labelEscaped = args.label.replace(/'/g, "''");
const sql = `INSERT INTO agent_credentials (id, kind, secret_hash, label, quota, used, period, expires_at, revoked, created_at) VALUES ('${id}', 'key', '${secretHash}', '${labelEscaped}', ${args.quota}, 0, '${period}', NULL, 0, '${createdAt}');`;

console.log("── Nuova API key agente ────────────────────────────────────────");
console.log("Chiave (mostrata UNA SOLA VOLTA — consegnala al partner ora):");
console.log("  " + key);
console.log("");
console.log(`id: ${id}  ·  quota: ${args.quota}/mese  ·  label: ${args.label}`);
console.log("");
console.log("SQL applicato/da applicare a D1 (contiene solo l'hash, mai il secret):");
console.log("  " + sql);

if (args.apply) {
  const target = args.remote ? "--remote" : "--local";
  console.log(`\nApplico su D1 imgauth-health (${target})…`);
  // --file (non --command): evita i problemi di quoting delle shell di Windows
  // con spazi/apici nell'SQL generato (es. nel label).
  const tmpFile = join(tmpdir(), `issue-agent-key-${id}.sql`);
  writeFileSync(tmpFile, sql, "utf8");
  try {
    execFileSync("npx", ["wrangler", "d1", "execute", "imgauth-health", target, `--file=${tmpFile}`], {
      stdio: "inherit",
      shell: process.platform === "win32",
    });
  } finally {
    unlinkSync(tmpFile);
  }
  console.log("Fatto.");
} else {
  console.log("\n(Non applicato: rilancia con --apply per scrivere sulla D1 locale, --apply --remote per produzione.)");
}
