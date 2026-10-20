// Test di imgauth (node:test, zero dipendenze). Entrano dalla porta pubblica
// del Worker — `default.fetch(request, env, ctx)` — con un `env` finto.
//
// Regole:
//  - TEST_SECRET è un valore di PROVA scritto qui: mai il vero HMAC_SECRET.
//  - Le impronte usate sono stringhe fabbricate in questo file: nessuna
//    impronta di un'opera reale.
//  - I valori attesi si calcolano con node:crypto sulla stringa canonica
//    scritta a mano, NON con le funzioni del Worker: se il Worker cambiasse
//    ciò che firma, il test lo vedrebbe.
//  - Non c'è R2, non c'è rete, e D1 è un finto di una riga: cosa NON è coperto
//    è elencato nel README.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import worker from "../worker.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const TEST_SECRET = "segreto-di-prova-solo-per-i-test";
const SHA = "ab".repeat(32); // impronta fabbricata, non di un'opera reale
const ctx = { waitUntil() {} };
const env = (extra = {}) => ({ HMAC_SECRET: TEST_SECRET, ...extra });

const hmacB64 = (message, secret = TEST_SECRET) =>
  createHmac("sha256", secret).update(message, "utf8").digest("base64");

const post = (path, body, headers = {}, e = env()) =>
  worker.fetch(
    new Request(`https://x.test${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    e,
    ctx,
  );

const verify = (fields, e = env()) => {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.set(k, v);
  return worker.fetch(new Request("https://x.test/api/verify", { method: "POST", body: form }), e, ctx);
};

const attest = async (extra = {}, e = env()) => {
  const res = await post("/api/hash", { sha256: SHA, ...extra }, {}, e);
  assert.equal(res.status, 200);
  return res.json();
};

// ── /ping ───────────────────────────────────────────────────────────────────

test("/ping risponde con la versione di package.json", async () => {
  const res = await worker.fetch(new Request("https://x.test/ping"), env(), ctx);
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.equal(j.version, pkg.version);
});

// ── Stringa canonica firmata (vettori fissi) ────────────────────────────────

test("senza metadati né riserva si firma la sola stringa di attestazione", async () => {
  const j = await attest();
  assert.equal(j.attestazione, `SHA-256:${SHA}@${j.timestamp_iso}`);
  assert.equal(j.hmac, hmacB64(`SHA-256:${SHA}@${j.timestamp_iso}`));
  assert.equal(j.riserva, null);
});

test("con metadati: righe canoniche titolo/autore/anno/note dopo l'attestazione", async () => {
  const j = await attest({ titolo: "Titolo", autore: "Autrice", anno: "2026", note: "nota" });
  const msg = `SHA-256:${SHA}@${j.timestamp_iso}\ntitolo:Titolo\nautore:Autrice\nanno:2026\nnote:nota`;
  assert.equal(j.hmac, hmacB64(msg));
});

test("con metadati parziali le righe vuote restano nel messaggio, in ordine fisso", async () => {
  const j = await attest({ autore: "Solo Autore" });
  const msg = `SHA-256:${SHA}@${j.timestamp_iso}\ntitolo:\nautore:Solo Autore\nanno:\nnote:`;
  assert.equal(j.hmac, hmacB64(msg));
});

test("la riserva è l'ultima riga: da sola e dopo i metadati", async () => {
  const solo = await attest({ riserva: "notAllowed" });
  assert.equal(solo.hmac, hmacB64(`SHA-256:${SHA}@${solo.timestamp_iso}\nriserva:notAllowed`));

  const conMeta = await attest({ titolo: "T", riserva: "constrained" });
  const msg = `SHA-256:${SHA}@${conMeta.timestamp_iso}\ntitolo:T\nautore:\nanno:\nnote:\nriserva:constrained`;
  assert.equal(conMeta.hmac, hmacB64(msg));
});

test("INVARIANTE: lang non entra nella firma (it, en e assente firmano allo stesso modo)", async () => {
  for (const lang of ["it", "en", undefined]) {
    const j = await attest(lang ? { lang } : {});
    assert.equal(j.hmac, hmacB64(`SHA-256:${SHA}@${j.timestamp_iso}`), `lang=${lang}`);
    // e la verifica non ha un parametro lang: la firma si valida comunque
    const v = await (await verify({ hash: SHA, attestazione: j.attestazione, hmac: j.hmac })).json();
    assert.equal(v.hmac_valido, true, `lang=${lang}`);
  }
});

// ── Andata e ritorno /api/hash → /api/verify ────────────────────────────────

test("round-trip: il token emesso da /api/hash è accettato da /api/verify", async () => {
  const j = await attest({ titolo: "T", autore: "A", anno: "2026", note: "n", riserva: "allowed" });
  const v = await (
    await verify({
      hash: SHA, attestazione: j.attestazione, hmac: j.hmac,
      titolo: "T", autore: "A", anno: "2026", note: "n", riserva: "allowed",
    })
  ).json();
  assert.equal(v.hmac_valido, true);
  assert.equal(v.hash_dichiarato, SHA);
  assert.equal(v.coincide, null); // senza file il confronto spetta al client
});

test("token manomesso: attestazione, firma, metadati o riserva alterati → hmac_valido false", async () => {
  const j = await attest({ titolo: "T", riserva: "notAllowed" });
  const base = { hash: SHA, attestazione: j.attestazione, hmac: j.hmac, titolo: "T", riserva: "notAllowed" };
  assert.equal((await (await verify(base)).json()).hmac_valido, true);

  const altroHash = "cd".repeat(32);
  const casi = {
    "hash nell'attestazione": { attestazione: j.attestazione.replace(SHA, altroHash) },
    "timestamp": { attestazione: j.attestazione.replace(/@.*$/, "@2000-01-01T00:00:00Z") },
    "firma di un altro segreto": { hmac: hmacB64(j.attestazione, "altro-segreto") },
    "titolo": { titolo: "Altro" },
    "riserva": { riserva: "allowed" },
    "riserva rimossa": { riserva: "" },
  };
  for (const [nome, patch] of Object.entries(casi)) {
    const v = await (await verify({ ...base, ...patch })).json();
    assert.equal(v.hmac_valido, false, nome);
  }
});

test("senza HMAC_SECRET /api/hash non firma e /api/verify non esprime un giudizio", async () => {
  const j = await attest({}, {});
  assert.equal(j.hmac, null);
  const v = await (await verify({ hash: SHA, attestazione: j.attestazione, hmac: "AAAA" }, {})).json();
  assert.equal(v.hmac_valido, null);
});

// ── Il timestamp lo genera il server ────────────────────────────────────────

test("un timestamp inviato dal client è ignorato", async () => {
  const prima = Date.now();
  const j = await attest({
    timestamp: "2000-01-01T00:00:00Z",
    timestamp_iso: "2000-01-01T00:00:00Z",
    attestazione: `SHA-256:${SHA}@2000-01-01T00:00:00Z`,
  });
  const t = Date.parse(j.timestamp_iso);
  assert.ok(t >= prima - 1000 && t <= Date.now() + 1000, `timestamp ${j.timestamp_iso} non è "adesso"`);
  assert.ok(!j.attestazione.includes("2000-01-01"));
});

// ── Formato in ingresso, cleanMeta, cleanRiserva ────────────────────────────

test("impronta malformata → 400, senza emettere nulla", async () => {
  for (const sha256 of ["xyz", "ab".repeat(31), "zz".repeat(32)]) {
    const res = await post("/api/hash", { sha256 });
    assert.equal(res.status, 400, sha256);
    assert.equal((await res.json()).hmac, undefined);
  }
  assert.equal((await post("/api/hash", {})).status, 400);
});

test("l'impronta maiuscola è normalizzata in minuscolo prima di firmare", async () => {
  const j = await attest({ sha256: SHA.toUpperCase() });
  assert.equal(j.sha256, SHA);
  assert.equal(j.hmac, hmacB64(`SHA-256:${SHA}@${j.timestamp_iso}`));
});

test("cleanMeta: whitespace collassato, caratteri fuori WinAnsi scartati, tetto di lunghezza", async () => {
  const j = await attest({
    titolo: "  Due\n\n righe\t\tcon   spazi \u{1F3A8} e “virgolette”  ",
    autore: "A".repeat(500),
    note: "n".repeat(500),
  });
  assert.equal(j.titolo, "Due righe con spazi e “virgolette”");
  assert.equal(j.autore.length, 100);
  assert.equal(j.note.length, 300);
  // ciò che è stato firmato è la forma canonica pulita, non l'input grezzo
  const msg = `SHA-256:${SHA}@${j.timestamp_iso}\ntitolo:${j.titolo}\nautore:${j.autore}\nanno:\nnote:${j.note}`;
  assert.equal(j.hmac, hmacB64(msg));
});

test("cleanRiserva: valori noti accettati, ignoto o vuoto → assente, mai un errore", async () => {
  for (const v of ["notAllowed", "constrained", "allowed"]) {
    assert.equal((await attest({ riserva: v })).riserva, v);
  }
  for (const v of ["", "  ", "NOTALLOWED", "boh", 42, null]) {
    const j = await attest({ riserva: v });
    assert.equal(j.riserva, null, JSON.stringify(v));
    assert.equal(j.hmac, hmacB64(`SHA-256:${SHA}@${j.timestamp_iso}`));
  }
});

// ── /api/cert-pdf fail-closed ───────────────────────────────────────────────

const certBody = async (extra = {}) => {
  const j = await attest();
  return { sha256: j.sha256, timestamp_iso: j.timestamp_iso, attestazione: j.attestazione, hmac: j.hmac, ...extra };
};

test("cert-pdf: senza HMAC_SECRET risponde 503 (fail-closed)", async () => {
  const res = await post("/api/cert-pdf", await certBody(), {}, {});
  assert.equal(res.status, 503);
});

test("cert-pdf: campi mancanti o malformati → 400", async () => {
  const b = await certBody();
  for (const patch of [{ hmac: "" }, { attestazione: "" }, { sha256: "nope" }, { timestamp_iso: "ieri" }]) {
    assert.equal((await post("/api/cert-pdf", { ...b, ...patch })).status, 400, JSON.stringify(patch));
  }
});

test("cert-pdf: attestazione incoerente con sha256 + timestamp_iso → 400", async () => {
  const b = await certBody();
  const altro = "cd".repeat(32);
  assert.equal((await post("/api/cert-pdf", { ...b, sha256: altro })).status, 400);
  assert.equal((await post("/api/cert-pdf", { ...b, timestamp_iso: "2000-01-01T00:00:00Z" })).status, 400);
});

test("cert-pdf: firma non valida (altro segreto, metadati o riserva aggiunti dopo) → 403", async () => {
  const b = await certBody();
  const firmataAltrove = { ...b, hmac: hmacB64(b.attestazione, "altro-segreto") };
  assert.equal((await post("/api/cert-pdf", firmataAltrove)).status, 403);
  // il token valido non copre metadati o riserva aggiunti dopo
  assert.equal((await post("/api/cert-pdf", { ...b, titolo: "Aggiunto dopo" })).status, 403);
  assert.equal((await post("/api/cert-pdf", { ...b, riserva: "notAllowed" })).status, 403);
});

// ── Percorso bearer: fail-closed, mai fallback a Turnstile ──────────────────

test("bearer malformato → 403, anche se Turnstile è configurato", async () => {
  const res = await post("/api/hash", { sha256: SHA }, { Authorization: "Bearer non-una-credenziale" }, env({ TURNSTILE_SECRET: "x" }));
  assert.equal(res.status, 403);
  assert.equal((await res.json()).hmac, undefined);
});

test("bearer ben formato ma sconosciuto → 403 (D1 finto che non trova la riga)", async () => {
  const DB = { prepare: () => ({ bind: () => ({ first: async () => null }) }) };
  const bearer = `Bearer sg_k_${"0".repeat(8)}_${"a".repeat(32)}`;
  const res = await post("/api/hash", { sha256: SHA }, { Authorization: bearer }, env({ DB, TURNSTILE_SECRET: "x" }));
  assert.equal(res.status, 403);
});

test("senza bearer e con Turnstile configurato, il token anti-bot è obbligatorio", async () => {
  const res = await post("/api/hash", { sha256: SHA }, {}, env({ TURNSTILE_SECRET: "x" }));
  assert.equal(res.status, 400);
});
