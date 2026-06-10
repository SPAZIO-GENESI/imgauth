import zlib from "node:zlib";
import { writeFileSync } from "node:fs";

const BASE = "https://imgauth.spaziogenesi.org";
// PNG 1x1 in base64
const img = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/aBLAAAAAElFTkSuQmCC";

const h = await (await fetch(BASE + "/api/hash", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "smoke-test.png", type: "image/png", image: img }),
})).json();
console.log("hash:", h.sha256);

const res = await fetch(BASE + "/api/cert-pdf", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify(h),
});
if (!res.ok) { console.log("cert-pdf FALLITO:", res.status, await res.text()); process.exit(1); }
const bytes = Buffer.from(await res.arrayBuffer());
writeFileSync(new URL("./smoke-prod.pdf", import.meta.url), bytes);
console.log("PDF ricevuto:", bytes.length, "byte");

// Estrai testo (inflate + decode hex string) e verifica footer
let idx = 0, found = { newAddr: false, newUrl: false, oldAddr: false, oldUrl: false, signed: false };
const s = bytes;
if (s.includes("/Type /Sig") || s.includes("/Sig") || s.includes("adbe.pkcs7")) found.signed = true;
while (true) {
  const st = s.indexOf("stream", idx); if (st === -1) break;
  let ds = st + 6; if (s[ds] === 0x0d) ds++; if (s[ds] === 0x0a) ds++;
  const en = s.indexOf("endstream", ds); if (en === -1) break; idx = en + 9;
  let txt; try { txt = zlib.inflateSync(s.subarray(ds, en)).toString("latin1"); } catch { txt = s.subarray(ds, en).toString("latin1"); }
  const plain = txt.replace(/<([0-9A-Fa-f\s]+)>/g, (_, hh) => {
    const hex = hh.replace(/\s/g, ""); let o = "";
    for (let i = 0; i + 1 < hex.length; i += 2) o += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    return o;
  });
  const hay = txt + "\n" + plain;
  if (hay.includes("Via Roma, 215")) found.newAddr = true;
  if (hay.includes("attestazione.spaziogenesi.org")) found.newUrl = true;
  if (hay.includes("Aquilone")) found.oldAddr = true;
  if (hay.includes("workers.dev") || hay.includes("spazio-genesi.wo")) found.oldUrl = true;
}
console.log("\nCertificato di PRODUZIONE:");
console.log("  firmato (PKCS#7):       ", found.signed ? "✓" : "(no signer?)");
console.log("  nuovo indirizzo:        ", found.newAddr ? "✓" : "✗");
console.log("  URL footer:             ", found.newUrl ? "✓" : "✗");
console.log("  vecchio indirizzo:      ", found.oldAddr ? "ANCORA ✗" : "assente ✓");
console.log("  vecchio URL:            ", found.oldUrl ? "ANCORA ✗" : "assente ✓");
