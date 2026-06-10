import { readFileSync, writeFileSync } from "node:fs";
import zlib from "node:zlib";
import { PDFDocument, PDFName, rgb, StandardFonts } from "pdf-lib";

const tplUrl = new URL("../certificato_opera_pdf_mod.pdf", import.meta.url);
const buf = readFileSync(tplUrl);
const doc = await PDFDocument.load(buf);

// 1) Campi AcroForm ancora presenti?
const form = doc.getForm();
console.log("Campi form:", form.getFields().map(f => f.getName()).join(", "));

// 2) Vecchi testi spariti dal content stream?
const page = doc.getPage(0);
const stream = doc.context.lookup(page.node.get(PDFName.of("Contents")));
const content = zlib.inflateSync(Buffer.from(stream.contents)).toString("latin1");
for (const [label, hex, wantGone] of [
  ["URL https://…wo (footer)", "004B0057005700530056001D", true],
  ["URL …rker (footer)", "0055004E00480055", true],
  ["URL s.dev/verify (footer)", "005600110047004800590012", true],
  ["Indirizzo footer (…Centro Aquilone)", "003600530044005D004C00520003002A0048005100480056004C0003002800370036000301010003002600480051005700550052", true],
  ["Sottotitolo header (Spazio Genesi ETS — L'Aquila)", "003600530044005D004C00520003002A0048005100480056004C0003002800370036000300B2", false],
]) {
  const present = content.includes(hex);
  const ok = wantGone ? !present : present;
  console.log(`  ${ok ? "✓" : "✗ ATTESO " + (wantGone ? "rimosso" : "presente")} ${label}: ${present ? "presente" : "assente"}`);
}

// 3) Simula il footer del worker e misura larghezza indirizzo
const font = await doc.embedFont(StandardFonts.TimesRoman);
const addr = "Spazio Genesi ETS – Galleria Commerciale Via Roma, 215, primo piano, L'Aquila (AQ) – Documento generato automaticamente — non richiede firma manuale.";
const w7 = font.widthOfTextAtSize(addr, 7);
console.log(`\nLarghezza indirizzo @7pt: ${w7.toFixed(1)}pt  (da x=97.3 → fino a x=${(97.306 + w7).toFixed(1)}; margine destro pagina utile ≈ 561)`);
const w65 = font.widthOfTextAtSize(addr, 6.5);
console.log(`Larghezza indirizzo @6.5pt: ${w65.toFixed(1)}pt → fino a x=${(97.306 + w65).toFixed(1)}`);

// Disegna e salva un campione per ispezione testo
const sampleHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
form.getTextField("TITOLO").setText("Opera di prova");
form.getTextField("SHA-256").setText(sampleHash);
form.flatten();
const verifyUrl = "https://attestazione.spaziogenesi.org?hash=" + sampleHash;
const pageW = page.getWidth();
const drawCentered = (text, y, size, color) => {
  const w = font.widthOfTextAtSize(text, size);
  page.drawText(text, { x: (pageW - w) / 2, y, size, font, color });
  console.log(`  centrato "${text.slice(0, 30)}…" @${size}pt: x=${((pageW - w) / 2).toFixed(1)} larghezza=${w.toFixed(1)} (fine x=${((pageW + w) / 2).toFixed(1)})`);
};
drawCentered(addr, 302.854, 7, rgb(0.478, 0.439, 0.376));
drawCentered(verifyUrl, 324.358, 7, rgb(0.545, 0.412, 0.078));
const out = await doc.save();
writeFileSync(new URL("./footer-sample.pdf", import.meta.url), out);

// 4) Estrai testo dal campione e verifica copia-incolla
const doc2bytes = out;
let idx = 0, found = { newAddr: false, newUrl: false, oldAddr: false, oldUrl: false };
const s = Buffer.from(doc2bytes);
while (true) {
  const st = s.indexOf("stream", idx); if (st === -1) break;
  let ds = st + 6; if (s[ds] === 0x0d) ds++; if (s[ds] === 0x0a) ds++;
  const en = s.indexOf("endstream", ds); if (en === -1) break;
  idx = en + 9;
  let txt; try { txt = zlib.inflateSync(s.subarray(ds, en)).toString("latin1"); } catch { txt = s.subarray(ds, en).toString("latin1"); }
  // Ricostruisci il testo "leggibile" decodificando le hex string <..> dei font standard (WinAnsi≈latin1)
  let plain = txt.replace(/<([0-9A-Fa-f\s]+)>/g, (_, h) => {
    const hex = h.replace(/\s/g, "");
    let o = ""; for (let i = 0; i + 1 < hex.length; i += 2) o += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    return o;
  });
  const hay = txt + "\n" + plain;
  if (hay.includes("Via Roma, 215")) found.newAddr = true;
  if (hay.includes("attestazione.spaziogenesi.org")) found.newUrl = true;
  if (hay.includes("Aquilone")) found.oldAddr = true;
  if (hay.includes("workers.dev") || hay.includes("spazio-genesi.wo")) found.oldUrl = true;
}
console.log("\nEstrazione testo dal PDF generato (= cosa ottiene chi copia-incolla):");
console.log(`  nuovo indirizzo presente: ${found.newAddr ? "✓" : "✗"}`);
console.log(`  nuovo URL presente:       ${found.newUrl ? "✓" : "✗"}`);
console.log(`  vecchio indirizzo:        ${found.oldAddr ? "ANCORA ✗" : "assente ✓"}`);
console.log(`  vecchio URL:              ${found.oldUrl ? "ANCORA ✗" : "assente ✓"}`);
