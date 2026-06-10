// Corregge UNA VOLTA il template certificato_opera_pdf_mod.pdf:
// rimuove dal content stream della pagina i due testi ERRATI ereditati dal
// template originale (URL di verifica e indirizzo), così che non siano più
// estraibili via copia-incolla. I testi corretti vengono ridisegnati a runtime
// dal worker, nelle stesse coordinate/colori. Label e crediti restano intatti
// (gli offset Td usano la text-line-matrix, indipendente dalla larghezza testo).
import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import zlib from "node:zlib";
import { PDFDocument, PDFName } from "pdf-lib";

const tplUrl  = new URL("../certificato_opera_pdf_mod.pdf", import.meta.url);
const origUrl = new URL("../certificato_opera_pdf_mod.orig.pdf", import.meta.url);

// Sorgente = backup pristino (.orig.pdf). Lo si crea una sola volta dal template
// committato; le esecuzioni successive ripartono sempre da lì (idempotente).
if (!existsSync(origUrl)) copyFileSync(tplUrl, origUrl);

const buf = readFileSync(origUrl);
const doc = await PDFDocument.load(buf);
const page = doc.getPage(0);

// Risolvi il content stream della pagina
let contentsRef = page.node.get(PDFName.of("Contents"));
let stream = doc.context.lookup(contentsRef);
const rawEncoded = stream.contents; // bytes (FlateDecode)
let content = zlib.inflateSync(Buffer.from(rawEncoded)).toString("latin1");

// I run da svuotare, individuati per prefisso hex univoco (vedi decode-footer.mjs)
const targets = [
  { name: "URL https://…wo",        re: /<004B0057005700530056001D[0-9A-Fa-f]*>/ },
  { name: "URL …rker",              re: /<0055004E00480055>/ },
  { name: "URL s.dev/api/verify",   re: /<005600110047004800590012[0-9A-Fa-f]*>/ },
  // Solo il footer ("Spazio Genesi ETS – Centro Commerciale L'Aquilone…").
  // NON il sottotitolo header "Spazio Genesi ETS — L'Aquila" (corretto, da tenere).
  { name: "Indirizzo footer (Centro…Aquilone)", re: /<003600530044005D004C00520003002A0048005100480056004C0003002800370036000301010003002600480051005700550052[0-9A-Fa-f]*>/ },
];

for (const t of targets) {
  const before = content;
  content = content.replace(t.re, "<>");
  if (content === before) throw new Error(`NON trovato: ${t.name}`);
  console.log(`svuotato: ${t.name}`);
}

// Re-encode in un nuovo stream Flate e ripunta /Contents (pdf-lib ricalcola xref/Length)
const newBytes = Uint8Array.from(Buffer.from(content, "latin1"));
const newStream = doc.context.flateStream(newBytes);
const newRef = doc.context.register(newStream);
page.node.set(PDFName.of("Contents"), newRef);

const out = await doc.save({ useObjectStreams: false });
writeFileSync(tplUrl, out);
console.log(`Template aggiornato: ${out.length} byte`);
