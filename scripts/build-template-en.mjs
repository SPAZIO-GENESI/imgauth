// Genera certificato_opera_pdf_en.pdf — la versione INGLESE del template del
// certificato — partendo da quello italiano già patchato.
//
// COSA FA: **svuota** dal content stream i run glyph-encoded delle etichette
// italiane (titolo, intestazioni di sezione, etichette di riga, riga sotto il QR).
// Le etichette inglesi NON vengono scritte qui: le disegna il worker a runtime
// (`EN_LABELS` in worker.js), nelle stesse coordinate, corpo e colore.
//
// PERCHÉ NON SI RISCRIVE IL TESTO AL SUO POSTO: il primo tentativo sostituiva i
// run con l'inglese codificato negli stessi glyph id (GID = ASCII - 29, mappatura
// verificata decodificando l'intero stream). Funziona solo per le lettere che il
// testo italiano già usa: il font incorporato è un **sottoinsieme** e i glifi
// W, K, Y, U non ci sono. Il risultato era leggibile ma sbagliato — "DIGITAL OR",
// "MIME T PE", "H MAN-READABLE" — e NON lo si vedeva estraendo il testo con
// pdftotext: è emerso solo rendendo la pagina a immagine. Da qui la scelta di
// ridisegnare a runtime con Times Roman standard, metricamente equivalente al
// Times New Roman del template.
//
// Restano volutamente invariati: il sottotitolo "Spazio Genesi ETS — L'Aquila"
// (nome dell'ente e sede), il credito tangram.page/mentesutela.it (è una firma),
// la filigrana e il numero di pagina.
//
// Idempotente: riparte sempre da certificato_opera_pdf_mod.pdf, mai dal proprio
// output. Da rieseguire se il template italiano cambia.
import { readFileSync, writeFileSync } from "node:fs";
import zlib from "node:zlib";
import { PDFDocument, PDFName } from "pdf-lib";

const srcUrl = new URL("../certificato_opera_pdf_mod.pdf", import.meta.url);
const outUrl = new URL("../certificato_opera_pdf_en.pdf", import.meta.url);

const GID_OFFSET = 29;
const enc = (s) =>
  [...s]
    .map((ch) => {
      const code = ch.charCodeAt(0);
      if (code < 32 || code > 126) throw new Error(`carattere non ASCII in "${s}"`);
      return (code - GID_OFFSET).toString(16).padStart(4, "0").toUpperCase();
    })
    .join("");

// Etichette da svuotare. L'ordine non conta: ognuna è cercata per il proprio run.
// Il titolo (3 righe) NON è più in questa lista: da P42 la testata (logo,
// titolo, sottotitolo, credito) è gestita da build-header-update.mjs, che va
// eseguito DOPO questo script — opera sul body soltanto.
const DA_SVUOTARE = [
  "DATI DELL'OPERA",
  "OPERA",
  "DIMENSIONE",
  "TIPO MIME",
  "IMPRONTA CRITTOGRAFICA",
  "TIMESTAMP ISO 8601",
  "TIMESTAMP LEGGIBILE",
  "STRINGA DI ATTESTAZIONE",
];
// SHA-256 resta com'è: è un nome di algoritmo, identico nelle due lingue.

const doc = await PDFDocument.load(readFileSync(srcUrl));
const page = doc.getPage(0);
const streamRef = page.node.get(PDFName.of("Contents"));
let content = zlib
  .inflateSync(Buffer.from(doc.context.lookup(streamRef).contents))
  .toString("latin1");

let svuotate = 0;
for (const label of DA_SVUOTARE) {
  // Match esatto del run (delimitato da <>): evita che "OPERA" colpisca anche
  // "OPERA DIGITALE" o "DATI DELL'OPERA", che sono run distinti e più lunghi.
  const re = new RegExp(`<${enc(label)}>(\\s*Tj)`);
  if (!re.test(content)) throw new Error(`etichetta non trovata: "${label}"`);
  content = content.replace(re, "<>$1");
  svuotate++;
  console.log(`  svuotata: "${label}"`);
}

// Riga sotto il QR: contiene "à" (glifo non ASCII), quindi si individua per prefisso.
const qrRe = new RegExp(`<${enc("Per verificare l'autenticit")}[0-9A-F]*>(\\s*Tj)`);
if (!qrRe.test(content)) throw new Error("riga del QR non trovata");
content = content.replace(qrRe, "<>$1");
svuotate++;
console.log(`  svuotata: "Per verificare l'autenticità …"`);

const nuovoStream = doc.context.flateStream(Uint8Array.from(Buffer.from(content, "latin1")));
page.node.set(PDFName.of("Contents"), doc.context.register(nuovoStream));

const out = await doc.save({ useObjectStreams: false });
writeFileSync(outUrl, out);
console.log(`\n${svuotate} etichette svuotate — template inglese: ${out.length} byte`);
console.log("Le etichette inglesi sono disegnate a runtime: vedi EN_LABELS in worker.js");
