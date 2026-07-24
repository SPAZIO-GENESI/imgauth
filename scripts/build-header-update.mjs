// Aggiorna la testata e il credito del template (IT ed EN), su richiesta del
// gestore: nuovo logo, titolo su due righe, sottotitolo senza "L'Aquila" con
// monogramma, credito "Design and Logo by Manuela Valloscuro" con link.
//
// Il logo si sostituisce SENZA toccare il content stream: la Resources/XObject
// dict rimappa la chiave /Im1 (invocata da "/Im1 Do" nel content stream, già
// presente) a una nuova immagine — stesso riquadro, nessun edit di stream.
//
// Titolo, sottotitolo e credito erano testo glyph-encoded in un font
// sottoinsieme (mancano W/K/Y/U — vedi build-template-en.mjs): non si riscrive
// sul posto. Si SVUOTANO i run vecchi e si ridisegna con pdf-lib/Times
// standard (font completo, nessun rischio di glifi mancanti) — stessa tecnica
// già usata per le etichette EN nel corpo.
import { readFileSync, writeFileSync } from "node:fs";
import zlib from "node:zlib";
import { PDFDocument, PDFName, PDFString, StandardFonts, rgb } from "pdf-lib";

const GID_OFFSET = 29;
const enc = (s) =>
  [...s].map((ch) => (ch.charCodeAt(0) - GID_OFFSET).toString(16).padStart(4, "0").toUpperCase()).join("");

const grigio = rgb(0.478, 0.439, 0.376);
const oro = rgb(0.545, 0.412, 0.078);
const inchiostro = rgb(0.102, 0.102, 0.102);

async function aggiornaTestata(inputPath, outputPath, { titolo, sottotitolo, creditoPrefisso, opts }) {
  const doc = await PDFDocument.load(readFileSync(inputPath));
  const page = doc.getPage(0);
  const pageW = page.getWidth();

  // ── 1) Logo: rimappa /Im1 alla nuova immagine, stesso riquadro ────────────
  const logoBytes = readFileSync(new URL("../assets/logo-attestazione.png", import.meta.url));
  const logoImg = await doc.embedPng(logoBytes);
  const xobj = doc.context.lookup(page.node.Resources().get(PDFName.of("XObject")));
  xobj.set(PDFName.of("Im1"), logoImg.ref);

  // ── 2) Svuota i run vecchi da rimuovere (testo, non immagine) ─────────────
  const stream = doc.context.lookup(page.node.get(PDFName.of("Contents")));
  let content = zlib.inflateSync(Buffer.from(stream.contents)).toString("latin1");
  const svuota = (label, hexPrefix) => {
    const re = hexPrefix
      ? new RegExp(`<${enc(label)}[0-9A-F]*>\\s*Tj`)
      : new RegExp(`<${enc(label)}>\\s*Tj`);
    const prima = content;
    content = content.replace(re, "<>Tj");
    if (content === prima) throw new Error(`run non trovato: "${label}"`);
  };
  svuota("CERTIFICATO DI");
  svuota("ATTESTAZIONE");
  svuota("OPERA DIGITALE");
  svuota("Spazio Genesi ETS ", true); // prefisso: il resto contiene l'em-dash non ASCII
  svuota("Realizzato da ");
  svuota("tangram.page");
  svuota(" - Design by ");
  svuota("mentesutela.it");

  // Icona penna/tangram (Im2) accanto al vecchio credito: rimossa dal blocco
  // "q ... /Im2 Do ... Q" del content stream. Il primo tentativo la copriva
  // con un rettangolo color-carta, che però tagliava un pezzo visibile della
  // filigrana "SPAZIO GENESI ETS" sullo sfondo (quadrato bianco segnalato dal
  // gestore) — rimuoverla è pulito e non lascia alcun artefatto.
  const im2Re = /q\s+18\.7619781 0 0 18\.8105316 195\.8364868 276\.3939209 cm\s*\/Im2 Do\s*Q\s*/;
  if (!im2Re.test(content)) throw new Error("blocco Im2 non trovato");
  content = content.replace(im2Re, "");

  const nuovoStream = doc.context.flateStream(Uint8Array.from(Buffer.from(content, "latin1")));
  page.node.set(PDFName.of("Contents"), doc.context.register(nuovoStream));

  // ── 3) Ridisegna testata e credito con pdf-lib (font pieno, coordinate note) ─
  const bold = await doc.embedFont(StandardFonts.TimesRomanBold);
  const regular = await doc.embedFont(StandardFonts.TimesRoman);
  const boldItalic = await doc.embedFont(StandardFonts.TimesRomanBoldItalic);

  // Titolo su due righe. Centrato NON sull'intera pagina ma nello spazio
  // libero fra il bordo destro del logo (~166pt) e il bordo sinistro del QR
  // (438pt, vedi Im0): a 18pt "CERTIFICATO DI ATTESTAZIONE" (291pt) e
  // "DIGITAL WORK ATTESTATION" (268pt) sforano quel gap di ~272pt — 16pt
  // (259pt/238pt) rientra con margine su entrambe le lingue.
  const [riga1, riga2] = titolo;
  const y1 = 730, y2 = 706;
  const gapCenter = (166 + 438) / 2;
  const titleSize = 16;
  for (const [testo, y] of [[riga1, y1], [riga2, y2]]) {
    const w = bold.widthOfTextAtSize(testo, titleSize);
    page.drawText(testo, { x: gapCenter - w / 2, y, size: titleSize, font: bold, color: inchiostro });
  }

  // Sottotitolo: monogramma + "Spazio Genesi ETS" (senza città), centrati insieme
  const monoBytes = readFileSync(new URL("../assets/monogramma.png", import.meta.url));
  const monoImg = await doc.embedPng(monoBytes);
  const subSize = 10;
  const subW = regular.widthOfTextAtSize(sottotitolo, subSize);
  const monoH = 12, monoW = (monoImg.width / monoImg.height) * monoH;
  const gap = 5;
  const totW = monoW + gap + subW;
  const subX = (pageW - totW) / 2;
  const subY = 662;
  page.drawImage(monoImg, { x: subX, y: subY - 1, width: monoW, height: monoH });
  page.drawText(sottotitolo, { x: subX + monoW + gap, y: subY, size: subSize, font: regular, color: grigio });

  // Credito: "Design and Logo by " (grigio) + "Manuela Valloscuro" (oro, link)
  const p1 = creditoPrefisso;
  const p2 = "Manuela Valloscuro";
  const creditoSize = 7;
  const w1 = regular.widthOfTextAtSize(p1, creditoSize);
  const w2 = boldItalic.widthOfTextAtSize(p2, creditoSize);
  const totCredW = w1 + w2;
  const credX = (pageW - totCredW) / 2;
  const credY = 282.85;
  page.drawText(p1, { x: credX, y: credY, size: creditoSize, font: regular, color: grigio });
  page.drawText(p2, { x: credX + w1, y: credY, size: creditoSize, font: boldItalic, color: oro });

  // Link cliccabile sul nome
  const linkAnnot = doc.context.obj({
    Type: "Annot",
    Subtype: "Link",
    Rect: [credX + w1, credY - 2, credX + w1 + w2, credY + 8],
    Border: [0, 0, 0],
    A: { Type: "Action", S: "URI", URI: PDFString.of("https://manuelavalloscuro.spaziogenesi.org") },
  });
  const linkRef = doc.context.register(linkAnnot);
  let annots = page.node.lookup(PDFName.of("Annots"));
  if (!annots) {
    annots = doc.context.obj([]);
    page.node.set(PDFName.of("Annots"), annots);
  }
  annots.push(linkRef);

  // pdf-lib mette i drawText/drawImage in nuovi content stream, separati da
  // quello che abbiamo scritto a mano: Contents diventa un array. È PDF
  // valido — i visualizzatori (Acrobat, pdf.js) concatenano gli stream alla
  // resa — quindi si salva così, senza fonderli.
  const out = await doc.save({ useObjectStreams: false });
  writeFileSync(outputPath, out);
  console.log(`${outputPath}: ${out.length} byte`);
}

const itUrl = new URL("../certificato_opera_pdf_mod.pdf", import.meta.url);
const enUrl = new URL("../certificato_opera_pdf_en.pdf", import.meta.url);

await aggiornaTestata(itUrl, itUrl, {
  titolo: ["CERTIFICATO DI ATTESTAZIONE", "OPERA / FILE DIGITALE"],
  sottotitolo: "Spazio Genesi ETS",
  creditoPrefisso: "Design e Logo by ",
});

await aggiornaTestata(enUrl, enUrl, {
  titolo: ["DIGITAL WORK ATTESTATION", "CERTIFICATE"],
  sottotitolo: "Spazio Genesi ETS",
  creditoPrefisso: "Design and Logo by ",
});

console.log("Testata aggiornata su entrambi i template.");
