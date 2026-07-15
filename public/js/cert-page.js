// Pulsante "copia" della pagina pubblica GET /c/<sha256>. File esterno, non
// handler onclick inline: la CSP impostata all'edge (script-src senza
// 'unsafe-inline') blocca anche gli attributi evento inline. Caricato con
// src ASSOLUTA (API_BASE) perché la pagina risponde anche su
// attestazione.spaziogenesi.org via route /c/*, dove /js/* non è instradato
// al Worker (e authweb ha una propria cartella js/).
(function () {
  Array.prototype.forEach.call(document.querySelectorAll("button.copy[data-hash]"), function (btn) {
    btn.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(btn.dataset.hash).then(function () { btn.textContent = "copiato"; });
    });
  });
})();
