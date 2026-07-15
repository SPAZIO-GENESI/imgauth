// Logica della pagina GET /agent/authorize (device flow P21).
// File esterno, non inline: la CSP impostata all'edge (Transform Rule
// security-headers, script-src senza 'unsafe-inline') copre anche le pagine
// servite dal Worker. Caricato con src ASSOLUTA (API_BASE) perché la pagina
// risponde anche su attestazione.spaziogenesi.org via route /agent/*, dove
// /js/* non è instradato al Worker (e authweb ha una propria cartella js/).
(function () {
  var body = document.getElementById("agentBody");
  var CODE = body.dataset.code;
  var SITEKEY = body.dataset.sitekey;
  var tsToken = "";
  window.onloadTurnstileCallback = function () {
    if (!window.turnstile) return;
    window.turnstile.render("#turnstileWidget", {
      sitekey: SITEKEY,
      action: "agent-authorize",
      callback: function (token) {
        tsToken = token;
        document.getElementById("agentApproveBtn").disabled = false;
      },
    });
  };
  document.getElementById("agentApproveBtn").addEventListener("click", async function () {
    var btn = this, msg = document.getElementById("agentMsg");
    btn.disabled = true;
    msg.textContent = "Autorizzazione in corso…";
    try {
      // URL ASSOLUTA, non relativa: questa pagina è servita su
      // attestazione.spaziogenesi.org via route Cloudflare /agent/*,
      // ma /api/agent/* su quel dominio NON è instradato al Worker
      // (risponde GitHub Pages, 405). Il CORS di imgauth consente già
      // l'origine attestazione. Bug latente da P21, scoperto al primo
      // approve reale dalla pagina (collaudo P26 FASE 4, 2026-07-12).
      var res = await fetch("https://imgauth.spaziogenesi.org/api/agent/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: CODE, turnstile_token: tsToken }),
      });
      if (!res.ok) throw new Error("http " + res.status);
      document.getElementById("agentBody").innerHTML = document.getElementById("agentSuccessTpl").innerHTML;
    } catch (e) {
      msg.textContent = "Autorizzazione non riuscita. Riprova.";
      btn.disabled = false;
      if (window.turnstile) window.turnstile.reset();
    }
  });
})();
