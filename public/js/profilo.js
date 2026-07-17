(function () {
  var voucherKey = "sg_pro_voucher";

  function getVoucher() { return sessionStorage.getItem(voucherKey) || ""; }
  function setVoucher(v) { sessionStorage.setItem(voucherKey, v); }
  function clearVoucher() { sessionStorage.removeItem(voucherKey); }

  // Cattura il voucher dal fragment (#sgv=...), lo sposta in sessionStorage e
  // ripulisce l'URL — stesso principio del sito (P25 §2.7): mai un cookie,
  // mai inviato a un server se non come header esplicito su questa richiesta.
  (function captureVoucherFromHash() {
    var m = location.hash.match(/sgv=([^&]+)/);
    if (m) {
      setVoucher(decodeURIComponent(m[1]));
      history.replaceState(null, "", location.pathname + location.search);
    }
  })();

  function api(path, opts) {
    opts = opts || {};
    var v = getVoucher();
    if (v) opts.headers = Object.assign({ "X-SG-Voucher": v }, opts.headers || {});
    return fetch(path, opts).then(function (res) {
      if (res.status === 403) {
        return res.json().then(function (b) {
          if (b.error === "voucher_scaduto") { clearVoucher(); showState("anon"); }
          throw new Error(b.error || "unauthorized");
        });
      }
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
        return body;
      });
    });
  }

  var states = ["Anon", "Onboard", "Active", "Canceled"];
  function showState(name) {
    states.forEach(function (s) {
      document.getElementById("state" + s).style.display = s.toLowerCase() === name ? "" : "none";
    });
  }

  function fmtDate(ms) {
    if (!ms) return "—";
    try { return new Date(ms).toLocaleDateString("it-IT", { year: "numeric", month: "long", day: "numeric" }); } catch (e) { return String(ms); }
  }
  function fmtDateTime(ms) {
    if (!ms) return "—";
    try { return new Date(ms).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" }); } catch (e) { return String(ms); }
  }
  function fmtEur(cents) {
    if (cents == null) return "—";
    return (cents / 100).toLocaleString("it-IT", { style: "currency", currency: "EUR" });
  }
  function escHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var EVENT_LABELS = { created: "Attivazione", renewed: "Rinnovo", payment_failed: "Pagamento non riuscito", canceled: "Cessazione", cancel_scheduled: "Cessazione programmata" };
  var CHANNEL_LABELS = { web: "Sito", api: "API o agente con chiave", mcp: "MCP (sessione)", telegram: "Bot Telegram" };

  var certsPage = 1;

  function renderMe(data) {
    if (!data.subscription) {
      var pricing = data.pricing;
      document.getElementById("onboardPrice").textContent = pricing
        ? "Abbonamento annuale: " + fmtEur(pricing.amount_cents) + "."
        : "Nessun listino attivo al momento: riprova più tardi.";
      showState("onboard");
      return;
    }
    var sub = data.subscription;
    if (sub.status === "canceled") {
      document.getElementById("canceledDate").textContent = fmtDate(sub.canceled_at);
      showState("canceled");
      return;
    }
    document.getElementById("pastDueBanner").style.display = sub.status === "past_due" ? "" : "none";
    document.getElementById("cancelScheduledBanner").style.display = sub.cancel_at_period_end ? "" : "none";
    document.getElementById("subStatus").textContent = sub.status === "past_due" ? "In tolleranza (pagamento da confermare)" : "Attivo";
    document.getElementById("subPeriodEnd").textContent = fmtDate(sub.period_end);
    document.getElementById("subPrice").textContent = fmtEur(sub.price_cents) + " / anno";

    var used = data.usage.used, quota = data.usage.quota;
    document.getElementById("usageText").textContent = used + " / " + quota + " attestazioni questo mese (" + data.usage.month + ")";
    document.getElementById("usageBar").style.width = Math.min(100, Math.round((used / quota) * 100)) + "%";

    var evBody = document.getElementById("eventsBody");
    evBody.innerHTML = data.events.map(function (e) {
      var detail = "";
      if (e.detail && e.detail.period_end) detail = "nuova scadenza " + fmtDate(e.detail.period_end);
      else if (e.detail && e.detail.amount_cents) detail = fmtEur(e.detail.amount_cents);
      return "<tr><td>" + fmtDateTime(e.ts) + "</td><td>" + escHtml(EVENT_LABELS[e.type] || e.type) + "</td><td>" + escHtml(detail) + "</td></tr>";
    }).join("") || '<tr><td colspan="3">Nessun evento.</td></tr>';

    document.getElementById("segmentSelect").value = (data.profile && data.profile.segment) || "";
    document.getElementById("regionSelect").value = (data.profile && data.profile.region) || "";
    document.getElementById("profileConsent").checked = !!data.profile;

    showState("active");
    loadCertificates(1);
  }

  function loadCertificates(page) {
    certsPage = page;
    api("/api/pro/certificates?page=" + page).then(function (data) {
      var body = document.getElementById("certsBody");
      body.innerHTML = data.certificates.map(function (c) {
        var short = c.sha256.slice(0, 12) + "…";
        return "<tr><td>" + fmtDateTime(c.ts) + "</td><td class=\"fingerprint\">" + escHtml(short) + "</td><td>" +
          escHtml(CHANNEL_LABELS[c.channel] || c.channel || "—") +
          "</td><td><a href=\"https://attestazione.spaziogenesi.org/c/" + c.sha256 + "\" target=\"_blank\" rel=\"noopener\">verifica</a></td></tr>";
      }).join("") || '<tr><td colspan="4">Nessun certificato in questa fascia.</td></tr>';
      document.getElementById("certsPageInfo").textContent = "Pagina " + data.page + " di " + Math.max(1, Math.ceil(data.total / data.per_page));
      document.getElementById("certsPrevBtn").disabled = data.page <= 1;
      document.getElementById("certsNextBtn").disabled = data.page * data.per_page >= data.total;
    }).catch(function () {});
  }

  function loadMe() {
    api("/api/pro/me").then(renderMe).catch(function () { /* voucher_scaduto già gestito in api() */ });
  }

  if (getVoucher()) loadMe(); else showState("anon");

  document.getElementById("checkoutBtn").addEventListener("click", function () {
    var msg = document.getElementById("checkoutMsg");
    msg.textContent = "Attendere…"; msg.className = "msg";
    var code = document.getElementById("discountInput").value.trim();
    api("/api/pro/checkout", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(code ? { discount_code: code } : {}) })
      .then(function (data) { location.href = data.url; })
      .catch(function (e) { msg.textContent = e.message; msg.className = "msg err"; });
  });

  document.getElementById("portalBtn").addEventListener("click", function () {
    var msg = document.getElementById("portalMsg");
    msg.textContent = "Attendere…"; msg.className = "msg";
    api("/api/pro/portal", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })
      .then(function (data) { location.href = data.url; })
      .catch(function (e) { msg.textContent = e.message; msg.className = "msg err"; });
  });

  document.getElementById("reactivateBtn").addEventListener("click", function () {
    api("/api/pro/checkout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })
      .then(function (data) { location.href = data.url; })
      .catch(function (e) { alert(e.message); });
  });

  document.getElementById("certsPrevBtn").addEventListener("click", function () { if (certsPage > 1) loadCertificates(certsPage - 1); });
  document.getElementById("certsNextBtn").addEventListener("click", function () { loadCertificates(certsPage + 1); });

  function doLogout() { clearVoucher(); showState("anon"); }
  document.getElementById("logoutBtnOnboard").addEventListener("click", doLogout);
  document.getElementById("logoutBtnActive").addEventListener("click", doLogout);
  document.getElementById("logoutBtnCanceled").addEventListener("click", doLogout);

  document.getElementById("saveProfileBtn").addEventListener("click", function () {
    var msg = document.getElementById("profileMsg");
    var segment = document.getElementById("segmentSelect").value;
    var region = document.getElementById("regionSelect").value;
    var consent = document.getElementById("profileConsent").checked;
    if ((segment || region) && !consent) { msg.textContent = "Serve il consenso per salvare questi dati."; msg.className = "msg err"; return; }
    msg.textContent = "Salvataggio…"; msg.className = "msg";
    api("/api/pro/profile", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ segment: segment || null, region: region || null, consent: consent }),
    })
      .then(function () { msg.textContent = "Salvato."; msg.className = "msg ok"; })
      .catch(function (e) { msg.textContent = e.message; msg.className = "msg err"; });
  });

  document.getElementById("clearProfileBtn").addEventListener("click", function () {
    if (!confirm("Rimuovere segmento e regione salvati?")) return;
    var msg = document.getElementById("profileMsg");
    api("/api/pro/profile", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ clear: true }) })
      .then(function () {
        document.getElementById("segmentSelect").value = "";
        document.getElementById("regionSelect").value = "";
        document.getElementById("profileConsent").checked = false;
        msg.textContent = "Rimosso."; msg.className = "msg ok";
      })
      .catch(function (e) { msg.textContent = e.message; msg.className = "msg err"; });
  });
})();
