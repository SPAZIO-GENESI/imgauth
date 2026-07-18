(function () {
  var secretKey = "sg_admin_secret";
  var loginCard = document.getElementById("loginCard");
  var app = document.getElementById("app");
  var loginMsg = document.getElementById("loginMsg");

  function getSecret() { return sessionStorage.getItem(secretKey) || ""; }
  function setSecret(v) { sessionStorage.setItem(secretKey, v); }
  function clearSecret() { sessionStorage.removeItem(secretKey); }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "X-Admin-Secret": getSecret() }, opts.headers || {});
    return fetch(path, opts).then(function (res) {
      if (res.status === 403) {
        clearSecret();
        showLogin("Secret non valido o scaduto.");
        throw new Error("unauthorized");
      }
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
        return body;
      });
    });
  }

  function showLogin(msg) {
    loginCard.style.display = "";
    app.style.display = "none";
    loginMsg.textContent = msg || "";
    loginMsg.className = "msg err";
  }

  function showApp() {
    loginCard.style.display = "none";
    app.style.display = "";
    loadKeys();
    loadConventions();
  }

  function showTab(name) {
    var tabs = { keys: "tabKeys", conventions: "tabConventions", pro: "tabPro" };
    var btns = { keys: "tabBtnKeys", conventions: "tabBtnConventions", pro: "tabBtnPro" };
    Object.keys(tabs).forEach(function (t) {
      document.getElementById(tabs[t]).style.display = t === name ? "" : "none";
      document.getElementById(btns[t]).classList.toggle("active", t === name);
      document.getElementById(btns[t]).setAttribute("aria-selected", String(t === name));
    });
  }
  // Ogni apertura di scheda ricarica i dati: chi guarda il pannello non deve
  // sapere che esiste un pulsante "Aggiorna" dedicato per vedere lo stato
  // corrente (es. dopo un'attestazione fatta altrove, come dal sito).
  document.getElementById("tabBtnKeys").addEventListener("click", function () { showTab("keys"); loadKeys(); });
  document.getElementById("tabBtnConventions").addEventListener("click", function () { showTab("conventions"); loadConventions(); });
  document.getElementById("tabBtnPro").addEventListener("click", function () { showTab("pro"); loadProPricing(); loadProDiscounts(); loadProSubscribers(); });

  function fmtDate(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleString("it-IT", { dateStyle: "short", timeStyle: "short" }); } catch (e) { return iso; }
  }

  function fmtDateOnly(ms) {
    if (ms == null || ms === "") return "—";
    try { return new Date(ms).toLocaleDateString("it-IT"); } catch (e) { return String(ms); }
  }

  function escHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ── Ordinamento/ricerca client-side (generico per entrambe le tabelle) ──
  function bindSortable(tableId, sortState, onChange) {
    Array.prototype.forEach.call(document.querySelectorAll("#" + tableId + " th.sortable"), function (th) {
      th.addEventListener("click", function () {
        var key = th.dataset.key;
        if (sortState.key === key) { sortState.dir = sortState.dir === "asc" ? "desc" : "asc"; }
        else { sortState.key = key; sortState.dir = "asc"; }
        onChange();
      });
    });
  }

  function updateSortIndicators(tableId, sortState) {
    Array.prototype.forEach.call(document.querySelectorAll("#" + tableId + " th.sortable"), function (th) {
      var active = th.dataset.key === sortState.key;
      th.classList.toggle("active", active);
      var arrow = th.querySelector(".arrow");
      if (arrow) arrow.textContent = active ? (sortState.dir === "asc" ? "▲" : "▼") : "▲";
    });
  }

  function sortRows(rows, sortState, boolKeys) {
    var sorted = rows.slice();
    sorted.sort(function (a, b) {
      var ka = a[sortState.key], kb = b[sortState.key];
      if (boolKeys && boolKeys.indexOf(sortState.key) !== -1) { ka = ka ? 1 : 0; kb = kb ? 1 : 0; }
      if (ka == null) ka = "";
      if (kb == null) kb = "";
      if (typeof ka === "string") ka = ka.toLowerCase();
      if (typeof kb === "string") kb = kb.toLowerCase();
      if (ka < kb) return sortState.dir === "asc" ? -1 : 1;
      if (ka > kb) return sortState.dir === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }

  function rowHtml(k) {
    var statusPill = k.revoked
      ? '<span class="pill revoked">revocata</span>'
      : '<span class="pill ok">attiva</span>';
    var kindLabel = k.kind === "key" ? "API key" : "sessione";
    var owner = k.owner_email
      ? escHtml(k.owner_email) + (k.owner_provider ? ' <span style="color:var(--muted);">(' + escHtml(k.owner_provider) + ')</span>' : '')
      : '—';
    var actions = '<div class="actions">';
    if (k.kind === "key") {
      actions += '<button class="secondary btn-sm qty-btn" data-id="' + k.id + '">Modifica quota</button>';
      if (!k.revoked) actions += '<button class="danger btn-sm revoke-btn" data-id="' + k.id + '">Revoca</button>';
      if (k.revoked && k.owner_email && k.owner_email !== "(rimosso)") {
        actions += '<button class="secondary btn-sm forget-btn" data-id="' + k.id + '">Dimentica titolare</button>';
      }
    } else if (!k.revoked) {
      actions += '<button class="danger btn-sm revoke-btn" data-id="' + k.id + '">Revoca</button>';
    }
    actions += '<button class="danger btn-sm delete-btn" data-id="' + k.id + '" data-label="' + escHtml(k.label || k.id) + '">Elimina</button>';
    actions += '</div>';
    return '<tr>' +
      '<td class="wrap-cell">' + escHtml(k.label || '—') + '</td>' +
      '<td>' + kindLabel + '</td>' +
      '<td class="wrap-cell">' + owner + '</td>' +
      '<td>' + k.quota + '</td>' +
      '<td>' + k.used + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + fmtDate(k.created_at) + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  var keysData = [];
  var keysSort = { key: "created_at", dir: "desc" };

  function applyKeysView() {
    var q = document.getElementById("keysSearch").value.trim().toLowerCase();
    var filtered = !q ? keysData : keysData.filter(function (k) {
      return (k.label || "").toLowerCase().indexOf(q) !== -1 ||
        (k.owner_email || "").toLowerCase().indexOf(q) !== -1 ||
        (k.id || "").toLowerCase().indexOf(q) !== -1;
    });
    var sorted = sortRows(filtered, keysSort, ["revoked"]);
    var body = document.getElementById("keysBody");
    body.innerHTML = sorted.map(rowHtml).join("") || '<tr><td colspan="8">Nessuna credenziale.</td></tr>';
    updateSortIndicators("keysTable", keysSort);
    attachKeyRowHandlers();
  }

  function attachKeyRowHandlers() {
    var listMsg = document.getElementById("listMsg");
    Array.prototype.forEach.call(document.querySelectorAll(".revoke-btn"), function (btn) {
      btn.addEventListener("click", function () {
        if (!confirm("Revocare questa credenziale?")) return;
        api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ revoked: true }) })
          .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".qty-btn"), function (btn) {
      btn.addEventListener("click", function () {
        var q = prompt("Nuova quota mensile:");
        if (!q) return;
        api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ quota: parseInt(q, 10) }) })
          .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".forget-btn"), function (btn) {
      btn.addEventListener("click", function () {
        if (!confirm("Rimuovere l'email del titolare da questa credenziale? Non si può annullare.")) return;
        api("/admin/api/keys/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ forget: true }) })
          .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".delete-btn"), function (btn) {
      btn.addEventListener("click", function () {
        if (!confirm('Eliminare DEFINITIVAMENTE la credenziale ' + btn.dataset.label + '? A differenza di Revoca, non si può annullare.')) return;
        api("/admin/api/keys/" + btn.dataset.id, { method: "DELETE" })
          .then(loadKeys).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; });
      });
    });
  }

  function loadKeys() {
    var listMsg = document.getElementById("listMsg");
    listMsg.textContent = "Carico…";
    listMsg.className = "loading-inline";
    api("/admin/api/keys").then(function (data) {
      keysData = data.keys || [];
      listMsg.textContent = "";
      applyKeysView();
    }).catch(function (e) {
      if (e.message !== "unauthorized") { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; }
    });
  }

  bindSortable("keysTable", keysSort, applyKeysView);
  document.getElementById("keysSearch").addEventListener("input", applyKeysView);

  document.getElementById("loginBtn").addEventListener("click", function () {
    var v = document.getElementById("secretInput").value.trim();
    if (!v) return;
    setSecret(v);
    api("/admin/api/keys").then(function () { showApp(); }).catch(function (e) {
      if (e.message === "unauthorized") return;
      loginMsg.textContent = e.message; loginMsg.className = "msg err";
    });
  });

  document.getElementById("toggleSecretBtn").addEventListener("click", function () {
    var input = document.getElementById("secretInput");
    var showing = input.type === "text";
    input.type = showing ? "password" : "text";
    this.textContent = showing ? "Mostra" : "Nascondi";
  });

  document.getElementById("refreshBtn").addEventListener("click", function (e) { e.preventDefault(); loadKeys(); });

  document.getElementById("issueBtn").addEventListener("click", function () {
    var label = document.getElementById("newLabel").value.trim();
    var quota = parseInt(document.getElementById("newQuota").value, 10);
    var convId = document.getElementById("newConvId").value.trim();
    var ownerEmail = document.getElementById("newOwnerEmail").value.trim();
    var issueMsg = document.getElementById("issueMsg");
    var box = document.getElementById("newKeyBox");
    box.style.display = "none";
    if (!label) { issueMsg.textContent = "Serve un'etichetta."; issueMsg.className = "msg err"; return; }
    if (convId && !ownerEmail) { issueMsg.textContent = "Serve l'email del titolare per una chiave in convenzione."; issueMsg.className = "msg err"; return; }
    issueMsg.textContent = "Emissione…"; issueMsg.className = "msg";
    var payload = { label: label, quota: quota };
    if (convId) { payload.convention_id = convId; payload.owner_email = ownerEmail; }
    api("/admin/api/keys", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then(function (data) {
        issueMsg.textContent = "Fatto. Copia la chiave ora — non sarà più recuperabile.";
        issueMsg.className = "msg ok";
        box.textContent = data.key;
        box.style.display = "";
        document.getElementById("newLabel").value = "";
        document.getElementById("newConvId").value = "";
        document.getElementById("newOwnerEmail").value = "";
        loadKeys();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { issueMsg.textContent = e.message; issueMsg.className = "msg err"; } });
  });

  // ── P25 (B): Convenzioni ──────────────────────────────────────────────
  function dateToMs(inputId) {
    var v = document.getElementById(inputId).value;
    if (!v) return null;
    return new Date(v + "T00:00:00Z").getTime();
  }

  function cvRowHtml(c) {
    var statusPill = c.active ? '<span class="pill ok">attiva</span>' : '<span class="pill revoked">disattivata</span>';
    var actions = '<div class="actions">' +
      '<button class="secondary btn-sm cv-report-btn" data-id="' + c.id + '">Report</button>' +
      '<button class="secondary btn-sm cv-toggle-btn" data-id="' + c.id + '" data-active="' + (c.active ? '1' : '0') + '">' +
      (c.active ? 'Disattiva' : 'Riattiva') + '</button>' +
      '</div>';
    return '<tr>' +
      '<td class="wrap-cell">' + escHtml(c.name) + '<div style="color:var(--muted);font-size:.78rem;">' + escHtml(c.id) + '</div></td>' +
      '<td class="wrap-cell">' + escHtml(c.domains) + '</td>' +
      '<td>' + c.pool_used_month + ' / ' + c.monthly_quota + '</td>' +
      '<td>' + c.members_this_month + '</td>' +
      '<td>' + c.keys_active + ' / ' + c.keys_total + '</td>' +
      '<td>' + fmtDateOnly(c.starts_at) + '</td>' +
      '<td>' + fmtDateOnly(c.ends_at) + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  var conventionsData = [];
  var cvSort = { key: "name", dir: "asc" };

  function applyConventionsView() {
    var q = document.getElementById("cvSearch").value.trim().toLowerCase();
    var filtered = !q ? conventionsData : conventionsData.filter(function (c) {
      return (c.name || "").toLowerCase().indexOf(q) !== -1 ||
        (c.domains || "").toLowerCase().indexOf(q) !== -1 ||
        (c.id || "").toLowerCase().indexOf(q) !== -1;
    });
    var sorted = sortRows(filtered, cvSort, ["active"]);
    var body = document.getElementById("conventionsBody");
    body.innerHTML = sorted.map(cvRowHtml).join("") || '<tr><td colspan="9">Nessuna convenzione.</td></tr>';
    updateSortIndicators("conventionsTable", cvSort);
    attachConventionRowHandlers();
  }

  function attachConventionRowHandlers() {
    var listMsg = document.getElementById("cvListMsg");
    Array.prototype.forEach.call(document.querySelectorAll(".cv-toggle-btn"), function (btn) {
      btn.addEventListener("click", function () {
        var nowActive = btn.dataset.active === "1";
        if (!confirm((nowActive ? "Disattivare" : "Riattivare") + " questa convenzione? Le chiavi già emesse non vengono revocate.")) return;
        api("/admin/api/conventions/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ active: !nowActive }) })
          .then(loadConventions).catch(function (e) { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".cv-report-btn"), function (btn) {
      btn.addEventListener("click", function () { showReport(btn.dataset.id); });
    });
  }

  function loadConventions() {
    var listMsg = document.getElementById("cvListMsg");
    listMsg.textContent = "Carico…";
    listMsg.className = "loading-inline";
    api("/admin/api/conventions").then(function (data) {
      conventionsData = data.conventions || [];
      listMsg.textContent = "";
      applyConventionsView();
    }).catch(function (e) {
      if (e.message !== "unauthorized") { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; }
    });
  }

  bindSortable("conventionsTable", cvSort, applyConventionsView);
  document.getElementById("cvSearch").addEventListener("input", applyConventionsView);

  function showReport(id) {
    var box = document.getElementById("cvReportBox");
    var title = document.getElementById("cvReportTitle");
    var content = document.getElementById("cvReportContent");
    box.style.display = "";
    title.textContent = id;
    content.textContent = "Carico…";
    api("/admin/api/conventions/" + id + "/report").then(function (data) {
      title.textContent = data.convention.name + " (" + data.convention.id + ")";
      if (!data.months.length) { content.textContent = "Nessuna emissione registrata."; return; }
      var html = '<table><thead><tr><th>Mese</th><th>Attestazioni</th><th>Membri</th></tr></thead><tbody>';
      data.months.forEach(function (m) {
        html += '<tr><td>' + escHtml(m.ym) + '</td><td>' + m.attestations + '</td><td>' + m.members.length + '</td></tr>';
      });
      html += '</tbody></table>';
      content.innerHTML = html;
    }).catch(function (e) { content.textContent = e.message; });
  }

  document.getElementById("cvRefreshBtn").addEventListener("click", function (e) { e.preventDefault(); loadConventions(); });

  document.getElementById("cvCreateBtn").addEventListener("click", function () {
    var msg = document.getElementById("cvCreateMsg");
    var payload = {
      id: document.getElementById("cvId").value.trim().toLowerCase(),
      name: document.getElementById("cvName").value.trim(),
      domains: document.getElementById("cvDomains").value.trim(),
      monthly_quota: parseInt(document.getElementById("cvMonthlyQuota").value, 10),
      member_cap: parseInt(document.getElementById("cvMemberCap").value, 10),
      persistence_years: parseInt(document.getElementById("cvPersistence").value, 10),
      starts_at: dateToMs("cvStarts"),
      ends_at: dateToMs("cvEnds"),
    };
    if (!payload.id || !payload.name || !payload.domains || !payload.starts_at || !payload.ends_at) {
      msg.textContent = "Compila tutti i campi."; msg.className = "msg err"; return;
    }
    msg.textContent = "Creazione…"; msg.className = "msg";
    api("/admin/api/conventions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then(function () {
        msg.textContent = "Fatto."; msg.className = "msg ok";
        ["cvId", "cvName", "cvDomains"].forEach(function (fid) { document.getElementById(fid).value = ""; });
        loadConventions();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { msg.textContent = e.message; msg.className = "msg err"; } });
  });

  // ── P27: Professionale (listino, sconti, abbonati) ──────────────────────
  function fmtEur(cents) {
    if (cents == null) return "—";
    return (cents / 100).toLocaleString("it-IT", { style: "currency", currency: "EUR" });
  }
  function eurToCents(v) {
    var n = parseFloat(v);
    return isFinite(n) ? Math.round(n * 100) : NaN;
  }

  function prRowHtml(p, activeId) {
    var statusPill = p.id === activeId ? '<span class="pill ok">attiva</span>'
      : (p.valid_to && p.valid_to <= Date.now()) ? '<span class="pill revoked">chiusa</span>' : '<span class="pill" style="background:#f2f0ea;color:var(--muted);">futura</span>';
    var actions = (!p.valid_to || p.valid_to > Date.now())
      ? '<button class="secondary btn-sm pr-close-btn" data-id="' + p.id + '">Chiudi</button>' : '';
    return '<tr>' +
      '<td class="wrap-cell">' + escHtml(p.label) + '</td>' +
      '<td>' + fmtEur(p.amount_cents) + '</td>' +
      '<td>' + fmtDateOnly(p.valid_from) + '</td>' +
      '<td>' + (p.valid_to ? fmtDateOnly(p.valid_to) : '—') + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  function loadProPricing() {
    api("/admin/api/pro/pricing").then(function (data) {
      var body = document.getElementById("prBody");
      body.innerHTML = (data.pricing || []).map(function (p) { return prRowHtml(p, data.active_id); }).join("") || '<tr><td colspan="6">Nessuna riga di listino.</td></tr>';
      document.getElementById("prOverlapWarn").style.display = data.overlap_warning ? "" : "none";
      Array.prototype.forEach.call(document.querySelectorAll(".pr-close-btn"), function (btn) {
        btn.addEventListener("click", function () {
          if (!confirm("Chiudere questa riga di listino da adesso?")) return;
          api("/admin/api/pro/pricing/" + btn.dataset.id, { method: "PATCH" }).then(loadProPricing).catch(function (e) { alert(e.message); });
        });
      });
    }).catch(function () {});
  }

  document.getElementById("prCreateBtn").addEventListener("click", function () {
    var msg = document.getElementById("prCreateMsg");
    var payload = {
      label: document.getElementById("prLabel").value.trim(),
      amount_cents: eurToCents(document.getElementById("prAmount").value),
      valid_from: dateToMs("prStarts"),
      valid_to: dateToMs("prEnds"),
    };
    if (!payload.label || !payload.amount_cents || !payload.valid_from) {
      msg.textContent = "Compila etichetta, prezzo e data di inizio."; msg.className = "msg err"; return;
    }
    msg.textContent = "Creazione…"; msg.className = "msg";
    api("/admin/api/pro/pricing", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then(function () {
        msg.textContent = "Fatto."; msg.className = "msg ok";
        document.getElementById("prLabel").value = "";
        loadProPricing();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { msg.textContent = e.message; msg.className = "msg err"; } });
  });

  function dcRowHtml(d) {
    var discount = d.percent_off != null ? d.percent_off + "%" : fmtEur(d.amount_off_cents);
    var window_ = fmtDateOnly(d.valid_from) + " → " + (d.valid_to ? fmtDateOnly(d.valid_to) : "senza scadenza");
    var statusPill = d.revoked ? '<span class="pill revoked">revocato</span>' : '<span class="pill ok">attivo</span>';
    var actions = '<button class="secondary btn-sm dc-toggle-btn" data-id="' + d.id + '" data-revoked="' + (d.revoked ? '1' : '0') + '">' +
      (d.revoked ? 'Riattiva' : 'Revoca') + '</button>';
    return '<tr>' +
      '<td class="fingerprint">' + escHtml(d.code) + '</td>' +
      '<td>' + discount + '</td>' +
      '<td class="wrap-cell">' + window_ + '</td>' +
      '<td>' + (d.restricted_email ? escHtml(d.restricted_email) : '—') + '</td>' +
      '<td>' + d.used_count + (d.max_uses ? ' / ' + d.max_uses : '') + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  function loadProDiscounts() {
    api("/admin/api/pro/discounts").then(function (data) {
      var body = document.getElementById("dcBody");
      body.innerHTML = (data.discounts || []).map(dcRowHtml).join("") || '<tr><td colspan="7">Nessun codice sconto.</td></tr>';
      Array.prototype.forEach.call(document.querySelectorAll(".dc-toggle-btn"), function (btn) {
        btn.addEventListener("click", function () {
          var nowRevoked = btn.dataset.revoked === "1";
          api("/admin/api/pro/discounts/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ revoked: !nowRevoked }) })
            .then(loadProDiscounts).catch(function (e) { alert(e.message); });
        });
      });
    }).catch(function () {});
  }

  document.getElementById("dcCreateBtn").addEventListener("click", function () {
    var msg = document.getElementById("dcCreateMsg");
    var percent = document.getElementById("dcPercent").value.trim();
    var amount = document.getElementById("dcAmount").value.trim();
    var payload = {
      code: document.getElementById("dcCode").value.trim().toUpperCase(),
      percent_off: percent ? parseInt(percent, 10) : null,
      amount_off_cents: amount ? eurToCents(amount) : null,
      restricted_email: document.getElementById("dcEmail").value.trim() || null,
      max_uses: document.getElementById("dcMaxUses").value ? parseInt(document.getElementById("dcMaxUses").value, 10) : null,
      note: document.getElementById("dcNote").value.trim() || null,
      valid_from: dateToMs("dcStarts"),
      valid_to: dateToMs("dcEnds"),
    };
    if (!payload.code || !payload.valid_from || (!payload.percent_off && !payload.amount_off_cents)) {
      msg.textContent = "Serve codice, data di inizio e uno sconto (percentuale O importo)."; msg.className = "msg err"; return;
    }
    msg.textContent = "Creazione…"; msg.className = "msg";
    api("/admin/api/pro/discounts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      .then(function () {
        msg.textContent = "Fatto."; msg.className = "msg ok";
        ["dcCode", "dcPercent", "dcAmount", "dcEmail", "dcMaxUses", "dcNote"].forEach(function (id) { document.getElementById(id).value = ""; });
        loadProDiscounts();
      })
      .catch(function (e) { if (e.message !== "unauthorized") { msg.textContent = e.message; msg.className = "msg err"; } });
  });

  var subData = [];
  var subSort = { key: "created_at", dir: "desc" };

  function subRowHtml(s) {
    var statusPill = s.status === "active"
      ? (s.cancel_at_period_end ? '<span class="pill" style="background:#f2f0ea;color:var(--muted);">cessa a fine periodo</span>' : '<span class="pill ok">attivo</span>')
      : s.status === "past_due" ? '<span class="pill" style="background:#fdf3e0;color:#8a5a00;">in tolleranza</span>'
      : '<span class="pill revoked">cessato</span>';
    var lastEvent = s.last_event ? (s.last_event.type + " · " + fmtDate(new Date(s.last_event.ts).toISOString())) : '—';
    var forgettable = s.email !== "(rimosso)";
    var actions = forgettable
      ? '<button class="danger btn-sm sub-forget-btn" data-id="' + s.id + '" data-email="' + escHtml(s.email) + '">Dimentica</button>'
      : '';
    return '<tr>' +
      '<td class="wrap-cell">' + escHtml(s.email) + '</td>' +
      '<td>' + statusPill + '</td>' +
      '<td>' + fmtDateOnly(s.current_period_end) + '</td>' +
      '<td>' + fmtEur(s.price_cents) + '</td>' +
      '<td>' + s.usage_month + '</td>' +
      '<td>' + escHtml(lastEvent) + '</td>' +
      '<td>' + actions + '</td>' +
      '</tr>';
  }

  function applySubView() {
    var q = document.getElementById("subSearch").value.trim().toLowerCase();
    var filtered = !q ? subData : subData.filter(function (s) { return (s.email || "").toLowerCase().indexOf(q) !== -1; });
    var sorted = sortRows(filtered, subSort, []);
    document.getElementById("subBody").innerHTML = sorted.map(subRowHtml).join("") || '<tr><td colspan="7">Nessun abbonato.</td></tr>';
    updateSortIndicators("subTable", subSort);
    Array.prototype.forEach.call(document.querySelectorAll(".sub-forget-btn"), function (btn) {
      btn.addEventListener("click", function () {
        var deletePdfs = confirm("Eliminare anche i PDF archiviati di " + btn.dataset.email + "? OK = sì (salta gli hash condivisi con altri), Annulla = no, solo anonimizza il profilo.");
        if (!confirm("Confermi la rimozione del titolare per " + btn.dataset.email + "? Non si può annullare.")) return;
        api("/admin/api/pro/subscribers/" + btn.dataset.id, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ delete_pdfs: deletePdfs }) })
          .then(loadProSubscribers).catch(function (e) { alert(e.message); });
      });
    });
  }

  function loadProSubscribers() {
    var listMsg = document.getElementById("subListMsg");
    listMsg.textContent = "Carico…"; listMsg.className = "loading-inline";
    api("/admin/api/pro/subscribers").then(function (data) {
      subData = data.subscribers || [];
      listMsg.textContent = "";
      applySubView();
    }).catch(function (e) {
      if (e.message !== "unauthorized") { listMsg.textContent = e.message; listMsg.className = "loading-inline err"; }
    });
  }

  bindSortable("subTable", subSort, applySubView);
  document.getElementById("subSearch").addEventListener("input", applySubView);
  document.getElementById("subRefreshBtn").addEventListener("click", function (e) { e.preventDefault(); loadProSubscribers(); });

  if (getSecret()) {
    api("/admin/api/keys").then(function () { showApp(); }).catch(function () {});
  }
})();
