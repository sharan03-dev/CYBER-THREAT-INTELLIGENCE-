/* Kavach CTI - frontend (vanilla JS, no build step). Talks to the FastAPI backend under /api. */
(() => {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (v) => (v ?? 0).toLocaleString("en-IN");
  const pct = (v, d = 1) => (v == null ? "n/a" : `${(100 * v).toFixed(d)}%`);
  const bytes = (n) => {
    n = Number(n || 0);
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
  };
  const dateFmt = new Intl.DateTimeFormat("en-IN", { day: "numeric", month: "short", year: "numeric" });
  const timeFmt = new Intl.DateTimeFormat("en-IN", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const fmtDate = (d) => (d ? dateFmt.format(new Date(d)) : "n/a");
  const fmtTime = (d) => (d ? timeFmt.format(new Date(d)) : "n/a");
  function ago(d) {
    if (!d) return "never";
    const s = (Date.now() - new Date(d).getTime()) / 1000;
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    if (s < 86400 * 30) return `${Math.round(s / 86400)} days ago`;
    return fmtDate(d);
  }
  const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  const CVE = /^CVE-\d{4}-\d{4,7}$/i;
  const refang = (s) => s.trim().replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".").replace(/\[:\]/g, ":").replace(/^hxxp/i, "http");
  const isIPv6 = (s) => s.includes(":") && /^[0-9a-f:.]+$/i.test(s) && (s.match(/:/g) || []).length >= 2;
  function kindOf(q) {
    const v = refang(q || "");
    if (!v) return null;
    if (IPV4.test(v) || isIPv6(v)) return "ip";
    if (CVE.test(v)) return "cve";
    return "text";
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok) {
      const msg = data && data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `Request failed (${res.status})`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function toast(msg, ms = 4200) {
    const slot = $("#toast-slot");
    slot.innerHTML = `<div class="toast">${msg}</div>`;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (slot.innerHTML = ""), ms);
  }

  function copyCmd(text) {
    return `<div class="cmd"><code>${esc(text)}</code><button class="copy" type="button" data-copy="${esc(text)}">Copy</button></div>`;
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    navigator.clipboard?.writeText(b.dataset.copy).then(() => {
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy"), 1400);
    });
  });

  const errorBox = (err, extra = "") => `<div class="panel empty"><strong>Could not load this page</strong>${esc(err.message || err)}${extra}</div>`;
  const verdictClass = (v) => (v === "Actual threat" ? "v-actual" : v === "Potential threat" ? "v-potential" : "v-info");
  const verdictTag = (v) => (v ? `<span class="verdict-tag ${verdictClass(v)}">${esc(v)}</span>` : "");
  const sevTag = (s) => (s ? `<span class="sev sev-${esc(s)}">${esc(s)}</span>` : "");
  const REL = { A: "Completely reliable", B: "Usually reliable", C: "Fairly reliable", D: "Not usually reliable", E: "Unreliable", F: "Reliability cannot be judged" };
  const CRED = { 1: "Confirmed by other sources", 2: "Probably true", 3: "Possibly true", 4: "Doubtful", 5: "Improbable", 6: "Truth cannot be judged" };

  // ------------------------------------------------------------------ state + cleanup
  const state = { health: null, cleanups: [] };
  function onLeave(fn) { state.cleanups.push(fn); }
  function runCleanups() { state.cleanups.splice(0).forEach((f) => { try { f(); } catch (e) { /* ignore */ } }); }

  // ------------------------------------------------------------------ theme, menu, omnibox
  function setTheme(t) {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem("kavach-theme", t); } catch (e) { /* private mode */ }
    $("#theme-btn span").textContent = t === "dark" ? "Light theme" : "Dark theme";
  }
  $("#theme-btn").addEventListener("click", () => {
    const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(t);
    api("/api/profile/preferences", { method: "PUT", body: { theme: t } }).catch(() => {});   // embedded preference
  });
  setTheme(document.documentElement.dataset.theme || "dark");
  $("#menu-btn").addEventListener("click", () => $("#rail").classList.toggle("open"));
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  $("#kbd-hint").textContent = isMac ? "\u2318 K" : "Ctrl K";

  const omniInput = $("#omni-input");
  omniInput.addEventListener("input", () => {
    const k = kindOf(omniInput.value);
    const chip = $("#omni-type");
    chip.hidden = !k;
    chip.textContent = k === "ip" ? "IP address" : k === "cve" ? "CVE" : "Search reports";
  });
  $("#omni").addEventListener("submit", (e) => {
    e.preventDefault();
    goSearch(omniInput.value);
    omniInput.blur();
  });
  function goSearch(q) {
    const v = refang(q || "");
    if (!v) return;
    const k = kindOf(v);
    if (k === "ip") location.hash = `#/ip/${encodeURIComponent(v)}`;
    else location.hash = `#/threats?q=${encodeURIComponent(v)}`;
  }
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); omniInput.focus(); omniInput.select(); }
    else if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); omniInput.focus(); }
    else if (e.key === "Escape") closeDrawer();
  });

  // ------------------------------------------------------------------ health + banners
  async function checkHealth() {
    let h;
    try { h = await api("/api/health"); } catch (e) { h = { mongodb: false, server: false }; }
    state.health = h;
    const el = $("#db-state");
    if (h.mongodb) el.innerHTML = `<span class="dot ok"></span><span>MongoDB ${esc(h.version || "")} connected</span>`;
    else if (h.server === false) el.innerHTML = `<span class="dot err"></span><span>Backend not reachable</span>`;
    else el.innerHTML = `<span class="dot err"></span><span>MongoDB offline</span>`;
    const slot = $("#banner-slot");
    if (h.server === false) {
      slot.innerHTML = `<div class="banner err"><div><strong>The backend server is not running</strong>Start it from the project folder, then reload this page.${copyCmd("python -m uvicorn backend.app.main:app --port 8000")}</div></div>`;
    } else if (!h.mongodb) {
      slot.innerHTML = `<div class="banner err"><div><strong>MongoDB is not running</strong>The website needs a local MongoDB server. Start it in Terminal, then reload.${copyCmd("brew services start mongodb-community@8.0")}</div></div>`;
    } else if (h.needs_setup) {
      slot.innerHTML = `<div class="banner"><div><strong>The database is empty</strong>Build it once (downloads threat feeds and reports, takes 1 to 3 minutes). Use --offline if you have no internet.${copyCmd("python backend/scripts/setup_database.py")}</div></div>`;
    } else slot.innerHTML = "";
    return h;
  }
  setInterval(async () => { const h = await checkHealth(); if (h.mongodb && !sync.es) startSync(); }, 20000);

  // ------------------------------------------------------------------ router
  const routes = { overview: pageOverview, threats: pageThreats, ip: pageIP, classify: pageClassify, sources: pageSources, lab71: pageLab71, lab72: pageLab72, usecases: pageUseCases };
  function parseHash() {
    const h = location.hash.replace(/^#\/?/, "");
    const [path, query = ""] = h.split("?");
    const parts = path.split("/").filter(Boolean);
    return { name: parts[0] || "overview", arg: parts.slice(1).map(decodeURIComponent).join("/"), params: new URLSearchParams(query) };
  }
  async function render() {
    runCleanups();
    closeDrawer();
    $("#rail").classList.remove("open");
    const r = parseHash();
    const fn = routes[r.name] || pageOverview;
    $$(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === (routes[r.name] ? r.name : "overview")));
    const page = $("#page");
    page.innerHTML = `<div class="skeleton" style="width:40%;height:34px;margin-bottom:16px"></div><div class="skeleton" style="width:65%"></div>`;
    window.scrollTo(0, 0);
    try { await fn(page, r); } catch (err) { page.innerHTML = errorBox(err); }
  }
  window.addEventListener("hashchange", render);

  // ================================================================== charts (hand-drawn SVG)
  function severityChart(perDay, days = 30) {
    const sevs = ["Low", "Medium", "High", "Critical"];
    const colors = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--lowsev)" };
    const keys = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
      keys.push(d.toISOString().slice(0, 10));
    }
    const m = {};
    perDay.forEach((x) => { (m[x.day] = m[x.day] || {})[x.severity] = x.n; });
    const totals = keys.map((k) => sevs.reduce((a, s) => a + ((m[k] || {})[s] || 0), 0));
    const max = Math.max(4, ...totals);
    const W = 640, H = 210, L = 30, B = 24, T = 10;
    const bw = (W - L) / keys.length;
    let bars = "";
    keys.forEach((k, i) => {
      let y = H - B;
      sevs.forEach((s) => {
        const v = (m[k] || {})[s] || 0;
        if (!v) return;
        const h = ((H - B - T) * v) / max;
        y -= h;
        bars += `<rect x="${(L + i * bw + 1.5).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 3).toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" style="fill:${colors[s]}"><title>${k}: ${v} ${s}</title></rect>`;
      });
    });
    let grid = "";
    [0, 0.5, 1].forEach((f) => {
      const y = H - B - (H - B - T) * f;
      grid += `<line x1="${L}" x2="${W}" y1="${y}" y2="${y}" style="stroke:var(--line)"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${Math.round(max * f)}</text>`;
    });
    let labels = "";
    keys.forEach((k, i) => {
      if ((i % 7 === 0 && i < keys.length - 4) || i === keys.length - 1) {
        const d = new Date(k + "T00:00:00Z");
        labels += `<text x="${L + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${d.toLocaleDateString("en-IN", { day: "numeric", month: "short" })}</text>`;
      }
    });
    return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Reports per day by severity">${grid}${bars}${labels}</svg>`;
  }

  function dialSVG(score) {
    const r = 92, cx = 120, cy = 118, len = Math.PI * r;
    const pt = (v, rr) => {
      const a = Math.PI * (1 - v / 100);
      return [cx + rr * Math.cos(a), cy - rr * Math.sin(a)];
    };
    const ticks = [15, 40, 70].map((v) => {
      const [x1, y1] = pt(v, r - 16), [x2, y2] = pt(v, r + 12);
      return `<line class="tick" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`;
    }).join("");
    return `<svg class="dial" viewBox="0 0 240 150" role="img" aria-label="Risk score ${score} out of 100">
      <path class="arc-bg" d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke-width="16" stroke-linecap="round"/>
      <path class="arc" d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke-width="16" stroke-linecap="round"
        stroke-dasharray="${len}" stroke-dashoffset="${len}" data-target="${len * (1 - Math.max(0.5, score) / 100)}"/>
      ${ticks}
      <text class="score" x="${cx}" y="${cy - 14}" text-anchor="middle">${score}</text>
      <text class="lbl" x="${cx}" y="${cy + 8}" text-anchor="middle">risk score out of 100</text>
      <text class="lbl" x="${cx - r}" y="${cy + 26}" text-anchor="middle">0</text>
      <text class="lbl" x="${cx + r}" y="${cy + 26}" text-anchor="middle">100</text>
    </svg>`;
  }
  function animateDial(root) {
    const arc = $(".dial .arc", root);
    if (arc) requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", arc.dataset.target)));
  }

  let MASK = null;
  function worldMap(lat, lon) {
    const wm = window.WORLD_MASK;
    if (!wm) return "";
    if (!MASK) {
      MASK = wm.rows.map((row) => row.split("").map((h) => parseInt(h, 16).toString(2).padStart(4, "0")).join("").slice(0, wm.cols));
    }
    const sp = 5, W = wm.cols * sp, H = MASK.length * sp;
    let dots = "";
    MASK.forEach((row, i) => {
      for (let j = 0; j < row.length; j++) if (row[j] === "1") dots += `M${j * sp + 2.5} ${i * sp + 2.5}h0`;
    });
    let pin = "";
    if (lat != null && lon != null) {
      const x = Math.min(W - 3, Math.max(3, ((lon - wm.lon0) / wm.step) * sp + 2.5));
      const y = Math.min(H - 3, Math.max(3, ((wm.lat0 - lat) / wm.step) * sp + 2.5));
      pin = `<line x1="${x}" x2="${x}" y1="0" y2="${H}" style="stroke:var(--vc,var(--accent));stroke-width:.6;opacity:.45"/>
             <line x1="0" x2="${W}" y1="${y}" y2="${y}" style="stroke:var(--vc,var(--accent));stroke-width:.6;opacity:.45"/>
             <circle class="ring" cx="${x}" cy="${y}" r="7"/><circle class="pin" cx="${x}" cy="${y}" r="4.5"/>`;
    }
    return `<svg class="geo-map" viewBox="0 0 ${W} ${H}" role="img" aria-label="Location on world map"><path d="${dots}" style="stroke:var(--muted);opacity:.38;stroke-width:2.8;stroke-linecap:round"/>${pin}</svg>`;
  }

  function lineChart(points, { yKey = "y", xLabel = (p) => p.x, domain, fmtY = (v) => v, color = "var(--accent)", h = 200, second } = {}) {
    const pts = points.filter((p) => p[yKey] != null);
    if (pts.length < 2) return `<div class="empty">Not enough samples yet. It needs at least two measurements.</div>`;
    const W = 640, H = h, L = 52, B = 24, T = 12, R = 10;
    const ys = pts.map((p) => p[yKey]);
    let [lo, hi] = domain || [Math.min(...ys), Math.max(...ys)];
    if (hi - lo < 1e-6) { lo -= 0.01; hi += 0.01; }
    const x = (i) => L + ((W - L - R) * i) / (points.length - 1);
    const y = (v) => T + (H - B - T) * (1 - (v - lo) / (hi - lo));
    let d = "";
    points.forEach((p, i) => {
      if (p[yKey] == null) return;
      d += `${d ? "L" : "M"}${x(i).toFixed(1)} ${y(p[yKey]).toFixed(1)}`;
    });
    let d2 = "";
    if (second) {
      const [lo2, hi2] = second.domain;
      points.forEach((p, i) => {
        if (p[second.key] == null) return;
        d2 += `${d2 ? "L" : "M"}${x(i).toFixed(1)} ${(T + (H - B - T) * (1 - (p[second.key] - lo2) / (hi2 - lo2))).toFixed(1)}`;
      });
    }
    let grid = "";
    [0, 0.25, 0.5, 0.75, 1].forEach((f) => {
      const v = lo + (hi - lo) * f;
      grid += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" style="stroke:var(--line)"/><text x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${fmtY(v)}</text>`;
    });
    const step = Math.max(1, Math.ceil(points.length / 6));
    let labels = "";
    points.forEach((p, i) => {
      if (i % step === 0 || i === points.length - 1) labels += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${esc(xLabel(p, i))}</text>`;
    });
    const dotsSvg = points.map((p, i) => (p[yKey] == null ? "" : `<circle cx="${x(i)}" cy="${y(p[yKey])}" r="2.6" style="fill:${color}"><title>${esc(xLabel(p, i))}: ${fmtY(p[yKey])}</title></circle>`)).join("");
    return `<svg class="chart" viewBox="0 0 ${W} ${H}">${grid}${d2 ? `<path d="${d2}" style="fill:none;stroke:var(--muted);stroke-width:1.5;stroke-dasharray:4 4"/>` : ""}<path d="${d}" style="fill:none;stroke:${color};stroke-width:2.2;stroke-linejoin:round"/>${dotsSvg}${labels}</svg>`;
  }

  // ================================================================== report card / drawer
  function highlight(text, q) {
    const safe = esc(text);
    if (!q) return safe;
    const words = q.split(/\s+/).filter((w) => w.length > 2).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    if (!words.length) return safe;
    return safe.replace(new RegExp(`(${words.join("|")})`, "gi"), "<mark>$1</mark>");
  }
  function reportCard(r, q) {
    return `<article class="report-card" data-report="${r.id}" tabindex="0">
      <div><h3>${highlight(r.title, q)}</h3>
        <div class="meta"><span>${esc(r.source)}</span><span>${fmtTime(r.published_at)}</span><span>${esc(r.category || "")}</span>
          ${r.cve_ids && r.cve_ids.length ? `<span class="mono">${esc(r.cve_ids.slice(0, 3).join(", "))}</span>` : ""}
          ${r.ioc_count ? `<span>${r.ioc_count} indicator${r.ioc_count > 1 ? "s" : ""}</span>` : ""}</div></div>
      <div class="side">${verdictTag(r.verdict)}${sevTag(r.severity)}</div>
      <p>${highlight(r.summary, q)}</p>
    </article>`;
  }
  document.addEventListener("click", (e) => {
    const card = e.target.closest("[data-report]");
    if (card && !e.target.closest("a")) openReport(card.dataset.report);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.matches && e.target.matches("[data-report]")) openReport(e.target.dataset.report);
  });

  function closeDrawer() { $("#drawer-slot").innerHTML = ""; }
  async function openReport(id) {
    const slot = $("#drawer-slot");
    slot.innerHTML = `<div class="drawer-back" data-close></div><aside class="drawer" role="dialog" aria-label="Report details"><div class="skeleton" style="height:28px;width:70%"></div><div class="skeleton" style="margin-top:14px"></div></aside>`;
    slot.onclick = (e) => { if (e.target.closest("[data-close]")) closeDrawer(); };
    let r;
    try { r = await api(`/api/reports/${id}`); } catch (err) { $(".drawer", slot).innerHTML = errorBox(err); return; }
    const c = r.classification || {};
    const adm = c.admiralty || "";
    const cats = (c.categories || []).map((x) => `<div class="share-row"><span>${esc(x.name)}</span><div class="track"><i style="width:${Math.round(x.share * 100)}%;background:${x.name === c.category ? "var(--accent)" : "var(--muted)"}"></i></div><span class="muted num">${x.score}</span></div>`).join("");
    const signals = (c.signals || []).map((s) => `<span class="chip signal" title="${esc(s.category)} +${s.weight}">${esc(s.match)}</span>`).join("");
    const cves = (r.cves || []).map((v) => `<li><span class="mono">${esc(v._id)}</span> ${v.kev ? `<span class="kev">KEV</span> <span class="muted">${esc(v.kev.vendor || "")} ${esc(v.kev.product || "")}, added ${fmtDate(v.kev.date_added)}${v.kev.ransomware_use === "Known" ? ", used by ransomware" : ""}</span>` : `<span class="muted">not in CISA KEV</span>`}</li>`).join("");
    const actors = (r.actors || []).map((a) => `<li><strong>${esc(a.name)}</strong> <span class="muted">${esc(a.type)}, ${esc(a.origin)}; also known as ${esc((a.aliases || []).slice(0, 3).join(", "))}</span></li>`).join("");
    const iocs = (r.indicators || []).map((i) => i.type.startsWith("ipv") ? `<a class="chip ioc" href="#/ip/${encodeURIComponent(i.value)}">${esc(i.value)}</a>` : `<span class="chip ioc" title="${esc(i.type)}">${esc(i.value.length > 48 ? i.value.slice(0, 46) + "..." : i.value)}</span>`).join("");
    const related = (r.related || []).map((x) => `<li><button class="link-btn" data-report="${x.id}">${esc(x.title)}</button> <span class="muted">${esc(x.source)}, ${fmtDate(x.published_at)}</span></li>`).join("");
    $(".drawer", slot).innerHTML = `
      <div class="row" style="justify-content:space-between"><div class="row">${verdictTag(c.verdict)}${sevTag(c.severity)}</div><button class="close-btn" data-close>Close</button></div>
      <h2>${esc(r.title)}</h2>
      <div class="meta"><span>${esc(r.source?.name || r.source_id)}</span><span>${fmtTime(r.published_at)}</span><a href="${esc(r.url)}" target="_blank" rel="noopener">Read the original</a></div>
      <p style="margin-top:14px">${esc(r.summary || "")}</p>
      <section><h3>Why Kavach classified it this way</h3>
        <dl class="kv">
          <dt>Main category</dt><dd><strong>${esc(c.category)}</strong></dd>
          <dt>Actual-threat confidence</dt><dd><div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1;max-width:220px"><i style="width:${Math.round((c.confidence || 0) * 100)}%;background:${c.verdict === "Actual threat" ? "var(--mal)" : c.verdict === "Potential threat" ? "var(--sus)" : "var(--muted)"}"></i></div><span>${pct(c.confidence, 0)}</span></div></dd>
          <dt>Admiralty code</dt><dd><strong>${esc(adm)}</strong> <span class="muted">source ${esc(REL[adm[0]] || "")}, information ${esc((CRED[adm.slice(1)] || "").toLowerCase())}</span></dd>
          <dt>Severity signals</dt><dd>${(c.severity_signals || []).map(esc).join(", ") || "none"}</dd>
        </dl>
        <div style="margin-top:14px">${cats}</div>
        <div class="chips" style="margin-top:10px">${signals}</div>
      </section>
      ${cves ? `<section><h3>Vulnerabilities (referenced from the vulnerabilities collection)</h3><ul class="mini-list" style="padding:0">${cves}</ul></section>` : ""}
      ${actors ? `<section><h3>Threat actors</h3><ul style="margin:0;padding-left:18px">${actors}</ul></section>` : ""}
      ${iocs ? `<section><h3>Indicators found in the text</h3><div class="chips">${iocs}</div></section>` : ""}
      ${related ? `<section><h3>Related reports (same CVE or actor)</h3><ul style="margin:0;padding-left:18px;display:grid;gap:6px">${related}</ul></section>` : ""}
      <section><h3>Source</h3><dl class="kv"><dt>Publisher</dt><dd>${esc(r.source?.name || "")}</dd><dt>Reliability</dt><dd>${esc(r.source?.reliability || "")}: ${esc(r.source?.reliability_text || "")}</dd><dt>Tags</dt><dd>${(r.tags || []).map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")}</dd></dl></section>`;
    $(".drawer", slot).focus?.();
  }

  // ================================================================== OVERVIEW
  async function pageOverview(page) {
    const [d, ex] = await Promise.all([api("/api/overview"), api("/api/ip-examples").catch(() => [])]);
    const c = d.counts;
    const actual = d.by_verdict["Actual threat"] || 0;
    const critHigh = (d.by_severity.Critical || 0) + (d.by_severity.High || 0);
    const maxCat = Math.max(1, ...d.by_category.map((x) => x.n));
    page.innerHTML = `
      <section class="hero">
        <h1>Is it a threat? Check any IP, CVE or campaign.</h1>
        <p class="lede">${num(c.reports)} threat reports from ${c.sources_ok} live sources, classified and cross-linked with ${num(c.indicators)} known-bad indicators. Everything is stored in MongoDB on your Mac.</p>
        <form class="hero-search" id="hero-form"><input id="hero-input" placeholder="Try an IP like ${esc(ex[0]?.ip || "185.220.101.1")}, or ransomware, or CVE-2024-3400" aria-label="Search"><button class="btn primary">Check</button></form>
        <div class="try">Examples ${ex.slice(0, 5).map((e) => `<a class="chip ioc" href="#/ip/${encodeURIComponent(e.ip)}" title="${esc(e.label)}">${esc(e.ip)}</a>`).join("")}<a class="chip" href="#/threats?q=ransomware">ransomware</a></div>
      </section>
      <div class="figures">
        <div class="figure"><b>${num(actual)}</b><span>reports judged an actual threat</span></div>
        <div class="figure"><b>${num(critHigh)}</b><span>critical or high severity</span></div>
        <div class="figure"><b>${num(c.indicators)}</b><span>indicators from ${num(c.sightings)} sightings</span></div>
        <div class="figure"><b>${num(c.kev)}</b><span>CVEs exploited in the wild (CISA KEV)</span></div>
      </div>
      <div class="grid cols-2">
        <section class="panel"><div class="panel-head"><h2>Latest actual threats</h2><a class="link-btn" href="#/threats?verdict=Actual%20threat">See all</a></div>
          <ul class="threat-list">${d.latest_threats.map((r) => `<li class="threat-row" data-report="${r.id}" tabindex="0"><span class="bar ${esc(r.severity)}"></span><div><div class="t">${esc(r.title)}</div><div class="meta"><span>${esc(r.source)}</span><span>${ago(r.published_at)}</span><span>${esc(r.category)}</span></div></div>${sevTag(r.severity)}</li>`).join("") || `<li class="empty">No actual threats yet. Run the setup script to download reports.</li>`}</ul></section>
        <section class="panel"><div class="panel-head"><h2>What is being reported</h2><span class="muted">all reports</span></div>
          <div class="cat-bars">${d.by_category.map((x) => `<div class="cat-bar"><button data-cat="${esc(x.name)}" title="Show ${esc(x.name)} reports">${esc(x.name)}</button><div class="track"><i style="width:${(100 * x.n) / maxCat}%;background:${x.name === d.by_category[0].name ? "var(--accent)" : "var(--muted)"}"></i></div><span class="muted num">${num(x.n)}</span></div>`).join("")}</div></section>
      </div>
      <div class="grid cols-2" style="margin-top:18px">
        <section class="panel"><div class="panel-head"><h2>Reports per day by severity</h2><span class="muted">last 30 days</span></div>
          <div style="padding:10px 16px 4px">${severityChart(d.per_day)}</div>
          <div class="legend">${["Critical", "High", "Medium", "Low"].map((s) => sevTag(s)).join("")}</div></section>
        <section class="panel"><div class="panel-head"><h2>Most reported</h2><span class="muted">CVEs and actors</span></div>
          <div class="grid" style="grid-template-columns:1fr 1fr;gap:0">
            <ul class="mini-list">${d.top_cves.map((x) => `<li><button class="mono" data-q="${esc(x.cve)}">${esc(x.cve)}</button><span class="row" style="gap:6px">${x.kev ? `<span class="kev" title="${esc((x.kev.vendor || "") + " " + (x.kev.product || ""))}">KEV</span>` : ""}<span class="muted">${x.n}</span></span></li>`).join("") || `<li class="muted">No CVEs yet</li>`}</ul>
            <ul class="mini-list">${d.top_actors.map((x) => `<li><button data-q="${esc(x.name)}">${esc(x.name)}</button><span class="muted">${x.n}</span></li>`).join("") || `<li class="muted">No actors named yet</li>`}</ul>
          </div></section>
      </div>
      <div class="grid cols-2" style="margin-top:18px">
        <section class="panel"><div class="panel-head"><h2>Source health</h2><a class="link-btn" href="#/sources">Manage sources</a></div>
          <div class="feed-grid">${d.sources.filter((s) => s.kind !== "sample" && s.kind !== "derived").map((s) => `<div title="${esc(s.error || `${s.items || 0} items, ${ago(s.last_fetch)}`)}"><span class="dot ${s.status === "ok" ? "ok" : s.status === "error" ? "err" : ""}"></span><span>${esc(s.name)}</span></div>`).join("")}</div></section>
        <section class="panel"><div class="panel-head"><h2>Recent IP checks</h2><a class="link-btn" href="#/ip">Check an IP</a></div>
          <ul class="mini-list">${(d.recent_lookups || []).map((l) => `<li><a class="mono" href="#/ip/${encodeURIComponent(l.ip)}">${esc(l.ip)}</a><span class="row" style="gap:10px"><span class="muted">${ago(l.at)}</span>${ipVerdictTag(l.verdict, l.score)}</span></li>`).join("") || `<li class="muted">No lookups yet. Try one of the examples above.</li>`}</ul></section>
      </div>`;
    $("#hero-form").addEventListener("submit", (e) => { e.preventDefault(); goSearch($("#hero-input").value); });
    $$("[data-cat]", page).forEach((b) => b.addEventListener("click", () => (location.hash = `#/threats?category=${encodeURIComponent(b.dataset.cat)}`)));
    $$("[data-q]", page).forEach((b) => b.addEventListener("click", () => (location.hash = `#/threats?q=${encodeURIComponent(b.dataset.q)}`)));
  }

  const IPV_COLORS = { Malicious: "var(--mal)", Suspicious: "var(--sus)", "Low risk": "var(--low)", "No known threat": "var(--ok)" };
  function ipVerdictTag(v, score) {
    const col = IPV_COLORS[v] || "var(--muted)";
    return `<span class="verdict-tag" style="color:${col};background:color-mix(in srgb, ${col} 14%, transparent)">${esc(v)}${score != null && IPV_COLORS[v] ? ` ${score}` : ""}</span>`;
  }

  // ================================================================== THREAT FEED
  async function pageThreats(page, route) {
    const p = route.params;
    const st = {
      q: p.get("q") || "", category: (p.get("category") || "").split("|").filter(Boolean), severity: (p.get("severity") || "").split("|").filter(Boolean),
      verdict: (p.get("verdict") || "").split("|").filter(Boolean), source: (p.get("source") || "").split("|").filter(Boolean),
      days: Number(p.get("days") || 0), sort: p.get("sort") || "relevance", page: Number(p.get("page") || 1),
    };
    const facets = await api("/api/facets");
    const facet = (key, title, items, labelKey = "value") => `
      <div class="facet"><h3>${title}</h3>${items.map((x) => `<label><input type="checkbox" data-f="${key}" value="${esc(x.value)}" ${st[key].includes(x.value) ? "checked" : ""}><span>${esc(x[labelKey] || x.value)}</span><span class="n">${num(x.n)}</span></label>`).join("")}</div>`;
    const sevOrder = ["Critical", "High", "Medium", "Low"];
    const verdictOrder = ["Actual threat", "Potential threat", "Informational"];
    const sortBy = (arr, order) => [...arr].sort((a, b) => order.indexOf(a.value) - order.indexOf(b.value));
    page.innerHTML = `
      <div class="page-head"><div><h1>Threat feed</h1><p class="lede">Every report is classified on arrival: category, severity, and whether it describes an actual threat. Search uses a MongoDB text index; a CVE or IP searches the referenced ids.</p></div></div>
      <div class="threats-layout">
        <aside class="filters" aria-label="Filters">
          ${facet("verdict", "Verdict", sortBy(facets.verdict, verdictOrder))}
          ${facet("severity", "Severity", sortBy(facets.severity, sevOrder))}
          <div class="facet"><h3>Published</h3><select data-days><option value="0">Any time</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></select></div>
          ${facet("category", "Category", facets.category)}
          ${facet("source", "Source", facets.source, "label")}
        </aside>
        <section>
          <div class="search-row"><input id="q" type="search" placeholder="Search titles and summaries, or paste a CVE or IP" value="${esc(st.q)}" aria-label="Search reports">
            <select id="sort" aria-label="Sort"><option value="relevance">Most relevant</option><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select>
            <button class="btn small" id="clear">Clear filters</button></div>
          <div class="result-info" id="info"></div>
          <div class="panel" id="list"></div>
          <div class="pager" id="pager"></div>
        </section>
      </div>`;
    $("[data-days]", page).value = String(st.days);
    $("#sort", page).value = st.sort;

    const sync = () => {
      const qp = new URLSearchParams();
      if (st.q) qp.set("q", st.q);
      ["category", "severity", "verdict", "source"].forEach((k) => st[k].length && qp.set(k, st[k].join("|")));
      if (st.days) qp.set("days", st.days);
      if (st.sort !== "relevance") qp.set("sort", st.sort);
      if (st.page > 1) qp.set("page", st.page);
      history.replaceState(null, "", `#/threats${qp.toString() ? "?" + qp : ""}`);
      return qp;
    };
    let seq = 0;
    async function load() {
      const my = ++seq;
      const qp = sync();
      qp.set("limit", "20");
      qp.set("page", st.page);
      $("#list").innerHTML = `<div class="panel-pad"><div class="skeleton"></div><div class="skeleton" style="margin-top:10px;width:70%"></div></div>`;
      let d;
      try { d = await api(`/api/reports?${qp}`); } catch (err) { $("#list").innerHTML = errorBox(err); return; }
      if (my !== seq) return;
      const modeText = { text: "full-text search ($text index)", cve: "reports referencing this CVE", ip: "reports that name this IP as an indicator", regex: "regex fallback", all: "all reports" }[d.mode];
      $("#info").innerHTML = `${num(d.total)} result${d.total === 1 ? "" : "s"}, ${esc(modeText)}, ${d.took_ms} ms${d.mode === "ip" ? ` <a class="link-btn" href="#/ip/${encodeURIComponent(st.q)}">Open the IP dossier</a>` : ""}`;
      $("#list").innerHTML = d.results.length ? d.results.map((r) => reportCard(r, d.mode === "text" ? st.q : "")).join("")
        : `<div class="empty"><strong>No reports match</strong>Try fewer filters or a broader word. ${st.q && kindOf(st.q) === "ip" ? `This IP is not named in any report, but you can still <a href="#/ip/${encodeURIComponent(st.q)}">check its reputation</a>.` : ""}</div>`;
      const pages = Math.ceil(d.total / d.limit);
      $("#pager").innerHTML = pages > 1 ? `<button class="btn small" data-page="${st.page - 1}" ${st.page <= 1 ? "disabled" : ""}>Previous</button><span class="muted">Page ${st.page} of ${pages}</span><button class="btn small" data-page="${st.page + 1}" ${st.page >= pages ? "disabled" : ""}>Next</button>` : "";
    }
    page.addEventListener("change", (e) => {
      const t = e.target;
      if (t.dataset.f) {
        const arr = st[t.dataset.f];
        if (t.checked) arr.push(t.value); else arr.splice(arr.indexOf(t.value), 1);
      } else if (t.matches("[data-days]")) st.days = Number(t.value);
      else if (t.id === "sort") st.sort = t.value;
      else return;
      st.page = 1;
      load();
    });
    let timer;
    $("#q").addEventListener("input", (e) => { clearTimeout(timer); timer = setTimeout(() => { st.q = refang(e.target.value); st.page = 1; load(); }, 320); });
    $("#clear").addEventListener("click", () => { location.hash = "#/threats"; });
    $("#pager").addEventListener("click", (e) => { const b = e.target.closest("[data-page]"); if (b) { st.page = Number(b.dataset.page); load(); window.scrollTo({ top: 0 }); } });
    load();
  }

  // ================================================================== IP INTELLIGENCE
  async function pageIP(page, route) {
    const ip = route.arg ? refang(route.arg) : "";
    const [ex, recent] = await Promise.all([api("/api/ip-examples").catch(() => []), api("/api/lookups/recent").catch(() => [])]);
    page.innerHTML = `
      <div class="page-head"><div><h1>IP intelligence</h1>
        <p class="lede">Enter any IPv4 or IPv6 address, including one this platform has never seen. Kavach checks its MongoDB threat feeds and live internet sources, then explains the verdict point by point.</p></div></div>
      <form class="ip-form" id="ipf"><input id="ipin" value="${esc(ip)}" placeholder="e.g. 45.155.205.233" aria-label="IP address" spellcheck="false" autocomplete="off"><button class="btn primary">Check IP</button></form>
      <div class="example-row">Try ${ex.map((e) => `<a class="chip ioc" href="#/ip/${encodeURIComponent(e.ip)}" title="${esc(e.label)}">${esc(e.ip)}</a>`).join("")}</div>
      <div id="dossier" class="dossier"></div>
      ${!ip ? `<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Recently checked</h2></div><ul class="mini-list">${recent.map((l) => `<li><a class="mono" href="#/ip/${encodeURIComponent(l.ip)}">${esc(l.ip)}</a><span class="row" style="gap:10px"><span class="muted">${l.country || ""}</span><span class="muted">${ago(l.at)}</span>${ipVerdictTag(l.verdict, l.score)}</span></li>`).join("") || `<li class="muted">Nothing checked yet.</li>`}</ul></section>` : ""}`;
    $("#ipf").addEventListener("submit", (e) => {
      e.preventDefault();
      const v = refang($("#ipin").value);
      if (kindOf(v) !== "ip") { toast("That does not look like an IP address. Example: 8.8.8.8 or 2001:4860:4860::8888"); return; }
      location.hash = `#/ip/${encodeURIComponent(v)}`;
    });
    if (ip) loadDossier(ip, false);
  }

  async function loadDossier(ip, refresh) {
    const box = $("#dossier");
    if (!box) return;
    box.innerHTML = `<div class="verdict-band"><div><div class="ipv">${esc(ip)}</div><div class="row" style="margin-top:18px;gap:12px"><span class="spin"></span><span>Checking local threat feeds, GreyNoise, Shodan InternetDB, geolocation and reverse DNS</span></div></div></div>`;
    let r;
    try { r = await api(`/api/ip/${encodeURIComponent(ip)}${refresh ? "?refresh=true" : ""}`); } catch (err) { box.innerHTML = errorBox(err); return; }
    const vclass = "v-" + r.verdict.replace(/[^A-Za-z]+/g, "-").replace(/-$/, "");
    const maxAbs = Math.max(30, ...r.factors.map((f) => Math.abs(f.points)));
    const ledger = r.factors.length ? r.factors.map((f) => {
      const w = (50 * Math.abs(f.points)) / maxAbs;
      const bar = f.points >= 0 ? `<i class="pos" style="width:${w}%"></i><b style="left:calc(50% + ${w}% + 6px)">+${f.points}</b>` : `<i class="neg" style="width:${w}%"></i><b style="right:calc(50% + ${w}% + 6px)">${f.points}</b>`;
      return `<li><div><div class="lab">${esc(f.label)}</div><div class="src">${esc(f.source)}${f.detail ? `: ${esc(f.detail)}` : ""}</div></div><div class="diverge" aria-label="${f.points} points">${bar}</div></li>`;
    }).join("") : `<li><div><div class="lab">No evidence against this IP</div><div class="src">None of the checked sources list it, and nothing suggests it is dangerous.</div></div><div></div></li>`;
    const statusDot = (s) => (s === "hit" ? "err" : s === "ok" || s === "clean" || s === "no-data" ? "ok" : s === "skipped" ? "" : "warn");
    const statusText = { hit: "listed", clean: "not listed", ok: "answered", "no-data": "no record", skipped: "not configured", error: "unavailable" };
    const checks = r.checks.map((c) => `<div class="check"><span class="dot ${statusDot(c.status)}"></span><div><strong>${esc(c.source)}</strong> <span class="muted">${statusText[c.status] || esc(c.status)}${c.ms != null ? `, ${c.ms} ms` : ""}</span><small>${esc(c.detail || "")}</small></div></div>`).join("");
    const g = r.geo;
    const net = r.network;
    const loc = r.local || {};
    const feedRows = (loc.sightings || []).filter((s) => !s.report_id).map((s) => `<tr><td>${esc(s.source)}${s.via_cidr ? `<div class="muted mono" style="font-size:12px">network ${esc(s.via_cidr)}</div>` : ""}</td><td>${esc(s.reliability || "")}</td><td class="nowrap">${fmtDate(s.first_observed)}</td><td class="nowrap">${ago(s.observed_at)}</td><td class="num">${s.detail && s.detail.hits ? `${s.detail.hits} lists` : s.confidence ?? ""}</td></tr>`).join("");
    const reps = (loc.reports || []).map((x) => `<li><button class="link-btn" data-report="${x.id}">${esc(x.title)}</button> <span class="muted">${fmtDate(x.published_at)}</span></li>`).join("");
    box.innerHTML = `
      <div class="verdict-band ${vclass}">
        <div>
          <div class="ipv"><span>${esc(r.ip)}</span><span>IPv${r.version}</span>${r.hostname ? `<span>${esc(r.hostname)}</span>` : ""}</div>
          <div class="verdict-word">${esc(r.verdict)}</div>
          <p class="summary">${esc(r.summary)}</p>
          <div class="row" style="margin-top:10px"><span class="muted" style="font-size:13px">${r.cached ? `Saved result from ${ago(r.looked_up_at)} (cached in MongoDB with a TTL index)` : `Checked just now in ${r.took_ms} ms`}${r.history?.times_checked > 1 ? `, checked ${r.history.times_checked} times` : ""}</span>
          <button class="btn small" id="recheck">Re-check live</button></div>
        </div>
        ${r.is_global || r.score ? dialSVG(r.score) : ""}
      </div>
      <div class="dossier-grid">
        <div class="grid" style="align-content:start">
          <section class="panel"><div class="panel-head"><h2>Evidence</h2><span class="muted">points add up to the score</span></div><ul class="ledger">${ledger}</ul>
            <div class="checks">${checks}</div></section>
          ${feedRows ? `<section class="panel"><div class="panel-head"><h2>Threat feeds in MongoDB that list it</h2><span class="muted">sightings collection</span></div><div class="scroll-x"><table class="table"><thead><tr><th>Source</th><th>Rel.</th><th>First seen</th><th>Last listed</th><th class="num">Detail</th></tr></thead><tbody>${feedRows}</tbody></table></div></section>` : ""}
          ${reps ? `<section class="panel panel-pad"><h2 style="margin-bottom:10px">Reports that name this IP</h2><ul style="margin:0;padding-left:18px;display:grid;gap:6px">${reps}</ul></section>` : ""}
        </div>
        <div class="grid" style="align-content:start">
          ${g ? `<section class="panel ${vclass}" style="overflow:hidden">${worldMap(g.lat, g.lon)}<div class="panel-pad"><dl class="kv">
              <dt>Location</dt><dd>${esc([g.city, g.regionName, g.country].filter(Boolean).join(", "))}</dd>
              <dt>Network</dt><dd>${esc(g.isp || "")}${g.org && g.org !== g.isp ? `, ${esc(g.org)}` : ""}</dd>
              <dt>ASN</dt><dd class="mono">${esc(g.as || "")}</dd>
              <dt>Connection</dt><dd>${[g.hosting ? "data centre / hosting" : "", g.proxy ? "proxy, VPN or Tor" : "", g.mobile ? "mobile network" : ""].filter(Boolean).join(", ") || "residential or business"}</dd>
              <dt>Time zone</dt><dd>${esc(g.timezone || "")}</dd></dl></div></section>`
              : r.range_note ? `<section class="panel panel-pad"><h2>Not on the public internet</h2><p class="muted">${esc(r.range_note)} No internet service can see traffic from it, so there is nothing to look up outside your own network.</p></section>` : ""}
          ${net && (net.ports.length || net.vulns.length || net.hostnames.length) ? `<section class="panel panel-pad"><h2 style="margin-bottom:12px">Exposed to the internet</h2><dl class="kv">
              <dt>Open ports</dt><dd><div class="ports">${net.ports.map((p) => `<span class="port">${p}</span>`).join("") || "none seen"}</div></dd>
              ${net.vulns.length ? `<dt>Known CVEs</dt><dd><div class="chips">${net.vulns.slice(0, 12).map((v) => `<a class="chip ioc" href="#/threats?q=${encodeURIComponent(v)}">${esc(v)}</a>`).join("")}${net.vulns.length > 12 ? `<span class="chip">+${net.vulns.length - 12} more</span>` : ""}</div></dd>` : ""}
              ${net.hostnames.length ? `<dt>Hostnames</dt><dd class="mono">${net.hostnames.slice(0, 5).map(esc).join("<br>")}</dd>` : ""}
              ${net.tags.length ? `<dt>Tags</dt><dd>${net.tags.map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")}</dd>` : ""}
              <dt>Software</dt><dd class="mono" style="font-size:12px">${net.cpes.slice(0, 5).map(esc).join("<br>") || "n/a"}</dd></dl><p class="faint" style="font-size:12.5px;margin:12px 0 0">From Shodan InternetDB. Open services are a risk, not proof of bad behaviour.</p></section>` : ""}
          ${r.greynoise ? `<section class="panel panel-pad"><h2 style="margin-bottom:12px">GreyNoise</h2><dl class="kv"><dt>Classification</dt><dd>${esc(r.greynoise.classification || "not observed")}</dd><dt>Internet scanner</dt><dd>${r.greynoise.noise ? "yes, seen scanning" : "no"}</dd><dt>Known service</dt><dd>${r.greynoise.riot ? esc(r.greynoise.name || "yes") : "no"}</dd>${r.greynoise.last_seen ? `<dt>Last seen</dt><dd>${esc(r.greynoise.last_seen)}</dd>` : ""}</dl></section>` : ""}
        </div>
      </div>`;
    animateDial(box);
    $("#recheck").addEventListener("click", () => loadDossier(ip, true));
  }

  // ================================================================== CLASSIFIER
  const EXAMPLES = [
    ["Zero-day", "Attackers are actively exploiting CVE-2024-3400, a critical command injection zero-day in Palo Alto Networks PAN-OS GlobalProtect. The state-sponsored group UTA0218 deployed a Python backdoor and exfiltrated configuration files. C2 traffic went to 144.172.79[.]92. Patch now."],
    ["Phishing kit", "A new phishing-as-a-service kit uses fake Microsoft 365 login pages and an adversary-in-the-middle proxy to steal session cookies and bypass MFA. Lures arrive as invoice emails from lookalike domains such as micros0ft-billing[.]com."],
    ["Policy news", "The European Union published new guidance on NIS2 compliance for medium-sized companies, including a framework for incident reporting deadlines and best practices for supply chain risk management."],
  ];
  async function pageClassify(page) {
    page.innerHTML = `
      <div class="page-head"><div><h1>Threat classifier</h1><p class="lede">Paste any advisory, news article or analyst note. The same engine that labels every incoming report tells you its category, severity, whether it is an actual threat, and exactly which words decided it.</p></div></div>
      <div class="classify-layout">
        <section class="panel panel-pad">
          <label for="ctext" class="sr-only">Text to classify</label>
          <textarea id="ctext" class="big" placeholder="Paste threat text here"></textarea>
          <div class="row" style="margin-top:12px;justify-content:space-between">
            <div class="row"><label for="crel" class="muted" style="font-size:13.5px">Source reliability</label>
              <select id="crel">${Object.entries(REL).map(([k, v]) => `<option value="${k}" ${k === "B" ? "selected" : ""}>${k}: ${v}</option>`).join("")}</select></div>
            <button class="btn primary" id="cgo">Classify</button></div>
          <div class="example-row">Examples ${EXAMPLES.map((e, i) => `<button class="chip" data-ex="${i}">${esc(e[0])}</button>`).join("")}</div>
        </section>
        <section id="cout"><div class="panel empty"><strong>Results appear here</strong>Choose an example or paste your own text.</div></section>
      </div>`;
    $$("[data-ex]", page).forEach((b) => b.addEventListener("click", () => { $("#ctext").value = EXAMPLES[b.dataset.ex][1]; run(); }));
    $("#cgo").addEventListener("click", run);
    $("#ctext").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); });
    async function run() {
      const text = $("#ctext").value;
      const out = $("#cout");
      out.innerHTML = `<div class="panel panel-pad"><span class="spin"></span></div>`;
      let r;
      try { r = await api("/api/classify", { method: "POST", body: { text, reliability: $("#crel").value } }); } catch (err) { out.innerHTML = errorBox(err); return; }
      const vcol = r.verdict === "Actual threat" ? "var(--mal)" : r.verdict === "Potential threat" ? "var(--sus)" : "var(--muted)";
      const cats = r.categories.map((x) => `<div class="share-row"><span>${esc(x.name)}</span><div class="track"><i style="width:${Math.round(x.share * 100)}%;background:${x.name === r.category ? "var(--accent)" : "var(--muted)"}"></i></div><span class="muted num">${x.score}</span></div>`).join("") || `<p class="muted">No threat vocabulary found.</p>`;
      const iocChips = [
        ...r.iocs.ips.map((v) => `<a class="chip ioc" href="#/ip/${encodeURIComponent(v)}">${esc(v)}</a>`),
        ...r.iocs.cves.map((v) => `<a class="chip ioc" href="#/threats?q=${encodeURIComponent(v)}">${esc(v)}${r.kev.includes(v) ? " KEV" : ""}</a>`),
        ...r.iocs.domains.map((v) => `<span class="chip ioc">${esc(v)}</span>`),
        ...r.iocs.urls.map((v) => `<span class="chip ioc">${esc(v.slice(0, 50))}</span>`),
        ...r.iocs.hashes.map((h) => `<span class="chip ioc" title="${esc(h.type)}">${esc(h.value.slice(0, 16))}...</span>`),
      ].join("");
      out.innerHTML = `<div class="panel panel-pad">
        <div class="row">${verdictTag(r.verdict)}${sevTag(r.severity)}<span class="muted" style="font-size:13px">Admiralty ${esc(r.admiralty)}</span></div>
        <div class="big-cat">${esc(r.category)}</div>
        <div class="row" style="flex-wrap:nowrap"><div class="meter" style="flex:1"><i style="width:${Math.round(r.confidence * 100)}%;background:${vcol}"></i></div><span class="nowrap">${pct(r.confidence, 0)} actual-threat confidence</span></div>
        <h3 style="margin:20px 0 10px">Category scores</h3>${cats}
        <h3 style="margin:18px 0 8px">Words that decided it</h3><div class="chips">${r.signals.map((s) => `<span class="chip signal" title="${esc(s.category)} +${s.weight}">${esc(s.match)}</span>`).join("") || `<span class="muted">none</span>`}</div>
        <h3 style="margin:18px 0 8px">Severity signals</h3><p style="margin:0">${r.severity_signals.map(esc).join(", ") || `<span class="muted">none, so severity stays low</span>`}</p>
        ${iocChips ? `<h3 style="margin:18px 0 8px">Indicators extracted (defanged text is refanged)</h3><div class="chips">${iocChips}</div>` : ""}
        ${r.actors.length ? `<h3 style="margin:18px 0 8px">Threat actors recognised</h3><p style="margin:0">${r.actors.map((a) => `<strong>${esc(a.name || a.id)}</strong> <span class="muted">${esc(a.origin || "")}</span>`).join(", ")}</p>` : ""}
        <p class="faint" style="font-size:12.5px;margin:18px 0 0">Admiralty code: letter = source reliability (${esc(REL[r.admiralty[0]])}), digit = credibility (${esc(CRED[r.admiralty.slice(1)])}).</p></div>`;
    }
  }

  // ================================================================== SOURCES
  async function pageSources(page) {
    const list = await api("/api/sources");
    const groups = { news: "Threat reports (RSS)", "ioc-feed": "Indicator feeds", "vulnerability-catalog": "Vulnerabilities", "annual-reports": "Annual reports (Lab 7.2 dataset)", aggregator: "Reference platform", derived: "Derived", sample: "Offline sample" };
    const rows = (kind) => list.filter((s) => s.kind === kind).map((s) => {
      const stt = s.stats || {};
      return `<tr><td><span class="row" style="flex-wrap:nowrap;gap:9px"><span class="dot ${stt.last_status === "ok" ? "ok" : stt.last_status === "error" ? "err" : ""}"></span><span>${s.homepage ? `<a href="${esc(s.homepage)}" target="_blank" rel="noopener">${esc(s.name)}</a>` : esc(s.name)}</span></span>${stt.last_error ? `<div class="faint" style="font-size:12px;margin-top:3px">${esc(stt.last_error)}</div>` : s.description ? `<div class="faint" style="font-size:12px;margin-top:3px">${esc(s.description)}</div>` : ""}</td>
        <td title="${esc(s.reliability_text || "")}">${esc(s.reliability || "")}</td><td class="num">${num(stt.items)}</td><td class="nowrap">${ago(stt.last_fetch)}</td></tr>`;
    }).join("");
    page.innerHTML = `
      <div class="page-head"><div><h1>Sources</h1><p class="lede">Where the intelligence comes from, how much each source is trusted (Admiralty scale A to F), and whether the last download worked. Each source document embeds its feed settings and fetch statistics.</p></div>
        <div class="row"><button class="btn" data-ingest="feeds">Update indicator feeds</button><button class="btn primary" data-ingest="news">Fetch new reports</button></div></div>
      <div id="ingest-status"></div>
      <div class="grid" style="gap:18px">${Object.entries(groups).map(([k, title]) => {
        const r = rows(k);
        return r ? `<section class="panel"><div class="panel-head"><h2>${title}</h2></div><div class="scroll-x"><table class="table"><thead><tr><th>Source</th><th>Rel.</th><th class="num">Items</th><th>Last fetch</th></tr></thead><tbody>${r}</tbody></table></div></section>` : "";
      }).join("")}</div>`;
    $$("[data-ingest]", page).forEach((b) => b.addEventListener("click", async () => {
      $$("[data-ingest]", page).forEach((x) => (x.disabled = true));
      const res = await api("/api/ingest", { method: "POST", body: { what: b.dataset.ingest } }).catch((e) => ({ started: false, message: e.message }));
      if (!res.started) { toast(esc(res.message || "Could not start")); $$("[data-ingest]", page).forEach((x) => (x.disabled = false)); return; }
      $("#ingest-status").innerHTML = `<div class="callout" style="margin-bottom:18px"><span class="spin"></span> Downloading. This takes 20 to 90 seconds; you can keep using the site.</div>`;
      const poll = setInterval(async () => {
        const s = await api("/api/ingest/status").catch(() => null);
        if (!s || s.running) return;
        clearInterval(poll);
        const n = s.result?.news?.new_reports;
        toast(s.error ? `Update failed: ${esc(s.error)}` : n != null ? `Update finished: ${n} new report${n === 1 ? "" : "s"} stored.` : "Indicator feeds updated.");
        render();
      }, 2500);
      onLeave(() => clearInterval(poll));
    }));
  }

  // ================================================================== LAB 7.1
  const NODE_POS = {
    reports: [330, 170], sources: [40, 40], vulnerabilities: [620, 40], threat_actors: [620, 300],
    indicators: [40, 300], sightings: [330, 420],
  };
  function schemaDiagram(rels, counts) {
    const W = 860, H = 540, nw = 200, nh = 96;
    const emb = {};
    rels.filter((r) => r.kind === "embedded").forEach((r) => (emb[r.collection] = emb[r.collection] || []).push(r.field));
    const center = (c) => [NODE_POS[c][0] + nw / 2, NODE_POS[c][1] + nh / 2];
    const edgeFor = (r) => {
      if (!NODE_POS[r.collection] || !NODE_POS[r.target]) return "";
      const [x1, y1] = center(r.collection), [x2, y2] = center(r.target);
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      const clip = (x, y, ox, oy) => {  // point on node border toward (ox, oy)
        const dx = ox - x, dy = oy - y;
        const s = Math.min(Math.abs((nw / 2 + 6) / (dx || 1e-6)), Math.abs((nh / 2 + 6) / (dy || 1e-6)));
        return [x + dx * s, y + dy * s];
      };
      const [ax, ay] = clip(x1, y1, x2, y2), [bx, by] = clip(x2, y2, x1, y1);
      const off = r.field === "report_id" ? 16 : r.field === "indicator_ids" ? -16 : 0;
      return `<path class="edge" d="M${ax} ${ay} L${bx} ${by}" marker-end="url(#arr)"/>
        <text class="edge-label" x="${mx}" y="${my - 6 + off}" text-anchor="middle">${esc(r.field)}</text>
        <text class="edge-card" x="${mx}" y="${my + 8 + off}" text-anchor="middle">${esc(r.cardinality)}</text>`;
    };
    const edges = rels.filter((r) => r.kind === "reference").map(edgeFor).join("");
    const nodes = Object.entries(NODE_POS).map(([c, [x, y]]) => `
      <g class="node ${c === "reports" ? "hub" : ""}"><rect x="${x}" y="${y}" width="${nw}" height="${nh}" rx="9"/>
        <text class="title" x="${x + 14}" y="${y + 24}">${c}</text><text class="count" x="${x + nw - 12}" y="${y + 24}" text-anchor="end">${num(counts[c] || 0)} docs</text>
        ${(emb[c] || []).slice(0, 3).map((f, i) => `<text class="emb" x="${x + 14}" y="${y + 48 + i * 16}">{ ${esc(f)} }</text>`).join("")}
        ${!(emb[c] || []).length ? `<text class="count" x="${x + 14}" y="${y + 48}">flat document</text>` : ""}</g>`).join("");
    return `<svg class="schema-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Collections and their relationships">
      <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" style="fill:var(--sus)"/></marker></defs>
      ${edges}${nodes}</svg>`;
  }

  async function pageLab71(page, route) {
    const [s, act] = await Promise.all([api("/api/lab71/schema"), api("/api/lab71/activity").catch(() => ({}))]);
    const tab = route.params.get("tab") || "map";
    const rels = s.relationships;
    const LIMIT = s.limit_bytes;
    const lg = (b) => Math.max(0, Math.log10(Math.max(1, b)) / Math.log10(LIMIT));
    const bson = s.bson.filter((b) => b.count);
    const totalDocs = bson.reduce((a, b) => a + b.count, 0);
    const avgAll = totalDocs ? bson.reduce((a, b) => a + b.total_bytes, 0) / totalDocs : 0;
    const biggest = bson.reduce((m, b) => (b.max_bytes > (m?.max_bytes || 0) ? b : m), null);
    page.innerHTML = `
      <div class="lab-intro"><div><h1>Schema lab 7.1</h1><p class="lede">This platform is the production schema under analysis. Its MongoDB dump is in the project's dump folder; every number below is computed live from the real documents.</p></div>
        <button class="btn small" id="refresh71">Recompute</button></div>
      <div class="tabs" role="tablist">${[["map", "Relationship map"], ["table", "Embedding vs referencing"], ["size", "$bsonSize and 16 MB"], ["activity", "Activity 7.1 redesign"]].map(([k, t]) => `<button role="tab" data-tab="${k}" class="${tab === k ? "active" : ""}">${t}</button>`).join("")}</div>
      <div id="tabbody"></div>`;
    const bodies = {
      map: () => `<section class="panel panel-pad">${schemaDiagram(rels, s.counts)}
          <div class="legend" style="padding:8px 0 0"><span class="pattern embedded">{ field } embedded inside the document</span><span class="pattern reference">field arrow = reference to another collection</span></div></section>
        <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Detected automatically from sampled documents</h2><span class="muted">$sample of 80 per collection</span></div>
          <div class="scroll-x"><table class="table"><thead><tr><th>Collection</th><th>Field</th><th>Detected as</th><th>Shape or target</th><th class="num">Evidence</th></tr></thead><tbody>
          ${s.detected.map((d) => `<tr><td>${esc(d.collection)}</td><td class="mono">${esc(d.field)}</td><td><span class="pattern ${d.kind}">${d.kind}</span></td><td>${d.kind === "reference" ? `to ${esc(d.target || "?")}` : esc(d.shape)}</td><td class="num">${d.kind === "reference" ? (d.resolved_pct != null ? `${d.resolved_pct}% of ${d.sampled_refs} resolve` : "none sampled") : d.avg_len != null ? `avg ${d.avg_len}, max ${d.max_len}` : `${d.avg_keys} keys`}</td></tr>`).join("")}
          </tbody></table></div></section>`,
      table: () => `<section class="panel"><div class="scroll-x"><table class="table"><thead><tr><th>Relationship</th><th>Pattern</th><th>Cardinality</th><th>Why this choice</th><th>Embedded alternative (for references)</th></tr></thead><tbody>
          ${[...rels].sort((a, b) => (a.kind > b.kind ? -1 : 1)).map((r) => `<tr><td class="mono">${esc(r.collection)}.${esc(r.field)}${r.target ? `<div class="faint">to ${esc(r.target)}</div>` : ""}</td><td><span class="pattern ${r.kind}">${r.kind}</span></td><td class="nowrap">${esc(r.cardinality)}</td><td>${esc(r.why)}</td><td class="muted">${esc(r.alternative || "")}</td></tr>`).join("")}
          </tbody></table></div></section>`,
      size: () => `<section class="panel"><div class="panel-head"><h2>Document size per collection</h2><span class="muted">log scale, red line = 16 MB</span></div>
          <div class="panel-pad" style="display:grid;gap:14px">${bson.map((b) => `<div class="gauge-row" style="grid-template-columns:150px 1fr 170px"><span class="mono">${esc(b.collection)}</span>
            <div class="sizebar" title="avg ${num(Math.round(b.avg_bytes))} B, max ${num(b.max_bytes)} B"><i class="max" style="width:${100 * lg(b.max_bytes)}%"></i><i class="avg" style="width:${100 * lg(b.avg_bytes)}%"></i><span class="limit"></span></div>
            <span class="num" style="text-align:right">avg ${bytes(b.avg_bytes)}, max ${bytes(b.max_bytes)}</span></div>`).join("")}
            <div class="legend" style="padding:0"><span><i style="display:inline-block;width:10px;height:10px;background:var(--low);border-radius:2px"></i> average</span><span><i style="display:inline-block;width:10px;height:10px;background:color-mix(in srgb,var(--low) 35%,transparent);border-radius:2px"></i> largest document</span></div></div>
          <div class="stat-line"><div><b>${bytes(avgAll)}</b><span>average document, all collections</span></div><div><b>${num(totalDocs)}</b><span>documents measured</span></div><div><b>${biggest ? bytes(biggest.max_bytes) : "n/a"}</b><span>largest (${esc(biggest?.collection || "")})</span></div><div><b>${biggest ? biggest.max_pct_of_16mb.toFixed(4) : 0}%</b><span>of the 16 MB limit</span></div></div></section>
        <div class="callout" style="margin-top:18px">No document approaches 16 MB. The only unbounded relationship, sightings per indicator, is stored as a separate referenced collection, so indicator documents never grow.</div>
        <section class="panel" style="margin-top:18px"><div class="scroll-x"><table class="table"><thead><tr><th>Collection</th><th class="num">Documents</th><th class="num">Average</th><th class="num">Min</th><th class="num">Max</th><th class="num">Max as % of 16 MB</th><th>Status</th></tr></thead><tbody>
          ${bson.map((b) => `<tr><td class="mono">${esc(b.collection)}</td><td class="num">${num(b.count)}</td><td class="num">${num(Math.round(b.avg_bytes))} B</td><td class="num">${num(b.min_bytes)} B</td><td class="num">${num(b.max_bytes)} B</td><td class="num">${b.max_pct_of_16mb.toFixed(4)}%</td><td>${esc(b.status)}</td></tr>`).join("")}</tbody></table></div></section>`,
      activity: () => activityBody(act),
    };
    const draw = (t) => {
      $$("[data-tab]", page).forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
      $("#tabbody").innerHTML = bodies[t]();
      history.replaceState(null, "", `#/lab71?tab=${t}`);
      const btn = $("#run71");
      if (btn) btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.innerHTML = `<span class="spin"></span> Building threat_verdicts and timing both designs`;
        try { Object.assign(act, await api("/api/lab71/activity/run", { method: "POST" })); draw("activity"); toast("Benchmark finished."); }
        catch (err) { toast(esc(err.message)); btn.disabled = false; btn.textContent = "Run the benchmark"; }
      });
    };
    $$("[data-tab]", page).forEach((b) => b.addEventListener("click", () => draw(b.dataset.tab)));
    $("#refresh71").addEventListener("click", async () => { await api("/api/lab71/schema?fresh=true"); render(); });
    draw(bodies[tab] ? tab : "map");
  }

  function activityBody(a) {
    const intro = `<section class="panel panel-pad"><h2>Redesign: embed sightings inside each indicator</h2>
      <p class="muted" style="max-width:78ch">To decide whether an indicator is an actual threat, the referenced design joins three collections: indicators, sightings and sources. The redesign copies each sighting, with its source's reliability, into one <span class="mono">threat_verdicts</span> document and stores the combined score. The score is noisy-OR: 1 minus the product of (1 minus source weight times confidence), so several independent reliable sources push it toward 100.</p>
      <div class="grid cols-2" style="margin-top:12px"><pre class="panel panel-pad mono" style="margin:0;font-size:12.5px;overflow-x:auto">// referenced (current)
indicators  { _id: "ipv4:1.2.3.4", type, value }
sightings   { indicator_id, source_id, confidence, observed_at }
sources     { _id, name, reliability, weight }</pre>
      <pre class="panel panel-pad mono" style="margin:0;font-size:12.5px;overflow-x:auto">// embedded (Activity 7.1)
threat_verdicts {
  _id: "ipv4:1.2.3.4", score: 91, verdict: "Actual threat",
  sightings: [ { source_id, source_name, reliability,
                 weight, confidence, observed_at } ]  // max 50
}</pre></div>
      <div class="row" style="margin-top:14px"><button class="btn primary" id="run71">${a && a.faster ? "Run the benchmark again" : "Run the benchmark"}</button><span class="muted" style="font-size:13px">Same as <span class="mono">python labs/lab7_1/activity_7_1_embedded_redesign.py</span></span></div></section>`;
    if (!a || !a.faster) return intro;
    const maxMs = (q) => Math.max(q.referenced_ms, q.embedded_ms, 0.001);
    const fast = a.faster.map((q) => `<tr><td><strong>${esc(q.query)}</strong><div class="faint" style="font-size:12.5px">referenced: ${esc(q.referenced_reads)}<br>embedded: ${esc(q.embedded_reads)}</div></td>
      <td style="min-width:230px"><div class="speed"><span class="faint" style="width:70px">referenced</span><div class="track"><i class="ref" style="width:${(100 * q.referenced_ms) / maxMs(q)}%"></i></div><span class="num">${q.referenced_ms} ms</span></div>
      <div class="speed" style="margin-top:6px"><span class="faint" style="width:70px">embedded</span><div class="track"><i class="emb" style="width:${Math.max(1, (100 * q.embedded_ms) / maxMs(q))}%"></i></div><span class="num">${q.embedded_ms} ms</span></div></td>
      <td class="num"><strong style="color:var(--ok)">${q.embedded_ms ? (q.referenced_ms / q.embedded_ms).toFixed(1) : "n/a"}x</strong> faster</td></tr>`).join("");
    const hard = a.harder.map((h) => `<tr><td><strong>${esc(h.operation)}</strong><div class="faint" style="font-size:12.5px">${esc(h.note)}</div></td><td class="num">${h.referenced_ms} ms${h.referenced_docs != null ? `<div class="faint">${num(h.referenced_docs)} doc</div>` : ""}</td><td class="num">${h.embedded_ms} ms${h.embedded_docs != null ? `<div class="faint">${num(h.embedded_docs)} docs</div>` : ""}</td></tr>`).join("");
    return `${intro}
      <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Faster when embedded</h2><span class="muted">${a.sample_size} random indicators, ${fmtTime(a.ran_at)}</span></div><div class="scroll-x"><table class="table"><tbody>${fast}</tbody></table></div></section>
      <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Harder when embedded</h2><span class="muted">time and documents written</span></div><div class="scroll-x"><table class="table"><thead><tr><th>Operation</th><th class="num">Referenced</th><th class="num">Embedded</th></tr></thead><tbody>${hard}</tbody></table></div></section>
      <section class="panel" style="margin-top:18px"><div class="stat-line" style="border-top:none"><div><b>${num(a.build?.documents)}</b><span>threat_verdicts built in ${a.build?.seconds ?? "?"} s</span></div><div><b>${bytes(a.size.avg_bytes)}</b><span>average embedded document</span></div><div><b>${bytes(a.size.max_bytes)}</b><span>largest embedded document</span></div><div><b>${num(a.size.sightings_to_reach_16mb)}</b><span>sightings would reach 16 MB, so the array is capped at 50</span></div></div></section>
      <div class="callout" style="margin-top:18px">Verdict: embed for the read-heavy question "is this an actual threat?" (one document, one index seek), and keep the referenced sightings as the source of truth. Rebuild threat_verdicts with $merge after each feed import, because a reliability change otherwise has to be written into every embedded copy.</div>`;
  }

  // ================================================================== LAB 7.2
  async function pageLab72(page) {
    const [snap, res] = await Promise.all([api("/api/lab72/cache"), api("/api/lab72/results").catch(() => ({}))]);
    const c = snap.counters, ws = snap.working_set, cs = snap.collection;
    page.innerHTML = `
      <div class="lab-intro"><div><h1>Cache lab 7.2</h1><p class="lede">How much of the data fits in WiredTiger's RAM cache, and how often reads are served from memory. Figures come from <span class="mono">db.serverStatus().wiredTiger.cache</span> and <span class="mono">$collStats</span> on MongoDB ${esc(snap.version || "")}.</p></div>
        <button class="btn small" id="refresh72">Refresh</button></div>
      ${!cs ? `<div class="callout" style="margin:18px 0">The 100,000-document test collection does not exist yet. Run the lab script once to insert it:${copyCmd("python labs/lab7_2/lab_02_working_set_analysis.py")}</div>` : ""}
      <section class="panel" style="margin-top:18px"><div class="stat-line" style="border-top:none">
        <div><b>${bytes(c.max_bytes)}</b><span>cache size configured</span></div>
        <div><b>${bytes(c.used_bytes)}</b><span>in cache now (${snap.used_pct}%)</span></div>
        <div><b>${snap.dirty_pct}%</b><span>dirty, not yet written</span></div>
        <div><b>${pct(snap.hit_ratio_since_start, 2)}</b><span>hit ratio since server start</span></div>
        <div><b>${num(c.pages_read)}</b><span>pages read from disk</span></div></div></section>
      ${ws ? `<section class="panel panel-pad" style="margin-top:18px"><h2 style="margin-bottom:6px">Does the working set fit?</h2>
        <p class="muted" style="margin:0 0 14px">Working set for random reads over the whole collection = data ${bytes(cs.size)} + indexes ${bytes(cs.index_size)}. WiredTiger starts evicting when the cache is 80% full.</p>
        <div class="gauge-row"><span>Working set vs cache</span><div class="stack-track"><i style="width:${Math.min(100, 100 * ws.ratio_of_cache)}%;background:${ws.fits ? "var(--ok)" : "var(--mal)"}"></i><i style="left:80%;width:2px;background:var(--text)" title="80% eviction target"></i></div><span class="num">${(100 * ws.ratio_of_cache).toFixed(1)}%</span></div>
        <div class="gauge-row"><span>Collection data in cache</span><div class="stack-track"><i style="width:${Math.min(100, ws.collection_in_cache_pct)}%;background:var(--low)"></i></div><span class="num">${ws.collection_in_cache_pct}%</span></div>
        <div class="gauge-row"><span>Index in cache</span><div class="stack-track"><i style="width:${Math.min(100, ws.index_in_cache_pct || 0)}%;background:var(--low)"></i></div><span class="num">${ws.index_in_cache_pct ?? 0}%</span></div>
        <p style="margin:12px 0 0">${ws.fits ? "It fits: after a short warm-up almost every read is a cache hit." : "It does not fit: some reads must go to disk, so expect a lower hit ratio and evictions."}</p></section>` : ""}
      <div class="grid cols-2" style="margin-top:18px">
        <section class="panel"><div class="panel-head"><h2>Random read test</h2><button class="btn small primary" id="reads" ${cs ? "" : "disabled"}>Run 16 seconds</button></div>
          <div id="readsout" class="panel-pad"><p class="muted" style="margin:0">Reads random documents by <span class="mono">seq</span> and measures the hit ratio every 2 seconds: 1 minus pages read into cache divided by pages requested.</p></div></section>
        <section class="panel"><div class="panel-head"><h2>Live monitor (Activity 7.2)</h2><span class="muted" id="monstate">every 10 s</span></div>
          <div id="monout" class="panel-pad"></div></section>
      </div>
      ${res && res.reads ? `<section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Lab script result</h2><span class="muted">${fmtTime(res.ran_at)}${res.insert ? `, inserted 100,000 docs in ${res.insert.seconds} s, avg ${res.insert.avg_bytes} B` : ""}</span></div>
        <div class="panel-pad">${lineChart(res.reads.map((r) => ({ ...r })), { yKey: "hit_ratio", xLabel: (p) => `${p.t}s`, fmtY: (v) => `${(100 * v).toFixed(1)}%`, color: "var(--accent)" })}
        ${res.small_cache ? `<h3 style="margin:16px 0 6px">Same reads with the cache limited to ${res.small_cache.mb} MB</h3>${lineChart(res.small_cache.reads, { yKey: "hit_ratio", xLabel: (p) => `${p.t}s`, fmtY: (v) => `${(100 * v).toFixed(1)}%`, color: "var(--mal)" })}` : ""}</div></section>` : ""}`;
    $("#refresh72").addEventListener("click", render);
    const rb = $("#reads");
    rb?.addEventListener("click", async () => {
      rb.disabled = true;
      rb.innerHTML = `<span class="spin"></span> Reading`;
      $("#readsout").innerHTML = `<p class="muted" style="margin:0">Running random reads for 16 seconds...</p>`;
      try {
        const r = await api("/api/lab72/random-reads", { method: "POST", body: { seconds: 16 } });
        if (r.error) throw new Error(r.error);
        const last = r.series[r.series.length - 1] || {};
        $("#readsout").innerHTML = lineChart(r.series, { yKey: "hit_ratio", xLabel: (p) => `${p.t}s`, fmtY: (v) => `${(100 * v).toFixed(2)}%` }) +
          `<p style="margin:10px 0 0">${num(r.reads)} reads in ${r.seconds} s (${num(Math.round(r.reads / r.seconds))} per second). Last interval: <strong>${pct(last.hit_ratio, 2)}</strong> hits, ${num(last.pages_read)} pages from disk, average ${last.avg_ms} ms per read.</p>`;
      } catch (err) { $("#readsout").innerHTML = `<p class="muted">${esc(err.message)}</p>`; }
      rb.disabled = false;
      rb.textContent = "Run 16 seconds";
    });
    async function monitor() {
      const rows = await api("/api/lab72/metrics?limit=90").catch(() => []);
      const box = $("#monout");
      if (!box) return;
      const fresh = rows.length && Date.now() - new Date(rows[rows.length - 1].at).getTime() < 30000;
      $("#monstate").textContent = fresh ? "monitor running" : rows.length ? `last sample ${ago(rows[rows.length - 1].at)}` : "not started";
      if (!rows.length) {
        box.innerHTML = `<p class="muted" style="margin:0 0 4px">Start the monitor in a second Terminal tab. It samples the cache every 10 seconds and looks for new threat reports; this chart updates by itself.</p>${copyCmd("python labs/lab7_2/activity_7_2_monitor.py --workload")}`;
        return;
      }
      const last = rows[rows.length - 1];
      box.innerHTML = lineChart(rows, { yKey: "hit_ratio", xLabel: (p) => new Date(p.at).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }), fmtY: (v) => `${(100 * v).toFixed(2)}%`, h: 180 }) +
        `<p style="margin:10px 0 0;font-size:14px">Latest: <strong>${pct(last.hit_ratio, 2)}</strong> hit ratio, cache ${last.used_pct}% full, ${num(last.evicted)} pages evicted, ${num(last.new_reports)} new reports found this session.</p>`;
    }
    monitor();
    const t = setInterval(monitor, 10000);
    onLeave(() => clearInterval(t));
  }

  // ================================================================== USE CASES (classroom update)
  // Live sync (use case 6): change stream / polling over Server-Sent Events + a local copy in the browser.
  const SYNC_KEY = "kavach-sync";
  const sync = { es: null, mode: null, connected: false, store: { token: "", items: [], updated_at: null } };
  try { Object.assign(sync.store, JSON.parse(localStorage.getItem(SYNC_KEY) || "{}")); } catch (e) { /* ignore */ }
  function saveSync() { try { localStorage.setItem(SYNC_KEY, JSON.stringify(sync.store)); } catch (e) { /* private mode */ } }
  function syncState() {
    const el = $("#sync-state");
    if (!el) return;
    const label = !sync.connected ? `Live sync offline (${num(sync.store.items.length)} saved)` : sync.mode === "change_stream" ? "Live sync: change stream" : "Live sync: polling";
    el.innerHTML = `<span class="dot ${sync.connected ? "ok" : "err"}"></span><span>${label}</span>`;
    window.dispatchEvent(new CustomEvent("kavach-sync"));
  }
  function startSync() {
    if (!window.EventSource || sync.es) return;
    const es = new EventSource(`/api/stream?resume=${encodeURIComponent(sync.store.token || "")}`);
    sync.es = es;
    es.addEventListener("hello", (e) => {
      const h = JSON.parse(e.data);
      sync.mode = h.mode;
      sync.connected = true;
      if (h.resync) sync.store.items = [];
      if (h.token && (!sync.store.token || h.resync || !sync.store.token.startsWith(h.mode === "change_stream" ? "cs:" : "poll:"))) sync.store.token = h.token;
      saveSync();
      syncState();
    });
    es.addEventListener("report", (e) => {
      const card = JSON.parse(e.data);
      sync.store.token = e.lastEventId || sync.store.token;
      sync.store.items = [card, ...sync.store.items.filter((x) => x.id !== card.id)].slice(0, 50);
      sync.store.updated_at = new Date().toISOString();
      saveSync();
      syncState();
      if (card.verdict === "Actual threat") toast(`New actual threat: <a href="#/threats?q=${encodeURIComponent(card.title || "")}">${esc(card.title)}</a>`);
    });
    es.onerror = () => { sync.connected = false; syncState(); };   // EventSource reconnects by itself with Last-Event-ID
  }


  async function pageUseCases(page, route) {
    let st = await api("/api/usecases");
    const tabs = [["table", "The six use cases"], ["content", "1 Content"], ["catalog", "2 Catalog"], ["profiles", "3 Profiles"], ["timeseries", "4 Time-series"], ["analytics", "5 Analytics"], ["sync", "6 Sync"]];
    let tab = route.params.get("tab") || "table";
    page.innerHTML = `
      <div class="lab-intro"><div><h1>MongoDB use cases</h1><p class="lede">The six "where MongoDB fits" use cases from the classroom, each built into this platform with its design pattern. Every panel reads real collections; run the demos to measure them.</p></div>
        <button class="btn small primary" id="ucrun">Run all six demos</button></div>
      <div class="tabs" role="tablist">${tabs.map(([k, t]) => `<button role="tab" data-tab="${k}">${t}</button>`).join("")}</div>
      <div id="tabbody"></div>`;
    const R = () => st.results || {};
    const resultLine = (k) => {
      const r = R()[k];
      if (!r) return `<span class="faint">not run yet</span>`;
      if (!r.ok) return `<span style="color:var(--mal)">${esc(r.error)}</span>`;
      return esc(r.takeaway || "done");
    };
    const runOne = (k, label, extra = {}) => `<button class="btn small" data-run="${k}" data-extra='${esc(JSON.stringify(extra))}'>${label}</button>`;
    const c = () => st.collections;

    const bodies = {
      table: () => `<section class="panel"><div class="scroll-x"><table class="table"><thead><tr><th>Use case</th><th>Why MongoDB fits</th><th>Design pattern</th><th>In Kavach CTI</th><th>Status</th></tr></thead><tbody>
        ${st.use_cases.map((u) => {
          const live = { content: `${num(c().briefings)} briefing(s)`, catalog: c().indicators_validator ? "validator on" : "validator off",
            profiles: `${num(c().analysts)} profile(s)`, timeseries: c().feed_telemetry_timeseries ? `${num(c().feed_telemetry)} measurements` : "not a time-series yet",
            analytics: `${num(c().report_stats_daily)} daily buckets`, sync: c().replica_set ? "change streams" : "polling (standalone)" }[u.key];
          const good = { content: c().briefings > 0, catalog: c().indicators_validator, profiles: c().analysts > 0,
            timeseries: !!c().feed_telemetry_timeseries, analytics: c().report_stats_daily > 0, sync: c().replica_set }[u.key];
          return `<tr><td><a href="#/usecases?tab=${u.key}"><strong>${u.n}. ${esc(u.use_case)}</strong></a></td><td>${esc(u.why)}</td><td>${esc(u.pattern)}</td>
            <td class="muted" style="max-width:46ch">${esc(u.where)}<div class="mono faint" style="margin-top:4px">${esc(u.collection)}</div></td>
            <td class="nowrap"><span class="pattern ${good ? "embedded" : "reference"}">${esc(live)}</span></td></tr>`;
        }).join("")}</tbody></table></div></section>
        ${R().ran_at ? `<section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Last run</h2><span class="muted">${fmtTime(R().ran_at)}</span></div><div class="scroll-x"><table class="table"><tbody>
          ${st.use_cases.map((u) => `<tr><td class="nowrap"><strong>${u.n}. ${esc(u.use_case)}</strong></td><td>${resultLine(u.key)}</td><td class="num">${R()[u.key]?.seconds ?? ""}${R()[u.key] ? " s" : ""}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
        <div class="callout" style="margin-top:18px">Same as ${copyCmd("python labs/use_cases/use_case_patterns.py")}Written answers: <span class="mono">labs/use_cases/USE_CASES.md</span></div>`,

      content: () => `<section class="panel panel-pad"><div class="row" style="justify-content:space-between"><div><h2 style="margin:0">Embedded content blocks</h2><p class="muted" style="margin:4px 0 0">One <span class="mono">briefings</span> document, an ordered <span class="mono">blocks[]</span> array, every block a different shape.</p></div><button class="btn small" id="rebrief">Rebuild today's briefing</button></div></section>
        <div class="grid cols-2" style="margin-top:18px"><section class="panel panel-pad" id="brief"><div class="skeleton"></div></section><section class="panel panel-pad"><h3 style="margin-top:0">Stored as</h3><pre class="mono" id="briefjson" style="font-size:12px;overflow-x:auto;margin:0"></pre></section></div>`,

      catalog: () => {
        const r = R().catalog;
        return `<section class="panel panel-pad"><div class="row" style="justify-content:space-between"><div><h2 style="margin:0">Schema validation with flexible fields</h2><p class="muted" style="margin:4px 0 0">Indicators share a core (<span class="mono">type</span>, <span class="mono">value</span>) and add per-type attributes. Validator: <strong>${c().indicators_validator ? "on" : "off"}</strong>, level moderate, action error.</p></div>${runOne("catalog", "Run validator tests")}</div></section>
        ${r && r.ok ? `<section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Fields per indicator type</h2><span class="muted">$objectToArray over a $sample</span></div><div class="scroll-x"><table class="table"><thead><tr><th>Type</th><th class="num">Sampled</th><th>Fields</th></tr></thead><tbody>
          ${r.shapes.map((s) => `<tr><td class="mono">${esc(s.type)}</td><td class="num">${num(s.sampled)}</td><td><div class="chips">${s.fields.filter((f) => f !== "_id").map((f) => `<span class="chip ioc">${esc(f)}</span>`).join("")}</div></td></tr>`).join("")}</tbody></table></div></section>
          <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Test inserts</h2></div><div class="scroll-x"><table class="table"><tbody>
          ${r.tests.map((t) => `<tr><td>${esc(t.case)}</td><td><span class="verdict-tag ${t.accepted ? "v-info" : "v-actual"}">${t.accepted ? "accepted" : "rejected"}</span></td><td class="mono muted">${esc(t.detail)}</td></tr>`).join("")}</tbody></table></div></section>` : ""}`;
      },

      profiles: () => `<section class="panel panel-pad"><h2 style="margin:0">Embed preferences, reference activity history</h2><p class="muted" style="margin:4px 0 0">Preferences live inside the <span class="mono">analysts</span> document; the unbounded IP lookup history stays in <span class="mono">lookup_history</span> with <span class="mono">analyst_id</span>.</p></section>
        <div class="grid cols-2" style="margin-top:18px"><section class="panel panel-pad" id="prof"><div class="skeleton"></div></section><section class="panel" id="activity"><div class="panel-pad"><div class="skeleton"></div></div></section></div>
        ${R().profiles?.ok ? `<div class="callout" style="margin-top:18px">Profile read ${R().profiles.profile_read_ms} ms (${num(R().profiles.profile_bytes)} bytes). Newest 20 of ${num(R().profiles.activity_total)} lookups in ${R().profiles.activity_page_ms} ms via <span class="mono">${esc(R().profiles.activity_plan)}</span>.</div>` : ""}`,

      timeseries: () => {
        const r = R().timeseries;
        const tsRow = (label, x) => `<tr><td>${label}</td><td class="num">${num(x.writes_per_sec)}</td><td class="num">${bytes(x.storage)}</td><td class="num">${bytes(x.index)}</td><td class="num">${x.buckets ?? "-"}</td><td class="num">${x.rollup_ms} ms</td></tr>`;
        return `<section class="panel panel-pad"><div class="row" style="justify-content:space-between"><div><h2 style="margin:0">Time-series collection</h2><p class="muted" style="margin:4px 0 0">Every feed fetch is a measurement in <span class="mono">feed_telemetry</span> ${c().feed_telemetry_timeseries ? `(timeField <span class="mono">${esc(c().feed_telemetry_timeseries.timeField)}</span>, metaField <span class="mono">${esc(c().feed_telemetry_timeseries.metaField)}</span>, granularity ${esc(c().feed_telemetry_timeseries.granularity)})` : ""}. ${num(c().feed_telemetry)} measurements so far.</p></div>${runOne("timeseries", "Run write benchmark", { events: 50000 })}</div></section>
        <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Feed fetches per hour</h2><span class="muted">last 72 h, $dateTrunc rollup</span></div><div class="panel-pad">${st.telemetry.length >= 2 ? lineChart(st.telemetry, { yKey: "fetches", xLabel: (p) => new Date(p.hour).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }), fmtY: (v) => v.toFixed(0) }) : `<p class="muted" style="margin:0">Measurements appear after feeds are fetched. Click <a href="#/sources">Update now</a> on the Sources page.</p>`}</div></section>
        ${r && r.ok ? `<section class="panel" style="margin-top:18px"><div class="panel-head"><h2>${num(r.events)} events, time-series vs regular</h2><span class="muted">${fmtTime(R().ran_at)}</span></div><div class="scroll-x"><table class="table"><thead><tr><th>Collection</th><th class="num">Writes/s</th><th class="num">Storage</th><th class="num">Indexes</th><th class="num">Buckets</th><th class="num">2-day rollup</th></tr></thead><tbody>${tsRow("time-series", r.ts_bench_events)}${tsRow("regular", r.ts_bench_plain)}</tbody></table></div>
          <div class="stat-line"><div><b>${r.storage_saving_pct}%</b><span>less disk + index space</span></div></div></section>` : ""}`;
      },

      analytics: () => {
        const r = R().analytics;
        const b = r?.latest_bucket;
        return `<section class="panel panel-pad"><div class="row" style="justify-content:space-between"><div><h2 style="margin:0">Pre-aggregated buckets + raw data</h2><p class="muted" style="margin:4px 0 0">Each new report <span class="mono">$inc</span>s its day in <span class="mono">report_stats_daily</span> (${num(c().report_stats_daily)} buckets). The Overview chart reads these; raw reports stay for drill-down.</p></div><div class="row">${runOne("analytics", "Compare raw vs buckets")}<button class="btn small" id="rebuild">Rebuild from raw</button></div></div></section>
        ${r && r.ok ? `<section class="panel" style="margin-top:18px"><div class="stat-line" style="border-top:none"><div><b>${r.raw_ms} ms</b><span>raw: group ${num(r.raw_reports_scanned)} reports</span></div><div><b>${r.bucket_ms} ms</b><span>buckets: read ${num(r.bucket_docs_read)} docs</span></div><div><b>${r.speedup ?? "n/a"}x</b><span>faster</span></div><div><b>${r.totals_match ? "yes" : "no"}</b><span>totals match (${num(r.bucket_total)})</span></div></div></section>` : ""}
        ${b ? `<section class="panel panel-pad" style="margin-top:18px"><h3 style="margin-top:0">Latest bucket</h3><pre class="mono" style="font-size:12px;overflow-x:auto;margin:0">${esc(JSON.stringify(b, null, 2))}</pre></section>` : ""}`;
      },

      sync: () => {
        const r = R().sync;
        const s = sync.store;
        return `<section class="panel panel-pad"><h2 style="margin:0">Change streams for sync, embedded local data</h2><p class="muted" style="margin:4px 0 0">This browser keeps the newest reports and a resume token. After being offline it reconnects with the token and receives only what it missed.</p>
          <div class="stat-line" style="margin-top:14px"><div><b>${sync.connected ? "online" : "offline"}</b><span>connection</span></div><div><b>${esc(sync.mode === "change_stream" ? "change stream" : sync.mode ? "polling" : "n/a")}</b><span>server mode</span></div><div><b>${num(s.items.length)}</b><span>reports stored locally</span></div><div><b>${s.updated_at ? ago(s.updated_at) : "never"}</b><span>last new report</span></div></div>
          <p class="mono faint" style="font-size:12px;overflow-wrap:anywhere;margin:12px 0 0">resume token: ${esc(s.token || "none yet")}</p></section>
        ${!c().replica_set ? `<div class="callout" style="margin-top:18px">MongoDB is running standalone, so the server syncs by polling. Change streams need a replica set; enable a one-node replica set (see <span class="mono">labs/use_cases/USE_CASES.md</span>, section 6):${copyCmd(`mongosh --eval 'rs.initiate({_id: "rs0", members: [{_id: 0, host: "localhost:27017"}]})'`)}</div>` : ""}
        ${r && r.ok && r.replica_set ? `<div class="callout" style="margin-top:18px">Resume test: first event after ${r.first_event_latency_ms} ms; after reconnecting with the saved token it received ${r.resumed_events.length} missed report(s): ${esc(r.resumed_events.join(", "))}.</div>` : ""}
        <section class="panel" style="margin-top:18px"><div class="panel-head"><h2>Stored on this device</h2><div class="row">${copyCmd("python labs/use_cases/watch_reports.py --demo")}<button class="btn small" id="clearsync">Clear local copy</button></div></div>
          ${s.items.length ? `<div class="scroll-x"><table class="table"><tbody>${s.items.map((x) => `<tr><td class="nowrap faint">${fmtTime(x.published_at)}</td><td>${sevTag(x.severity)}</td><td>${verdictTag(x.verdict)}</td><td>${x.url && !x.url.startsWith("urn:") ? `<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.title)}</a>` : esc(x.title)}</td></tr>`).join("")}</tbody></table></div>`
          : `<div class="empty"><strong>Nothing received yet</strong>New reports appear here as soon as they are inserted. Run the watcher demo above or click Update now on the Sources page.</div>`}</section>`;
      },
    };

    async function after(t) {
      if (t === "content") {
        const b = await api("/api/briefings/latest").catch((e) => ({ error: e.message }));
        drawBriefing(b);
        $("#rebrief")?.addEventListener("click", async (e) => {
          e.target.disabled = true;
          drawBriefing(await api("/api/briefings/latest?rebuild=true").catch((err) => ({ error: err.message })));
          e.target.disabled = false;
          toast("Briefing rebuilt (version incremented).");
        });
      }
      if (t === "profiles") drawProfile(await api("/api/profile").catch((e) => ({ error: e.message })));
      if (t === "analytics") $("#rebuild")?.addEventListener("click", async (e) => {
        e.target.disabled = true;
        const r = await api("/api/analytics/rebuild", { method: "POST" }).catch((err) => ({ error: err.message }));
        toast(r.error ? esc(r.error) : `Rebuilt ${num(r.buckets)} daily buckets in ${r.seconds} s.`);
        st = await api("/api/usecases");
        draw("analytics");
      });
      if (t === "sync") $("#clearsync")?.addEventListener("click", () => { sync.store.items = []; saveSync(); draw("sync"); });
      $$("[data-run]", page).forEach((btn) => btn.addEventListener("click", async () => {
        const label = btn.textContent;
        btn.disabled = true;
        btn.innerHTML = `<span class="spin"></span> Running`;
        try {
          await api("/api/usecases/run", { method: "POST", body: { only: [btn.dataset.run], ...JSON.parse(btn.dataset.extra || "{}") } });
          st = await api("/api/usecases");
          draw(t);
          toast("Done.");
        } catch (err) { toast(esc(err.message)); btn.disabled = false; btn.textContent = label; }
      }));
    }

    function drawBriefing(b) {
      const box = $("#brief");
      if (!box) return;
      if (!b || b.error) { box.innerHTML = `<p class="muted">${esc(b?.error || "No briefing yet")}</p>`; return; }
      const blk = (x) => {
        switch (x.type) {
          case "heading": return `<h2 style="margin:0 0 8px">${esc(x.text)}</h2>`;
          case "summary": return `<p style="margin:0 0 14px">${esc(x.text)}</p>`;
          case "report_list": return `<h3>${esc(x.title)}</h3><div class="mini-list">${x.items.map((i) => `<div style="margin-bottom:6px">${sevTag(i.severity)} <a href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.title)}</a></div>`).join("")}</div>`;
          case "cve_table": return `<h3>${esc(x.title)}</h3><table class="table"><tbody>${x.rows.map((r) => `<tr><td class="mono"><a href="#/threats?q=${esc(r.cve)}">${esc(r.cve)}</a></td><td class="num">${r.mentions}</td><td>${r.kev ? `<span class="verdict-tag v-actual">KEV</span>` : ""}</td></tr>`).join("")}</tbody></table>`;
          case "actor_callout": return `<h3>${esc(x.title)}</h3><div class="chips">${x.actors.map((a) => `<span class="chip">${esc(a.name)} (${a.mentions})</span>`).join("")}</div>`;
          case "ioc_list": return `<h3>${esc(x.title)}</h3><div class="chips">${x.indicator_ids.map((i) => `<span class="chip ioc">${esc(i)}</span>`).join("")}</div>`;
          case "note": return `<div class="callout" style="margin-top:14px">${esc(x.text)}</div>`;
          default: return `<pre class="mono">${esc(JSON.stringify(x))}</pre>`;
        }
      };
      box.innerHTML = `<p class="faint" style="margin:0 0 10px;font-size:12.5px">${esc(b._id)}, version ${b.version}, updated ${fmtTime(b.updated_at)}</p>${b.blocks.map(blk).join("")}`;
      const shape = { _id: b._id, version: b.version, author_id: b.author_id, blocks: b.blocks.map((x) => {
        const o = {};
        Object.entries(x).forEach(([k, v]) => { o[k] = Array.isArray(v) ? `[ ${v.length} item(s) ]` : typeof v === "string" && v.length > 40 ? v.slice(0, 40) + "..." : v; });
        return o;
      }) };
      $("#briefjson").textContent = JSON.stringify(shape, null, 2);
    }

    function drawProfile(p) {
      const box = $("#prof");
      if (!box) return;
      if (p.error) { box.innerHTML = `<p class="muted">${esc(p.error)}</p>`; return; }
      const pr = p.preferences || {};
      const wl = pr.watchlist || {};
      box.innerHTML = `<h3 style="margin-top:0">${esc(p.name)} <span class="faint" style="font-weight:400">(${esc(p.role)})</span></h3>
        <dl class="kv"><dt>Minimum severity</dt><dd><select id="pf-sev">${["Low", "Medium", "High", "Critical"].map((s) => `<option ${s === pr.min_severity ? "selected" : ""}>${s}</option>`).join("")}</select></dd>
        <dt>Default period</dt><dd><input id="pf-days" type="number" min="1" max="365" value="${pr.default_days || 30}" style="width:80px"> days</dd>
        <dt>Notify on actual threats</dt><dd><input id="pf-notify" type="checkbox" ${pr.notify_actual_threats ? "checked" : ""}></dd>
        <dt>Watchlist IPs</dt><dd><input id="pf-ips" value="${esc((wl.ips || []).join(", "))}" placeholder="1.2.3.4, 5.6.7.8" style="width:100%"></dd>
        <dt>Watchlist CVEs</dt><dd><input id="pf-cves" value="${esc((wl.cves || []).join(", "))}" placeholder="CVE-2024-3400" style="width:100%"></dd></dl>
        <div class="row" style="margin-top:14px"><button class="btn small primary" id="pf-save">Save preferences</button><span class="faint" style="font-size:12.5px">one $set on the embedded sub-document</span></div>`;
      const split = (v) => v.split(/[\s,]+/).filter(Boolean);
      $("#pf-save").addEventListener("click", async () => {
        const body = { min_severity: $("#pf-sev").value, default_days: parseInt($("#pf-days").value, 10) || 30, notify_actual_threats: $("#pf-notify").checked,
          watchlist: { ips: split($("#pf-ips").value), cves: split($("#pf-cves").value) } };
        try { drawProfile(await api("/api/profile/preferences", { method: "PUT", body })); toast("Preferences saved."); } catch (err) { toast(esc(err.message)); }
      });
      $("#activity").innerHTML = `<div class="panel-head"><h2>Activity history</h2><span class="muted">${num(p.activity_total)} lookups, referenced</span></div>
        ${p.activity.length ? `<div class="scroll-x"><table class="table"><tbody>${p.activity.map((a) => `<tr><td class="mono"><a href="#/ip/${encodeURIComponent(a.ip)}">${esc(a.ip)}</a></td><td>${esc(a.verdict)}</td><td class="num">${a.score}</td><td class="faint nowrap">${ago(a.at)}</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="empty"><strong>No lookups yet</strong>Check an IP on the <a href="#/ip">IP intelligence</a> page.</div>`}`;
    }

    function draw(t) {
      if (!bodies[t]) t = "table";
      tab = t;
      $$("[data-tab]", page).forEach((b) => b.classList.toggle("active", b.dataset.tab === t));
      $("#tabbody").innerHTML = bodies[t]();
      history.replaceState(null, "", `#/usecases?tab=${t}`);
      after(t);
    }
    $$("[data-tab]", page).forEach((b) => b.addEventListener("click", () => draw(b.dataset.tab)));
    $("#ucrun").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      btn.innerHTML = `<span class="spin"></span> Running all six`;
      try { await api("/api/usecases/run", { method: "POST", body: {} }); st = await api("/api/usecases"); draw(tab); toast("All six use cases ran."); }
      catch (err) { toast(esc(err.message)); }
      btn.disabled = false;
      btn.textContent = "Run all six demos";
    });
    const onSync = () => { if (tab === "sync") draw("sync"); };
    window.addEventListener("kavach-sync", onSync);
    onLeave(() => window.removeEventListener("kavach-sync", onSync));
    draw(tab);
  }

  // ------------------------------------------------------------------ boot
  (async () => {
    const h = await checkHealth();
    render();
    syncState();
    if (h.mongodb) startSync();
  })();
})();
