const SEV_COLOR = {
  emerg: "#ff3b5c",
  alert: "#ff5d73",
  crit: "#ff7a59",
  err: "#f3b23c",
  warning: "#ffe08a",
  notice: "#c4b5fd",
  info: "#79b4ff",
  debug: "#6b7787",
};

const state = {
  report: null,
  since: "24h",
  query: "",
  app: "",
  sort: "impact",
  severities: new Set(["emerg", "alert", "crit", "err", "warning"]),
  selected: null,
  ai: { configured: false, provider: null, signup: {} },
  tips: {},
  tab: "journal",
  bootOnly: false,
  live: null,
  disk: null,
  diskRoot: "",
  diskFocus: [],
  diskSelected: "",
  diskInspect: null,
  diskView: "rings",
  diskOpen: new Set(),
  units: null,
  unitQuery: "",
  unitState: "all",
  unitSelected: null,
  unitLogs: null,
  unitTips: {},
  machine: null,
  machineTips: null,
  hostId: "local",
  hostsLocal: null,
  hosts: [],
  hostFilter: "",
};

const HOST_STORAGE = "healthd-host";
const HOST_STORAGE_LEGACY = "journalctl-obs-host";

const AI_SIGNUP = {
  groq: "https://console.groq.com/keys",
  gemini: "https://aistudio.google.com/apikey",
  openrouter: "https://openrouter.ai/keys",
};

const $ = (id) => document.getElementById(id);

function apiUrl(path) {
  const id = state.hostId || "local";
  if (!path.startsWith("/api/") || id === "local") return path;
  if (
    path.startsWith("/api/hosts")
    || path.startsWith("/api/login")
    || path.startsWith("/api/logout")
    || path.startsWith("/api/session")
  ) return path;
  return `/api/remote/${encodeURIComponent(id)}/${path.slice(5)}`;
}

function api(path, options) {
  return fetch(apiUrl(path), { credentials: "same-origin", ...options }).then((res) => {
    if (res.status === 401 && path !== "/api/login" && path !== "/api/session") {
      window.location.replace("/login");
    }
    return res;
  });
}

function fmtNum(n) {
  return new Intl.NumberFormat("pt-BR").format(n);
}

function fmtPct(n) {
  const v = Number(n);
  if (v > 0 && v < 0.1) return "<0,1%";
  return `${v.toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("pt-BR", { hour12: false });
}

function relative(iso) {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const min = Math.round(diff / 60000);
  if (min < 1) return "agora";
  if (min < 60) return `${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} h`;
  return `${Math.round(h / 24)} d`;
}

function fmtBytes(n) {
  const sign = n < 0 ? "-" : "";
  let v = Math.abs(Number(n) || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 || v >= 10 ? 0 : 1;
  return `${sign}${v.toLocaleString("pt-BR", { maximumFractionDigits: digits })} ${units[i]}`;
}

function fmtRate(n) {
  return `${fmtBytes(n)}/s`;
}

function kpiTone(ok, warn) {
  if (ok) return "";
  if (warn) return "is-warn";
  return "is-bad";
}

function lampOf(ok, warn) {
  if (ok) return "ok";
  if (warn) return "warn";
  return "bad";
}

function allHosts() {
  const local = state.hostsLocal || {
    id: "local",
    name: "esta máquina",
    address: "esta máquina",
    kind: "local",
    online: true,
  };
  return [local, ...(state.hosts || [])];
}

function currentHost() {
  return allHosts().find((h) => h.id === state.hostId) || allHosts()[0];
}

function persistHost(id) {
  try {
    localStorage.setItem(HOST_STORAGE, id);
    localStorage.removeItem(HOST_STORAGE_LEGACY);
  } catch { /* ignore */ }
}

function savedHostId() {
  try {
    return localStorage.getItem(HOST_STORAGE) || localStorage.getItem(HOST_STORAGE_LEGACY) || "local";
  } catch { return "local"; }
}

function closeHostMenu() {
  const menu = $("hostMenu");
  const btn = $("hostCurrent");
  if (menu) menu.hidden = true;
  if (btn) btn.setAttribute("aria-expanded", "false");
}

function resetHostData() {
  state.report = null;
  state.live = null;
  state.disk = null;
  state.diskRoot = "";
  state.diskFocus = [];
  state.diskSelected = "";
  state.diskInspect = null;
  state.diskOpen = new Set();
  state.units = null;
  state.unitSelected = null;
  state.unitLogs = null;
  state.unitTips = {};
  state.machine = null;
  state.machineTips = null;
  state.tips = {};
  state.selected = null;
  state.ai = { configured: false, provider: null, signup: AI_SIGNUP };
  if ($("drawer")) $("drawer").hidden = true;
  if ($("banner")) $("banner").hidden = true;
}

function reloadActiveView() {
  if (state.tab === "live") {
    loadLive();
  } else if (state.tab === "disk") {
    loadDisk(true);
  } else if (state.tab === "services") {
    loadUnits();
  } else if (state.tab === "machine") {
    loadMachine(true);
  } else {
    loadReport();
  }
}

function selectHost(id) {
  const next = allHosts().some((h) => h.id === id) ? id : "local";
  closeHostMenu();
  if (next === state.hostId) {
    paintHostBar();
    return;
  }
  state.hostId = next;
  persistHost(next);
  paintHostBar();
  resetHostData();
  loadAiStatus();
  reloadActiveView();
}

function paintHostBar() {
  const bar = $("hostBar");
  if (!bar) return;
  const remotes = state.hosts || [];
  bar.classList.toggle("is-multi", remotes.length > 0);
  const host = currentHost();
  const online = host.kind === "local" || host.online;
  $("hostName").textContent = host.name || host.address || "host";
  $("hostAddr").textContent = host.kind === "local"
    ? (host.listen ? `esta máquina · ${host.listen}` : "esta máquina")
    : host.address || "";
  $("hostLamp").className = `lamp ${online ? "ok" : "bad"}`;
  document.title = `healthD · ${host.name || "painel"}`;
  const filter = $("hostFilter");
  if (filter) filter.parentElement.hidden = remotes.length === 0;
  renderHostList();
  renderHostManageList();
}

function renderHostList() {
  const box = $("hostList");
  if (!box) return;
  const q = (state.hostFilter || "").trim().toLowerCase();
  const rows = allHosts().filter((h) => {
    if (!q) return true;
    return String(h.name || "").toLowerCase().includes(q)
      || String(h.address || "").toLowerCase().includes(q);
  });
  if (!rows.length) {
    box.innerHTML = `<p class="empty">Nenhum host com esse nome.</p>`;
    return;
  }
  box.innerHTML = rows.map((h) => {
    const online = h.kind === "local" || h.online;
    const status = h.kind === "local" ? "local" : (online ? "online" : "offline");
    return `
      <button type="button" class="hostbar__item ${h.id === state.hostId ? "is-on" : ""} ${online ? "" : "is-offline"}" data-host="${escapeAttr(h.id)}" role="option">
        <span class="lamp ${online ? "ok" : "bad"}"></span>
        <span>
          <b>${escapeHtml(h.name || h.address)}</b>
          <small>${escapeHtml(h.kind === "local" ? "esta máquina" : (h.address || ""))}</small>
        </span>
        <em>${escapeHtml(status)}</em>
      </button>
    `;
  }).join("");
}

function renderHostManageList() {
  const box = $("hostRemoteList");
  if (!box) return;
  const rows = state.hosts || [];
  if (!rows.length) {
    box.innerHTML = `<p class="empty">Nenhum remoto ainda. Adicione ip:porta abaixo.</p>`;
    return;
  }
  box.innerHTML = rows.map((h) => `
    <article class="host-manage-row" data-host-row="${escapeAttr(h.id)}">
      <div>
        <b>${escapeHtml(h.name)}</b>
        <small>${escapeHtml(h.address)}${h.username ? ` · user ${h.username}` : ""} · ${h.online ? "online" : (h.error || "offline")}${h.version ? ` · v${h.version}` : ""}</small>
      </div>
      <div class="host-manage-actions">
        <button type="button" class="ghost" data-host-rename="${escapeAttr(h.id)}">Renomear</button>
        <button type="button" class="ghost btn-disable" data-host-remove="${escapeAttr(h.id)}">Remover</button>
      </div>
    </article>
  `).join("");
}

async function loadHosts(probe = false) {
  try {
    const res = await api(`/api/hosts${probe ? "?probe=1" : ""}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    state.hostsLocal = payload.local;
    state.hosts = payload.hosts || [];
    const saved = savedHostId();
    if (!allHosts().some((h) => h.id === state.hostId)) {
      state.hostId = allHosts().some((h) => h.id === saved) ? saved : "local";
    } else if (state.hostId === "local" && saved !== "local" && allHosts().some((h) => h.id === saved) && !state.report) {
      state.hostId = saved;
    }
    paintHostBar();
  } catch {
    state.hostsLocal = state.hostsLocal || { id: "local", name: "esta máquina", kind: "local", online: true };
    paintHostBar();
  }
}

function openHostModal() {
  closeHostMenu();
  const local = state.hostsLocal || {};
  $("hostLocalName").value = local.name || "";
  $("hostNewName").value = "";
  $("hostNewAddr").value = "";
  $("hostNewUser").value = "";
  $("hostNewPass").value = "";
  $("hostModalHint").textContent = local.listen
    ? `Este painel escuta em ${local.listen}. No remoto: usuário Linux do grupo healthd.`
    : "Nome, ip:porta, usuário e senha do Linux remoto (grupo healthd).";
  renderHostManageList();
  $("hostModal").hidden = false;
  $("hostNewName").focus();
}

async function addRemoteHost() {
  const name = $("hostNewName").value.trim();
  const address = $("hostNewAddr").value.trim();
  const username = $("hostNewUser").value.trim();
  const password = $("hostNewPass").value;
  const hint = $("hostModalHint");
  if (!name || !address || !username || !password) {
    hint.textContent = "Preencha nome, ip:porta, usuário e senha do host remoto.";
    return;
  }
  hint.textContent = "Testando o host…";
  try {
    const res = await api("/api/hosts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, address, username, password }),
    });
    const payload = await res.json();
    if (!res.ok || payload.error) {
      hint.textContent = payload.message || "Não foi possível adicionar.";
      return;
    }
    state.hostsLocal = payload.local;
    state.hosts = payload.hosts || [];
    $("hostNewName").value = "";
    $("hostNewAddr").value = "";
    $("hostNewUser").value = "";
    $("hostNewPass").value = "";
    hint.textContent = payload.warning
      ? payload.warning
      : "Host adicionado. O login remoto precisa ser um usuário do grupo healthd.";
    paintHostBar();
  } catch (err) {
    hint.textContent = err.message;
  }
}

async function renameHost(id, name) {
    const res = await api("/api/hosts/rename", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, name }),
  });
  const payload = await res.json();
  if (!res.ok || payload.error) {
    window.alert(payload.message || "Não foi possível renomear.");
    return;
  }
  state.hostsLocal = payload.local;
  state.hosts = payload.hosts || [];
  paintHostBar();
}

async function removeHost(id) {
  if (!window.confirm("Remover este host da lista? O agente na máquina remota continua rodando.")) return;
    const res = await api("/api/hosts/remove", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
  const payload = await res.json();
  if (!res.ok || payload.error) {
    window.alert(payload.message || "Não foi possível remover.");
    return;
  }
  state.hostsLocal = payload.local;
  state.hosts = payload.hosts || [];
  if (state.hostId === id) selectHost("local");
  else paintHostBar();
}

let reportSeq = 0;

async function loadReport(silent = false) {
  const seq = ++reportSeq;
  if (!silent) {
    $("loadingText").textContent = "Lendo o journal…";
    $("loading").hidden = false;
  }
  try {
    const res = await api(`/api/report?since=${encodeURIComponent(state.since)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (seq !== reportSeq) return;
    state.report = payload;
    render();
  } catch (err) {
    if (seq !== reportSeq) return;
    $("banner").hidden = false;
    $("banner").textContent = `Não foi possível ler o journal: ${err.message}`;
  } finally {
    if (seq === reportSeq) $("loading").hidden = true;
  }
}

function render() {
  const r = state.report;
  if (!r) return;
  $("kicker").textContent = `Relatório operacional · ${r.since_label}`;
  $("clock").textContent = fmtTime(r.generated_at);
  $("sourceMeta").textContent = `${r.source} · ${fmtNum(r.stats.total)} eventos · v${r.version}`;
  if (r.warning) {
    $("banner").hidden = false;
    $("banner").textContent = r.warning;
  } else {
    $("banner").hidden = true;
  }
  renderBeacons(r.beacons);
  renderKpis(r);
  renderTimeline(r.timeline);
  renderSeverity(r.severity);
  renderBars("appsChart", r.apps.map((a) => ({
    name: a.app,
    value: a.impact,
    extra: a.count,
    state: a.state,
    openIdent: a.app,
    openUnit: `${a.app}.service`,
  })));
  renderBars("unitsChart", r.units.slice(0, 8).map((u) => ({
    name: u.unit.replace(".service", ""),
    value: u.impact,
    extra: u.count,
    state: u.state,
    openUnit: u.unit,
  })));
  fillAppFilter(r.apps);
  renderSevFilters(r.severity);
  renderFailedUnits(r.failed_units || []);
  renderBootNew(r.boot_diff || {});
  renderIssues();
}

function renderBeacons(beacons) {
  $("beacons").innerHTML = beacons.map((b) => `
    <article class="beacon">
      <span class="lamp ${b.state}"></span>
      <div>
        <b>${b.label}</b>
        <small>${b.hint}</small>
      </div>
      <em>${b.id === "health" ? b.value : fmtNum(b.value)}</em>
    </article>
  `).join("");
}

function renderKpis(r) {
  const s = r.stats;
  const healthClass = s.health >= 88 ? "" : s.health >= 70 ? "is-warn" : "is-bad";
  const bootClass = (s.new_this_boot || 0) > 8 ? "is-bad" : (s.new_this_boot || 0) > 2 ? "is-warn" : "";
  const failClass = (s.failed_units || 0) ? "is-bad" : "";
  const oomClass = (s.oom || 0) ? "is-bad" : "";
  $("kpis").innerHTML = `
    <article class="kpi kpi--health ${healthClass}">
      <span>Saúde estimada</span>
      <strong>${s.health}</strong>
      <small>${s.health_label}</small>
    </article>
    <article class="kpi kpi--gain">
      <span>Melhoria potencial</span>
      <strong>${fmtPct(s.improvement_potential)}</strong>
      <small>se os erros de maior impacto forem corrigidos</small>
    </article>
    <article class="kpi">
      <span>Erros</span>
      <strong>${fmtNum(s.errors)}</strong>
      <small>${fmtNum(s.errors_15m || 0)} nos últimos 15 min</small>
    </article>
    <article class="kpi kpi--health ${bootClass}">
      <span>Novo neste boot</span>
      <strong>${fmtNum(s.new_this_boot || 0)}</strong>
      <small>${(r.boot_diff || {}).has_previous ? "não estavam no boot anterior" : "visto desde o boot"}</small>
    </article>
    <article class="kpi kpi--health ${failClass}">
      <span>Unidades falhas</span>
      <strong>${fmtNum(s.failed_units || 0)}</strong>
      <small>systemd --failed e restart loop</small>
    </article>
    <article class="kpi kpi--health ${oomClass}">
      <span>OOM</span>
      <strong>${fmtNum(s.oom || 0)}</strong>
      <small>processos mortos por memória</small>
    </article>
  `;
}

function renderTimeline(points) {
  const el = $("timelineChart");
  if (!points.length) {
    el.innerHTML = `<p class="empty">Sem pontos no período.</p>`;
    return;
  }
  const keys = ["emerg", "alert", "crit", "err", "warning"];
  const w = 900;
  const h = 200;
  const pad = { l: 28, r: 12, t: 16, b: 28 };
  const totals = points.map((p) => keys.reduce((acc, k) => acc + (p.counts[k] || 0), 0));
  const max = Math.max(1, ...totals);
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;
  const gap = innerW / points.length;
  let bars = "";
  points.forEach((p, i) => {
    let y = pad.t + innerH;
    keys.forEach((k) => {
      const v = p.counts[k] || 0;
      if (!v) return;
      const bh = (v / max) * innerH;
      y -= bh;
      bars += `<rect x="${pad.l + i * gap + 1}" y="${y}" width="${Math.max(gap - 2, 1)}" height="${bh}" fill="${SEV_COLOR[k]}" rx="1">
        <title>${fmtTime(p.t)} · ${k}: ${v}</title>
      </rect>`;
    });
  });
  const first = fmtTime(points[0].t);
  const last = fmtTime(points[points.length - 1].t);
  el.innerHTML = `
    <svg class="chart-svg" viewBox="0 0 ${w} ${h}" role="img" aria-label="Linha do tempo de erros">
      <line x1="${pad.l}" y1="${pad.t + innerH}" x2="${w - pad.r}" y2="${pad.t + innerH}" stroke="rgba(231,238,247,.12)"/>
      ${bars}
      <text x="${pad.l}" y="${h - 8}" fill="#8d9aab" font-size="11">${first}</text>
      <text x="${w - pad.r}" y="${h - 8}" fill="#8d9aab" font-size="11" text-anchor="end">${last}</text>
    </svg>
    <div class="legend">
      ${keys.map((k) => `<span><i style="background:${SEV_COLOR[k]}"></i>${k}</span>`).join("")}
    </div>
  `;
}

function renderSeverity(rows) {
  const el = $("severityChart");
  const total = rows.reduce((a, b) => a + b.count, 0) || 1;
  const cx = 120;
  const cy = 120;
  const r = 74;
  const stroke = 22;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const arcs = rows.filter((x) => x.count).map((row) => {
    const len = (row.count / total) * c;
    const arc = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${SEV_COLOR[row.id]}" stroke-width="${stroke}"
      stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})">
      <title>${row.label}: ${row.count} (${row.pct}%)</title>
    </circle>`;
    offset += len;
    return arc;
  }).join("");
  el.innerHTML = `
    <svg class="chart-svg" viewBox="0 0 360 250" role="img" aria-label="Distribuição por severidade">
      ${arcs || `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1c2430" stroke-width="${stroke}"/>`}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="#e8eef6" font-size="22" font-family="IBM Plex Mono">${fmtNum(total)}</text>
      <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="#8d9aab" font-size="11">eventos</text>
      ${rows.filter((x) => x.count).slice(0, 6).map((row, i) => `
        <rect x="230" y="${28 + i * 28}" width="8" height="8" rx="4" fill="${SEV_COLOR[row.id]}"/>
        <text x="246" y="${36 + i * 28}" fill="#e8eef6" font-size="12">${row.label}</text>
        <text x="340" y="${36 + i * 28}" fill="#8d9aab" font-size="12" text-anchor="end">${row.pct}%</text>
      `).join("")}
    </svg>
  `;
}

function renderBars(id, rows) {
  const el = $(id);
  if (!rows.length) {
    el.innerHTML = `<p class="empty">Sem dados.</p>`;
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.value));
  el.innerHTML = rows.map((row) => {
    const clickable = row.openUnit || row.openIdent ? "is-clickable" : "";
    const openUnit = row.openUnit ? `data-open-unit="${escapeAttr(row.openUnit)}"` : "";
    const openIdent = row.openIdent ? `data-open-ident="${escapeAttr(row.openIdent)}"` : "";
    return `
    <div class="bar ${row.state || ""} ${clickable}" ${openUnit} ${openIdent}>
      <b title="${escapeAttr(row.name)}">${escapeHtml(row.name)}</b>
      <i><em style="width:${Math.max(4, (row.value / max) * 100)}%"></em></i>
      <span>${fmtNum(row.extra)}</span>
    </div>
  `;
  }).join("");
}

function fillAppFilter(apps) {
  const select = $("appFilter");
  const current = state.app;
  const opts = [`<option value="">Todas as apps</option>`]
    .concat(apps.map((a) => `<option value="${escapeAttr(a.app)}">${escapeHtml(a.app)}</option>`));
  select.innerHTML = opts.join("");
  select.value = current;
}

function renderSevFilters(rows) {
  $("sevFilters").innerHTML = rows.map((row) => {
    const on = state.severities.size === 0 || state.severities.has(row.id);
    return `<button type="button" data-sev="${row.id}" class="${on ? "is-on" : ""}">${row.label} ${fmtNum(row.count)}</button>`;
  }).join("");
}

function filteredIssues() {
  const r = state.report;
  let rows = r.issues.slice();
  const q = state.query.trim().toLowerCase();
  if (q) {
    rows = rows.filter((i) =>
      `${i.title} ${i.sample} ${i.app} ${i.unit}`.toLowerCase().includes(q)
    );
  }
  if (state.app) rows = rows.filter((i) => i.app === state.app);
  if (state.severities.size) rows = rows.filter((i) => state.severities.has(i.severity));
  if (state.bootOnly) rows = rows.filter((i) => i.boot_status === "new" || i.boot_status === "this_boot");
  const sorters = {
    impact: (a, b) => b.impact - a.impact,
    count: (a, b) => b.count - a.count,
    improvement: (a, b) => b.improvement_pct - a.improvement_pct,
    recent: (a, b) => new Date(b.last_seen) - new Date(a.last_seen),
    boot: (a, b) => Number(b.boot_status === "new") - Number(a.boot_status === "new") || b.impact - a.impact,
  };
  rows.sort(sorters[state.sort] || sorters.impact);
  return rows;
}

function renderIssues() {
  const rows = filteredIssues();
  $("emptyIssues").hidden = rows.length > 0;
  const maxImpact = Math.max(1, ...rows.map((r) => r.impact));
  $("issueBody").innerHTML = rows.map((row) => `
    <tr data-id="${row.id}" role="button" tabindex="0">
      <td><span class="dot" style="color:${SEV_COLOR[row.severity]}" title="${row.severity_label}"></span></td>
      <td>
        <span class="msg">
          ${escapeHtml(row.title)}
          <small>${escapeHtml(row.tags.join(" · ") || row.severity_label)}${row.boot_status === "new" ? " · novo neste boot" : ""}</small>
        </span>
      </td>
      <td>${escapeHtml(row.app)}<small class="msg"><small>${escapeHtml(row.unit)}</small></small></td>
      <td class="mono">${fmtNum(row.count)}</td>
      <td class="mono">${fmtPct(row.pct)}</td>
      <td>
        <div class="impact"><b style="width:${(row.impact / maxImpact) * 100}%; background:${impactColor(row.impact_label)}"></b></div>
        <small>${row.impact_label}</small>
      </td>
      <td class="mono">${row.improvement_pct ? fmtPct(row.improvement_pct) : "—"}</td>
      <td class="mono">${relative(row.last_seen)}</td>
      <td><span class="boot-tag ${row.boot_status || ""}">${escapeHtml(row.boot_label || "—")}</span></td>
      <td>
        <button type="button" class="btn-ai" data-tips="${row.id}">IA Tips</button>
      </td>
    </tr>
  `).join("");
}

function renderFailedUnits(rows) {
  const el = $("failedUnits");
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<p class="empty">Nenhuma unidade falha ou em restart loop.</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table">
      <thead><tr><th>Unidade</th><th>Estado</th><th>Restarts</th><th>Resultado</th></tr></thead>
      <tbody>
        ${rows.map((row) => `
          <tr data-unit="${escapeAttr(row.unit)}">
            <td><span class="folder-name">${escapeHtml(row.unit)}<small>${escapeHtml(row.description || "")}</small></span></td>
            <td class="mono">${escapeHtml(row.sub || row.active || "failed")}</td>
            <td class="mono">${fmtNum(row.restarts || 0)}</td>
            <td class="mono">${escapeHtml(row.result || "—")}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderBootNew(diff) {
  const el = $("bootNew");
  if (!el) return;
  const rows = diff.new || [];
  if (!rows.length) {
    el.innerHTML = `<p class="empty">${diff.has_previous ? "Nada novo em relação ao boot anterior." : "Sem journal do boot anterior para comparar."}</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table">
      <thead><tr><th>Problema</th><th>App</th><th>Vezes</th></tr></thead>
      <tbody>
        ${rows.map((row) => `
          <tr ${row.id ? `data-id="${row.id}"` : ""}>
            <td>${escapeHtml(row.title)}</td>
            <td>${escapeHtml(row.app || "")}</td>
            <td class="mono">${fmtNum(row.count || 0)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

const UNIT_BUCKET_LABEL = {
  running: "running",
  stopped: "stopped",
  failed: "failed",
  active: "exited",
  starting: "starting",
  other: "outro",
};

let unitSeq = 0;
let unitLogSeq = 0;
let unitTipSeq = 0;
let unitTimer = 0;

function unitKey(sel) {
  if (!sel) return "";
  return sel.unit ? `u:${sel.unit}` : `i:${sel.ident || ""}`;
}

function resolveUnitOpen(unit, ident) {
  const units = state.units?.units || [];
  const cleanUnit = (unit || "").trim();
  const cleanIdent = (ident || "").trim();
  if (cleanIdent === "kernel" || cleanUnit === "kernel") {
    return { unit: "", ident: "kernel" };
  }
  if (cleanUnit && units.some((row) => row.unit === cleanUnit)) {
    return { unit: cleanUnit, ident: "" };
  }
  if (cleanIdent) {
    const hit = units.find((row) =>
      row.unit === `${cleanIdent}.service` || row.unit.replace(/\.service$/, "") === cleanIdent
    );
    if (hit) return { unit: hit.unit, ident: "" };
  }
  if (cleanUnit && cleanUnit.includes(".")) return { unit: cleanUnit, ident: "" };
  return { unit: cleanUnit, ident: cleanIdent };
}

function filteredUnits() {
  const rows = state.units?.units || [];
  const q = state.unitQuery.trim().toLowerCase();
  return rows.filter((row) => {
    if (state.unitState !== "all" && row.bucket !== state.unitState) return false;
    if (!q) return true;
    return `${row.unit} ${row.description} ${row.sub}`.toLowerCase().includes(q);
  });
}

function renderUnitFilters() {
  const el = $("unitStateFilter");
  if (!el) return;
  const counts = state.units?.counts || {};
  const total = state.units?.total || 0;
  const labels = [
    ["all", "Todos", total],
    ["running", "Running", counts.running || 0],
    ["stopped", "Stopped", counts.stopped || 0],
    ["failed", "Failed", counts.failed || 0],
    ["active", "Ativo (exited)", counts.active || 0],
  ];
  el.innerHTML = labels.map(([id, label, n]) => `
    <button type="button" data-unit-state="${id}" class="${state.unitState === id ? "is-on" : ""}">${label} ${fmtNum(n)}</button>
  `).join("");
}

function renderUnitList() {
  const el = $("unitList");
  if (!el) return;
  if (!state.units) {
    el.innerHTML = `<p class="empty">Lendo systemctl…</p>`;
    return;
  }
  const rows = filteredUnits();
  const selected = unitKey(state.unitSelected);
  if (!rows.length) {
    el.innerHTML = `<p class="empty">Nenhum serviço com esse filtro.</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table">
      <thead><tr><th>Unidade</th><th>Estado</th></tr></thead>
      <tbody>
        ${rows.map((row) => {
          const key = unitKey({ unit: row.unit, ident: "" });
          return `
          <tr data-unit="${escapeAttr(row.unit)}" class="${selected === key ? "is-on" : ""}">
            <td>
              <span class="folder-name">${escapeHtml(row.unit.replace(/\.service$/, ""))}
                <small>${escapeHtml(row.description || row.unit)}</small>
              </span>
            </td>
            <td><span class="state-pill ${row.bucket}">${escapeHtml(UNIT_BUCKET_LABEL[row.bucket] || row.sub || row.active)}</span></td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
}

async function loadUnits(silent = false) {
  const seq = ++unitSeq;
  try {
    const res = await api("/api/units");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (seq !== unitSeq) return;
    state.units = payload;
    renderUnitFilters();
    renderUnitList();
    renderServicesRail();
  } catch (err) {
    if (seq !== unitSeq || silent) return;
    const el = $("unitList");
    if (el) el.innerHTML = `<p class="empty">Não foi possível ler o systemctl: ${escapeHtml(err.message)}</p>`;
  }
}

function renderServicesRail() {
  const el = $("serviceBeacons");
  const meta = $("servicesMeta");
  const counts = state.units?.counts || {};
  const total = state.units?.total || 0;
  if (meta) {
    meta.textContent = `${fmtNum(total)} unidades · v${state.units?.version || ""}`;
  }
  if (!el) return;
  const items = [
    { label: "Running", hint: "active running", value: counts.running || 0, state: "ok" },
    { label: "Stopped", hint: "inactive / dead", value: counts.stopped || 0, state: "ok" },
    { label: "Failed", hint: "systemctl --failed", value: counts.failed || 0, state: counts.failed ? "bad" : "ok" },
    { label: "Ativo", hint: "exited / waiting", value: counts.active || 0, state: "ok" },
  ];
  el.innerHTML = items.map((b) => `
    <article class="beacon">
      <span class="lamp ${b.state}"></span>
      <div>
        <b>${b.label}</b>
        <small>${b.hint}</small>
      </div>
      <em>${fmtNum(b.value)}</em>
    </article>
  `).join("");
}

function paintSinceChips() {
  document.querySelectorAll("button[data-since]").forEach((btn) => {
    btn.classList.toggle("is-on", btn.dataset.since === state.since);
  });
}

function onSinceClick(ev) {
  const btn = ev.target.closest("button[data-since]");
  if (!btn) return;
  state.since = btn.dataset.since;
  paintSinceChips();
  loadReport();
  if (state.tab === "services" && state.unitSelected) loadUnitLogs();
}

function openUnitLogs(unit, ident) {
  state.unitSelected = resolveUnitOpen(unit, ident);
  if (state.tab !== "services") {
    setTab("services");
  } else {
    renderUnitList();
    loadUnitLogs();
  }
  const panel = $("unitLog");
  if (panel) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadUnitLogs() {
  const sel = state.unitSelected;
  const box = $("unitLog");
  const refresh = $("unitLogRefresh");
  const head = $("unitLogHead");
  if (!sel || (!sel.unit && !sel.ident)) return;
  if (refresh) refresh.hidden = false;
  const seq = ++unitLogSeq;
  if (box) box.innerHTML = `<p class="empty">Lendo journalctl…</p>`;
  const params = new URLSearchParams({ since: state.since, lines: "500" });
  if (sel.unit) params.set("unit", sel.unit);
  if (sel.ident) params.set("ident", sel.ident);
  try {
    const res = await api(`/api/unit-logs?${params.toString()}`);
    const payload = await res.json();
    if (seq !== unitLogSeq) return;
    state.unitLogs = payload;
    renderUnitLogs();
    paintUnitChrome(payload);
    if (head) {
      const title = payload.selector || sel.unit || sel.ident;
      head.querySelector("h3").textContent = title;
      head.querySelector("p").innerHTML = payload.command
        ? `Equivale a <span class="mono">${escapeHtml(payload.command)}</span>`
        : "Logs da unidade";
    }
    if (payload.failed) requestUnitTips(false);
  } catch (err) {
    if (seq !== unitLogSeq) return;
    if (box) box.innerHTML = `<p class="empty">Não foi possível ler os logs: ${escapeHtml(err.message)}</p>`;
  }
}

function renderUnitLogs() {
  const box = $("unitLog");
  if (!box) return;
  const payload = state.unitLogs;
  if (!payload) {
    box.innerHTML = `<p class="empty">Clique num serviço à esquerda para ler só os logs dele.</p>`;
    return;
  }
  if (payload.error) {
    box.innerHTML = `<p class="empty">${escapeHtml(payload.message || payload.error)}</p>`;
    return;
  }
  const rows = payload.entries || [];
  if (!rows.length) {
    box.innerHTML = `<p class="empty">${payload.warning || "Sem eventos neste recorte."}</p>`;
    return;
  }
  box.innerHTML = `
    ${payload.warning ? `<p class="empty">${escapeHtml(payload.warning)}</p>` : ""}
    <ol class="log-lines">
      ${rows.map((row) => `
        <li class="log-line ${row.severity || ""}">
          <time>${fmtTime(row.t)}</time>
          <span class="sev">${escapeHtml(row.severity || "")}</span>
          <span class="log-text">${escapeHtml(row.message)}</span>
        </li>
      `).join("")}
    </ol>
  `;
  box.scrollTop = box.scrollHeight;
}

function paintUnitChrome(payload) {
  const disable = $("unitDisable");
  const aiBox = $("unitAi");
  const showDisable = !!(payload && payload.failed && payload.can_disable && !payload.essential);
  if (disable) disable.hidden = !showDisable;
  if (!aiBox) return;
  if (!payload || payload.error || !payload.failed) {
    aiBox.hidden = true;
    aiBox.innerHTML = "";
  }
}

function formatTipsHtml(entry) {
  if (!entry || entry.status === "loading") {
    return `<p class="tips__cause">Consultando a IA com o log de inicialização…</p>`;
  }
  if (entry.status === "error") {
    return `<p class="tips__caution">${escapeHtml(entry.message || "Falha ao gerar dicas.")}</p>
      <p><button type="button" class="btn-ai" data-open-ai>Configurar IA</button></p>`;
  }
  const t = entry.tips || {};
  const steps = (t.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  const cmds = (t.commands || []).map((c) => `
    <div class="cmd">
      <code>${escapeHtml(c.cmd)}</code>
      ${c.why ? `<small>${escapeHtml(c.why)}</small>` : ""}
    </div>
  `).join("");
  return `
    ${t.summary ? `<p class="tips__summary">${escapeHtml(t.summary)}</p>` : ""}
    ${t.likely_cause ? `<p class="tips__cause"><strong>Causa provável.</strong> ${escapeHtml(t.likely_cause)}</p>` : ""}
    ${steps ? `<ol>${steps}</ol>` : ""}
    ${cmds}
    ${t.caution ? `<p class="tips__caution"><strong>Cuidado.</strong> ${escapeHtml(t.caution)}</p>` : ""}
    <p class="tips__cause">${escapeHtml(entry.model || "")}</p>
  `;
}

function renderUnitAi() {
  const el = $("unitAi");
  if (!el) return;
  const payload = state.unitLogs;
  if (!payload || payload.error || !payload.failed) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  const unit = payload.unit || state.unitSelected?.unit || "";
  const entry = state.unitTips[unit];
  const essentialNote = payload.essential
    ? `<p class="tips__caution">Serviço essencial do Linux — o disable não está disponível.</p>`
    : "";
  const staticNote = !payload.essential && !payload.can_disable
    ? `<p class="tips__caution">Unidade estática: o systemd não deixa dar disable. A IA ainda pode sugerir a correção.</p>`
    : "";
  el.innerHTML = `
    <header>
      <h3>IA · serviço failed</h3>
      <button type="button" class="btn-ai" id="unitTipsRefresh">Pedir dicas</button>
    </header>
    ${essentialNote}
    ${staticNote}
    <div>${formatTipsHtml(entry)}</div>
  `;
}

async function requestUnitTips(refresh = false) {
  const payload = state.unitLogs;
  const unit = payload?.unit || state.unitSelected?.unit;
  if (!unit || !payload?.failed) return;
  if (!state.ai.configured) {
    state.unitTips[unit] = { status: "error", message: "Configure uma chave de IA para analisar este serviço." };
    renderUnitAi();
    return;
  }
  if (state.unitTips[unit]?.status === "ok" && !refresh) {
    renderUnitAi();
    return;
  }
  const seq = ++unitTipSeq;
  state.unitTips[unit] = { status: "loading" };
  renderUnitAi();
  try {
    const res = await api("/api/unit-tips", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit, refresh }),
    });
    const data = await res.json();
    if (seq !== unitTipSeq) return;
    if (res.status === 412 || data.error === "ai_not_configured") {
      state.ai.configured = false;
      paintAiStatus();
      state.unitTips[unit] = { status: "error", message: data.message || "IA não configurada." };
    } else if (!res.ok || data.error) {
      state.unitTips[unit] = { status: "error", message: data.message || "A IA não conseguiu responder." };
    } else {
      state.unitTips[unit] = { status: "ok", tips: data.tips, model: data.model };
    }
  } catch (err) {
    if (seq !== unitTipSeq) return;
    state.unitTips[unit] = { status: "error", message: err.message };
  }
  if ((state.unitLogs?.unit || "") === unit) renderUnitAi();
}

async function disableSelectedUnit() {
  const payload = state.unitLogs;
  const unit = payload?.unit;
  if (!unit || !payload?.can_disable || payload.essential) return;
  if (!window.confirm(`Desabilitar ${unit}?\n\nEle não inicia mais no boot (systemctl disable --now).`)) return;
  const btn = $("unitDisable");
  if (btn) btn.disabled = true;
  try {
    const res = await api("/api/unit-disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ unit }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      window.alert(data.message || "Não foi possível desabilitar o serviço.");
      return;
    }
    await loadUnits();
    await loadUnitLogs();
  } catch (err) {
    window.alert(err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function impactColor(label) {
  if (label === "crítico") return "var(--bad)";
  if (label === "alto") return "var(--warn)";
  if (label === "médio") return "var(--info)";
  return "var(--ok)";
}

function openDrawer(id) {
  const issue = state.report.issues.find((i) => i.id === id);
  if (!issue) return;
  state.selected = id;
  $("drawer").hidden = false;
  $("drawerSev").textContent = `${issue.severity_label} · ${issue.app}`;
  $("drawerTitle").textContent = issue.title;
  $("drawerFacts").innerHTML = [
    ["Ocorrências", fmtNum(issue.count)],
    ["Percentual", fmtPct(issue.pct)],
    ["Impacto", `${issue.impact_label} (${issue.impact})`],
    ["Melhoria estimada", issue.improvement_pct ? fmtPct(issue.improvement_pct) : "—"],
    ["Unidade", issue.unit],
    ["Primeira vez", fmtTime(issue.first_seen)],
    ["Última vez", fmtTime(issue.last_seen)],
    ["Tags", issue.tags.join(", ") || "—"],
    ["Neste boot", issue.boot_label || "—"],
  ].map(([k, v]) => `<div><dt>${k}</dt><dd>${escapeHtml(String(v))}</dd></div>`).join("");
  const ctx = issue.context;
  const box = $("drawerContext");
  if (box) {
    if (ctx) {
      box.innerHTML = `
        <h3>O que a máquina fazia na última ocorrência</h3>
        <p>Amostra de métricas ${ctx.skew_sec ? `(±${fmtNum(ctx.skew_sec)}s)` : ""} · ${fmtTime(ctx.t)}</p>
        <dl class="facts">
          <div><dt>CPU</dt><dd>${fmtPct(ctx.cpu)}</dd></div>
          <div><dt>I/O wait</dt><dd>${fmtPct(ctx.iowait)}</dd></div>
          <div><dt>RAM</dt><dd>${fmtPct(ctx.mem)}</dd></div>
          <div><dt>Load 1</dt><dd>${Number(ctx.load1 || 0).toFixed(2)}</dd></div>
          <div><dt>PSI mem</dt><dd>${Number(ctx.psi_mem || 0).toFixed(2)}</dd></div>
          <div><dt>Disco</dt><dd>${fmtRate((ctx.dread || 0) + (ctx.dwrite || 0))}</dd></div>
        </dl>
      `;
    } else {
      box.innerHTML = `<h3>O que a máquina fazia</h3><p class="empty">Ainda não há amostra de CPU/RAM perto deste horário. Deixe o painel aberto que o histórico passa a correlacionar.</p>`;
    }
  }
  $("drawerSamples").innerHTML = issue.samples.map((s) =>
    `<li><time>${fmtTime(s.t)}</time>${escapeHtml(s.message)}</li>`
  ).join("") || "<li>Sem amostras.</li>";
  renderTips(id);
}

async function loadAiStatus() {
  try {
    const res = await api("/api/ai");
    if (res.ok) state.ai = await res.json();
  } catch {
    state.ai = { configured: false, provider: null, signup: AI_SIGNUP };
  }
  paintAiStatus();
  if (state.tab === "machine" && state.ai.configured && !state.machineTips) {
    requestMachineTips(false);
  }
}

function paintAiStatus() {
  const btn = $("aiStatusBtn");
  if (!btn) return;
  if (state.ai.configured) {
    btn.textContent = `IA · ${state.ai.provider} · trocar`;
    btn.classList.add("is-ready");
  } else {
    btn.textContent = "Configurar IA";
    btn.classList.remove("is-ready");
  }
}

function openAiModal() {
  const configured = Boolean(state.ai.configured && state.ai.provider);
  $("aiModalTitle").textContent = configured ? "Trocar chave da IA" : "Configurar IA Tips";
  $("aiModalLead").textContent = configured
    ? "Cole uma chave nova para substituir a atual. O provedor é detectado pelo prefixo (gsk_ = Groq, AIza = Gemini)."
    : "Cole uma chave do plano gratuito. Ela fica no host selecionado e pode ser trocada a qualquer momento.";
  const host = currentHost();
  if (host && host.id !== "local") {
    $("aiModalLead").textContent = configured
      ? `A chave nova substitui a do host “${host.name}” (${host.address}).`
      : `Cole uma chave para o host “${host.name}”. Ela fica naquela máquina, não nesta.`;
  }
  $("aiCurrent").hidden = !configured;
  $("aiCurrent").textContent = configured
    ? `Em uso agora: ${state.ai.provider}. A chave antiga é substituída ao salvar.`
    : "";
  if (state.ai.provider) $("aiProvider").value = state.ai.provider;
  $("aiKey").value = "";
  $("aiHint").textContent = `Crie a chave em ${AI_SIGNUP[$("aiProvider").value] || AI_SIGNUP.groq}`;
  $("aiModal").hidden = false;
  $("aiKey").focus();
}

function renderTips(id) {
  const el = $("tipsBody");
  if (!el) return;
  const entry = state.tips[id];
  if (!entry) {
    el.innerHTML = state.ai.configured
      ? `<p class="tips__cause">A IA recebe o contexto completo deste problema (app, unidade, amostras, impacto) e devolve passos de correção.</p>`
      : `<p class="tips__cause">Configure uma chave gratuita (Groq, sem cartão) para pedir sugestões de correção.</p>`;
    return;
  }
  if (entry.status === "loading") {
    el.innerHTML = `<p class="tips__cause">Consultando a IA com o contexto do journal…</p>`;
    return;
  }
  if (entry.status === "error") {
    el.innerHTML = `<p class="tips__caution">${escapeHtml(entry.message || "Falha ao gerar dicas.")}</p>
      <p><button type="button" class="btn-ai" data-open-ai>Trocar chave</button></p>`;
    return;
  }
  const t = entry.tips || {};
  const steps = (t.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  const cmds = (t.commands || []).map((c) => `
    <div class="cmd">
      <code>${escapeHtml(c.cmd)}</code>
      ${c.why ? `<small>${escapeHtml(c.why)}</small>` : ""}
    </div>
  `).join("");
  el.innerHTML = `
    ${t.summary ? `<p class="tips__summary">${escapeHtml(t.summary)}</p>` : ""}
    ${t.likely_cause ? `<p class="tips__cause"><strong>Causa provável.</strong> ${escapeHtml(t.likely_cause)}</p>` : ""}
    ${steps ? `<ol>${steps}</ol>` : ""}
    ${cmds}
    ${t.caution ? `<p class="tips__caution"><strong>Cuidado.</strong> ${escapeHtml(t.caution)}</p>` : ""}
    <p class="tips__cause">${escapeHtml(entry.model || "")}</p>
  `;
}

async function requestTips(id, refresh = false) {
  const issue = state.report?.issues?.find((i) => i.id === id);
  if (!issue) return;
  if (!state.ai.configured) {
    openAiModal();
    return;
  }
  if (state.tips[id]?.status === "ok" && !refresh) {
    renderTips(id);
    return;
  }
  state.tips[id] = { status: "loading" };
  renderTips(id);
  $("tipsRefresh").disabled = true;
  try {
    const res = await api("/api/tips", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ issue, refresh }),
    });
    const payload = await res.json();
    if (res.status === 412 || payload.error === "ai_not_configured") {
      state.ai.configured = false;
      paintAiStatus();
      openAiModal();
      state.tips[id] = { status: "error", message: payload.message || "IA não configurada." };
    } else if (!res.ok || payload.error) {
      state.tips[id] = { status: "error", message: payload.message || "A IA não conseguiu responder." };
    } else {
      state.tips[id] = { status: "ok", tips: payload.tips, model: payload.model };
    }
  } catch (err) {
    state.tips[id] = { status: "error", message: err.message };
  } finally {
    $("tipsRefresh").disabled = false;
    if (state.selected === id) renderTips(id);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value).replaceAll("'", "&#39;");
}

function polyline(values, w, h, pad, max) {
  if (!values.length) return "";
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;
  const maxV = Math.max(max || 1, 1);
  const step = values.length === 1 ? 0 : innerW / (values.length - 1);
  return values.map((v, i) => {
    const x = pad.l + i * step;
    const y = pad.t + innerH - (Math.max(0, Number(v) || 0) / maxV) * innerH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

function renderLineChart(id, points, series, opts = {}) {
  const el = $(id);
  if (!points.length) {
    el.innerHTML = `<p class="empty">Aguardando a primeira amostra…</p>`;
    return;
  }
  const w = 900;
  const h = 200;
  const pad = { l: 52, r: 12, t: 16, b: 28 };
  const fmt = opts.fmt || ((n) => n.toLocaleString("pt-BR", { maximumFractionDigits: 1 }));
  const max = Math.max(opts.minMax || 1, ...series.flatMap((s) => points.map((p) => Number(p[s.key]) || 0)));
  const innerH = h - pad.t - pad.b;
  const lines = series.map((s) => {
    const pts = polyline(points.map((p) => Number(p[s.key]) || 0), w, h, pad, max);
    return `<polyline fill="none" stroke="${s.color}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round" points="${pts}"></polyline>`;
  }).join("");
  el.innerHTML = `
    <svg class="chart-svg" viewBox="0 0 ${w} ${h}" role="img">
      <line x1="${pad.l}" y1="${pad.t + innerH}" x2="${w - pad.r}" y2="${pad.t + innerH}" stroke="rgba(231,238,247,.12)"/>
      <text x="${pad.l - 6}" y="${pad.t + 4}" fill="#8d9aab" font-size="10" text-anchor="end">${fmt(max)}</text>
      ${lines}
      <text x="${pad.l}" y="${h - 8}" fill="#8d9aab" font-size="11">${fmtTime(points[0].t)}</text>
      <text x="${w - pad.r}" y="${h - 8}" fill="#8d9aab" font-size="11" text-anchor="end">${fmtTime(points[points.length - 1].t)}</text>
    </svg>
    <div class="legend">
      ${series.map((s) => `<span><i style="background:${s.color}"></i>${s.label}</span>`).join("")}
    </div>
  `;
}

function renderTopTable(id, rows, columns) {
  const el = $(id);
  if (!rows?.length) {
    el.innerHTML = `<p class="empty">Nenhum ofensor neste instante.</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table">
      <thead><tr>${columns.map((c) => `<th>${c.label}</th>`).join("")}</tr></thead>
      <tbody>
        ${rows.map((row) => `<tr>${columns.map((c) =>
          `<td class="${c.mono ? "mono" : ""}">${c.render(row)}</td>`
        ).join("")}</tr>`).join("")}
      </tbody>
    </table>
  `;
}

function procLabel(row) {
  const cmd = row.cmd && row.cmd !== row.name
    ? `<span class="cmd" title="${escapeAttr(row.cmd)}">${escapeHtml(row.cmd)}</span>`
    : "";
  return `${escapeHtml(row.name || "—")}${cmd}`;
}

let liveTimer = 0;
let diskTimer = 0;
let machineTimer = 0;
let machineSeq = 0;
let machineTipSeq = 0;

function setTab(tab) {
  state.tab = tab;
  $("viewJournal").hidden = tab !== "journal";
  $("viewServices").hidden = tab !== "services";
  $("viewLive").hidden = tab !== "live";
  $("viewMachine").hidden = tab !== "machine";
  $("viewDisk").hidden = tab !== "disk";
  $("railJournal").hidden = tab !== "journal";
  $("railServices").hidden = tab !== "services";
  $("railLive").hidden = tab !== "live";
  $("railMachine").hidden = tab !== "machine";
  $("railDisk").hidden = tab !== "disk";
  document.querySelectorAll(".tabs [data-tab]").forEach((btn) => {
    btn.classList.toggle("is-on", btn.dataset.tab === tab);
  });
  $("aiStatusBtn").hidden = tab !== "journal" && tab !== "services" && tab !== "machine";
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = 0;
  }
  if (diskTimer) {
    clearInterval(diskTimer);
    diskTimer = 0;
  }
  if (machineTimer) {
    clearInterval(machineTimer);
    machineTimer = 0;
  }
  $("banner").hidden = true;
  if (tab === "live") {
    $("kicker").textContent = "Monitor em tempo real";
    $("pageTitle").textContent = "Uso do sistema agora";
    loadLive();
    liveTimer = setInterval(loadLive, 2000);
  } else if (tab === "disk") {
    $("kicker").textContent = "Uso de disco";
    $("pageTitle").textContent = "Onde o espaço está indo";
    loadDisk();
  } else if (tab === "services") {
    $("kicker").textContent = "systemd";
    $("pageTitle").textContent = "O que está running, stopped e failed";
    paintSinceChips();
    if (state.report) renderFailedUnits(state.report.failed_units || []);
    loadUnits();
    if (state.unitSelected) loadUnitLogs();
  } else if (tab === "machine") {
    $("kicker").textContent = "Hardware e gargalos";
    $("pageTitle").textContent = "O que esta máquina aguenta — e o que melhorar";
    loadMachine();
    machineTimer = setInterval(() => loadMachine(false), 20000);
  } else {
    $("kicker").textContent = state.report ? `Relatório operacional · ${state.report.since_label}` : "Relatório operacional";
    $("pageTitle").textContent = "O que o journal está tentando te dizer";
    if (state.report) render();
    else loadReport();
  }
}

function fmtUptime(sec) {
  const s = Math.max(0, Number(sec) || 0);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  return `${Math.max(m, 0)} min`;
}

function shortGpu(name) {
  const quoted = String(name || "").match(/"([^"]+)"/g);
  if (quoted && quoted.length >= 4) {
    return `${quoted[2].replace(/"/g, "")} ${quoted[3].replace(/"/g, "")}`.trim();
  }
  return String(name || "GPU").slice(0, 90);
}

function diskKindLabel(disk) {
  const tran = String(disk.transport || "").toLowerCase();
  if (tran === "nvme" || String(disk.name || "").startsWith("nvme")) return "NVMe";
  if (disk.rotational || disk.kind === "hdd") return "HDD";
  if (disk.kind === "ssd" || tran === "sata") return "SSD";
  return (disk.kind || tran || "disco").toUpperCase();
}

function bottleneckLamp(kind) {
  if (kind === "bad") return "bad";
  if (kind === "warn") return "warn";
  return "ok";
}

function statLine(stat, suffix = "%") {
  const row = stat || {};
  const avg = Number(row.avg || 0);
  const max = Number(row.max || 0);
  if (!row.samples) return "ainda coletando";
  const fmt = suffix === "%"
    ? (n) => fmtPct(n)
    : (n) => Number(n).toLocaleString("pt-BR", { maximumFractionDigits: 2 });
  return `média ${fmt(avg)} · pico ${fmt(max)}`;
}

async function loadMachine(refresh = false) {
  const seq = ++machineSeq;
  try {
    const q = refresh ? "?refresh=1" : "";
    const res = await api(`/api/machine${q}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    if (seq !== machineSeq) return;
    state.machine = payload;
    if (state.tab === "machine") renderMachine();
    if (state.tab === "machine" && state.ai.configured && !state.machineTips) {
      requestMachineTips(false);
    }
  } catch (err) {
    if (seq !== machineSeq || state.tab !== "machine") return;
    $("banner").hidden = false;
    $("banner").textContent = `Não foi possível ler o hardware: ${err.message}`;
  }
}

function renderMachine() {
  const r = state.machine;
  if (!r) return;
  $("banner").hidden = true;
  $("clock").textContent = fmtTime(r.generated_at);
  const hw = r.hardware || {};
  const dmi = hw.dmi || {};
  const host = [hw.hostname, `${dmi.vendor || ""} ${dmi.product || ""}`.trim(), `v${r.version || ""}`]
    .filter(Boolean)
    .join(" · ");
  $("machineMeta").textContent = host || "inventário lido";
  renderMachineBeacons(r);
  renderMachineKpis(r);
  renderMachineFacts(r);
  renderMachineUsage(r);
  renderMachineBottlenecks(r);
  renderMachineAi();
}

function renderMachineBeacons(r) {
  const findings = r.bottlenecks || [];
  const items = findings.slice(0, 6).map((b) => ({
    label: b.area || "sistema",
    hint: b.title || "",
    value: b.state === "bad" ? "ruim" : b.state === "warn" ? "atenção" : "ok",
    state: bottleneckLamp(b.state),
  }));
  $("machineBeacons").innerHTML = items.map((b) => `
    <article class="beacon">
      <span class="lamp ${b.state}"></span>
      <div>
        <b>${escapeHtml(b.label)}</b>
        <small>${escapeHtml(b.hint)}</small>
      </div>
      <em>${escapeHtml(b.value)}</em>
    </article>
  `).join("");
}

function renderMachineKpis(r) {
  const hw = r.hardware || {};
  const mem = hw.memory || {};
  const usage = r.usage || {};
  const now = usage.now || {};
  const journal = r.journal || {};
  const cpuHw = hw.cpu || {};
  const score = Number(r.score || 0);
  const cpuNow = Number(now.cpu ?? usage.cpu?.last ?? 0);
  const memNow = Number(now.mem_pct ?? usage.mem?.last ?? 0);
  const swapUsed = Number(now.swap_used ?? mem.swap_used ?? 0);
  const swapTotal = Number(now.swap_total ?? mem.swap_total ?? 0);
  const oom = Number(journal.oom || 0);
  const failed = (journal.failed_units || []).length;
  const bat = hw.battery;
  const scoreClass = kpiTone(score >= 75, score >= 50);
  const cpuClass = kpiTone(cpuNow < 70, cpuNow < 90);
  const memClass = kpiTone(memNow < 80, memNow < 92);
  const oomClass = kpiTone(oom === 0, oom < 3);
  $("machineKpis").innerHTML = `
    <article class="kpi kpi--health ${scoreClass}">
      <span>Score local</span>
      <strong>${fmtNum(score)}</strong>
      <small>heurística de gargalos</small>
    </article>
    <article class="kpi kpi--health ${cpuClass}">
      <span>CPU agora</span>
      <strong>${fmtPct(cpuNow)}</strong>
      <small>${escapeHtml(String(cpuHw.ncpu || "—"))} núcleos · ${statLine(usage.cpu)}</small>
    </article>
    <article class="kpi kpi--health ${memClass}">
      <span>RAM</span>
      <strong>${fmtPct(memNow)}</strong>
      <small>${fmtBytes(now.mem_used || mem.used)} de ${fmtBytes(now.mem_total || mem.total)}</small>
    </article>
    <article class="kpi">
      <span>Swap</span>
      <strong>${swapTotal ? fmtBytes(swapUsed) : "off"}</strong>
      <small>${swapTotal ? `de ${fmtBytes(swapTotal)} · swappiness ${hw.vm?.swappiness ?? "—"}` : "sem partição/arquivo"}</small>
    </article>
    <article class="kpi kpi--health ${oomClass}">
      <span>OOM / failed</span>
      <strong>${fmtNum(oom)} / ${fmtNum(failed)}</strong>
      <small>journal + systemd neste recorte</small>
    </article>
    <article class="kpi">
      <span>${bat ? "Bateria" : "GPU"}</span>
      <strong>${bat ? `${bat.capacity ?? "—"}%` : escapeHtml(shortGpu((hw.gpus || [])[0]?.name || "—"))}</strong>
      <small>${bat
        ? `${escapeHtml(bat.status || "")} · saúde ${bat.health_pct != null ? fmtPct(bat.health_pct) : "—"}`
        : `${(hw.gpus || []).length || 0} adaptador(es)`}</small>
    </article>
  `;
}

function fact(label, value) {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${value || "—"}</dd></div>`;
}

function renderMachineFacts(r) {
  const hw = r.hardware || {};
  const cpu = hw.cpu || {};
  const dmi = hw.dmi || {};
  const disks = hw.disks || [];
  const mounts = hw.mounts || [];
  const gpus = hw.gpus || [];
  const bat = hw.battery;
  const thermals = hw.thermals || [];
  const diskText = disks.length
    ? disks.map((d) => `${d.name} ${fmtBytes(d.size)} ${diskKindLabel(d)}${d.model ? ` (${d.model})` : ""}`).join(" · ")
    : "não detectado";
  const mountText = mounts.length
    ? mounts.map((m) => `${m.path} ${fmtPct(m.pct)} (${fmtBytes(m.free)} livre)`).join(" · ")
    : "—";
  const gpuText = gpus.length ? gpus.map((g) => shortGpu(g.name)).join(" · ") : "não detectada";
  const thermalText = thermals.length
    ? thermals.map((t) => `${t.name} ${Number(t.celsius).toLocaleString("pt-BR", { maximumFractionDigits: 1 })} °C`).join(" · ")
    : "sem sensores";
  $("machineFacts").innerHTML = [
    fact("Máquina", escapeHtml(`${dmi.vendor || ""} ${dmi.product || ""}`.trim() || hw.hostname || "—")),
    fact("Placa / BIOS", escapeHtml([dmi.board, dmi.bios].filter(Boolean).join(" · ") || "—")),
    fact("Processador", escapeHtml(`${cpu.model || "CPU"} · ${cpu.ncpu || "?"} núcleos`)),
    fact("Frequência", escapeHtml(`${cpu.mhz ? `${fmtNum(cpu.mhz)} MHz agora` : "—"}${cpu.max_mhz ? ` · máx ${fmtNum(cpu.max_mhz)} MHz` : ""} · governor ${cpu.governor || "?"}`)),
    fact("RAM", escapeHtml(`${fmtBytes(hw.memory?.total)} · ${fmtBytes(hw.memory?.available)} disponível`)),
    fact("Swap / vm", escapeHtml(`${fmtBytes(hw.memory?.swap_total)} · swappiness ${hw.vm?.swappiness ?? "—"}`)),
    fact("Discos", escapeHtml(diskText)),
    fact("Montagens", escapeHtml(mountText)),
    fact("GPU", escapeHtml(gpuText)),
    fact("Bateria", bat
      ? escapeHtml(`${bat.name} ${bat.capacity ?? "—"}% · ${bat.status || ""} · ${bat.cycle_count ?? "?"} ciclos · saúde ${bat.health_pct != null ? `${bat.health_pct}%` : "?"}`)
      : "desktop / sem BAT*"),
    fact("Térmico", escapeHtml(thermalText)),
    fact("Kernel / uptime", escapeHtml(`${hw.kernel || "Linux"} · ${fmtUptime(hw.uptime_sec)}`)),
  ].join("");
}

function renderMachineUsage(r) {
  const usage = r.usage || {};
  const now = usage.now || {};
  const journal = r.journal || {};
  const topCpu = ((usage.top || {}).cpu || []).slice(0, 3);
  const topMem = ((usage.top || {}).mem || []).slice(0, 3);
  const issues = journal.top_issues || [];
  $("machineUsage").innerHTML = [
    fact("Amostras", escapeHtml(`${fmtNum(usage.samples || 0)} pontos do monitor ao vivo`)),
    fact("CPU", escapeHtml(statLine(usage.cpu))),
    fact("Load 1", escapeHtml(statLine(usage.load1, ""))),
    fact("RAM", escapeHtml(statLine(usage.mem))),
    fact("PSI memória", escapeHtml(statLine(usage.psi_mem, ""))),
    fact("I/O wait", escapeHtml(statLine(usage.iowait))),
    fact("PSI I/O", escapeHtml(statLine(usage.psi_io, ""))),
    fact("Disco agora", escapeHtml(`R ${fmtRate(now.disk_read || 0)} · W ${fmtRate(now.disk_write || 0)}`)),
    fact("Top CPU", escapeHtml(topCpu.length ? topCpu.map((p) => `${p.name} ${fmtPct(p.cpu)}`).join(" · ") : "—")),
    fact("Top RAM", escapeHtml(topMem.length ? topMem.map((p) => `${p.name} ${fmtBytes(p.rss)}`).join(" · ") : "—")),
    fact("Saúde do journal", escapeHtml(`${journal.health != null ? journal.health : "—"} · ${fmtNum(journal.errors_15m || 0)} erros/15 min · ${fmtNum(journal.oom || 0)} OOM`)),
    fact("Serviços failed", escapeHtml((journal.failed_units || []).join(", ") || "nenhum")),
    fact("Problemas do journal", escapeHtml(issues.length ? issues.map((i) => i.title || i.app).join(" · ") : "—")),
  ].join("");
}

function renderMachineBottlenecks(r) {
  const rows = r.bottlenecks || [];
  if (!rows.length) {
    $("machineBottlenecks").innerHTML = `<p class="empty">Nenhum gargalo óbvio neste recorte.</p>`;
    return;
  }
  $("machineBottlenecks").innerHTML = `<div class="bottleneck-list">${rows.map((b) => `
    <article class="bottleneck is-${escapeAttr(b.state || "ok")}">
      <span class="lamp ${bottleneckLamp(b.state)}"></span>
      <div>
        <b>${escapeHtml(b.title || b.area || "achado")}</b>
        <small>${escapeHtml(b.area || "")}</small>
        <p>${escapeHtml(b.detail || "")}</p>
      </div>
    </article>
  `).join("")}</div>`;
}

function renderMachineAi() {
  const el = $("machineAi");
  const btn = $("machineTipsBtn");
  if (!el) return;
  const entry = state.machineTips;
  if (btn) {
    btn.disabled = entry?.status === "loading";
    btn.textContent = entry?.status === "ok" ? "Pedir de novo" : "Analisar com IA";
  }
  if (!entry) {
    el.innerHTML = state.ai.configured
      ? `<p class="empty">A IA cruza hardware, uso, journal (OOM) e serviços failed. Clique em Analisar com IA.</p>`
      : `<p class="empty">Configure uma chave gratuita para receber sugestões de software e hardware.
          <button type="button" class="btn-ai" data-open-ai>Configurar IA</button></p>`;
    return;
  }
  if (entry.status === "loading") {
    el.innerHTML = `<p class="empty">Consultando a IA com o inventário, o uso e o journal…</p>`;
    return;
  }
  if (entry.status === "error") {
    el.innerHTML = `<p class="tips__caution">${escapeHtml(entry.message || "Falha ao gerar dicas.")}</p>
      <p><button type="button" class="btn-ai" data-open-ai>Configurar IA</button></p>`;
    return;
  }
  const t = entry.tips || {};
  const aiBottlenecks = (t.ai_bottlenecks || []).map((b) => `
    <li><strong>${escapeHtml(b.area || b.severity || "")}</strong> ${escapeHtml(b.finding || "")}</li>
  `).join("");
  const software = (t.software || []).map((item) => {
    const steps = (item.steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("");
    const cmds = (item.commands || []).map((c) => `
      <div class="cmd">
        <code>${escapeHtml(c.cmd)}</code>
        ${c.why ? `<small>${escapeHtml(c.why)}</small>` : ""}
      </div>
    `).join("");
    return `
      <article class="machine-card">
        <h3>${escapeHtml(item.title || "Ajuste de software")}</h3>
        ${item.why ? `<p>${escapeHtml(item.why)}</p>` : ""}
        ${steps ? `<ol>${steps}</ol>` : ""}
        ${cmds}
      </article>
    `;
  }).join("");
  const hardware = (t.hardware || []).map((item) => `
    <article class="machine-card">
      <span class="hw-priority">${escapeHtml(item.priority || "média")}</span>
      <h3>${escapeHtml(item.title || "Upgrade")}</h3>
      ${item.why ? `<p>${escapeHtml(item.why)}</p>` : ""}
    </article>
  `).join("");
  el.innerHTML = `
    ${t.summary ? `<p class="tips__summary">${escapeHtml(t.summary)}</p>` : ""}
    ${aiBottlenecks ? `<ul class="machine-ai-findings">${aiBottlenecks}</ul>` : ""}
    <div class="machine-ai__cols">
      <div>
        <h3 class="machine-ai__h">Software</h3>
        ${software || `<p class="empty">Nenhuma sugestão de software neste recorte.</p>`}
      </div>
      <div>
        <h3 class="machine-ai__h">Hardware</h3>
        ${hardware || `<p class="empty">Nenhum upgrade físico óbvio agora.</p>`}
      </div>
    </div>
    ${t.caution ? `<p class="tips__caution"><strong>Cuidado.</strong> ${escapeHtml(t.caution)}</p>` : ""}
    <p class="tips__cause">${escapeHtml([t.provider, t.model].filter(Boolean).join(" · "))}</p>
  `;
}

async function requestMachineTips(refresh = false) {
  if (!state.ai.configured) {
    state.machineTips = { status: "error", message: "Configure uma chave de IA para analisar esta máquina." };
    renderMachineAi();
    return;
  }
  if ((state.machineTips?.status === "ok" || state.machineTips?.status === "loading") && !refresh) {
    renderMachineAi();
    return;
  }
  const seq = ++machineTipSeq;
  state.machineTips = { status: "loading" };
  renderMachineAi();
  try {
    const res = await api("/api/machine-tips", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh }),
    });
    const data = await res.json();
    if (seq !== machineTipSeq) return;
    if (res.status === 412 || data.error === "ai_not_configured") {
      state.ai.configured = false;
      paintAiStatus();
      state.machineTips = { status: "error", message: data.message || "IA não configurada." };
    } else if (!res.ok || data.error) {
      state.machineTips = { status: "error", message: data.message || "A IA não conseguiu responder." };
    } else {
      state.machineTips = { status: "ok", tips: data };
    }
  } catch (err) {
    if (seq !== machineTipSeq) return;
    state.machineTips = { status: "error", message: err.message };
  }
  if (state.tab === "machine") renderMachineAi();
}

async function loadLive() {
  try {
    const res = await api("/api/live");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.live = await res.json();
    if (state.tab === "live") renderLive();
  } catch (err) {
    if (state.tab !== "live") return;
    $("banner").hidden = false;
    $("banner").textContent = `Não foi possível ler as métricas: ${err.message}`;
  }
}

function renderLive() {
  const payload = state.live;
  const latest = payload?.latest;
  const history = payload?.history || [];
  if (!latest) {
    $("liveMeta").textContent = "coletando a primeira amostra…";
    $("liveKpis").innerHTML = `<article class="kpi"><span>Aguarde</span><strong>…</strong><small>intervalo de 2s</small></article>`;
    return;
  }
  $("banner").hidden = true;
  $("clock").textContent = fmtTime(latest.t);
  $("liveMeta").textContent = `${latest.hostname} · ${latest.ncpu} CPUs · amostra a cada 2s · v${payload.version || ""}`;
  renderLiveBeacons(latest, payload.journal);
  renderLiveKpis(latest, payload.journal);
  renderLiveCores(latest.cpu.cores || []);
  const ncpu = Math.max(latest.ncpu || 1, 1);
  const hist = history.map((p) => ({
    ...p,
    pressure: (Number(p.load1) / ncpu) * 100,
  }));
  renderLineChart("liveCpuChart", hist, [
    { key: "cpu", color: "#9dff6a", label: "CPU ocupada" },
    { key: "iowait", color: "#f3b23c", label: "I/O wait" },
    { key: "pressure", color: "#79b4ff", label: "Load / CPUs" },
  ], { minMax: 100, fmt: (n) => `${n.toLocaleString("pt-BR", { maximumFractionDigits: 0 })}%` });
  renderLineChart("liveMemChart", hist, [
    { key: "mem", color: "#c4b5fd", label: "RAM usada" },
  ], { minMax: 100, fmt: (n) => `${n.toLocaleString("pt-BR", { maximumFractionDigits: 0 })}%` });
  renderLineChart("livePsiChart", hist, [
    { key: "psi_mem", color: "#ff5d73", label: "PSI memória" },
    { key: "psi_io", color: "#f3b23c", label: "PSI I/O" },
  ], { fmt: (n) => Number(n || 0).toFixed(2) });
  renderLineChart("liveDiskChart", hist, [
    { key: "dread", color: "#9dff6a", label: "Leitura" },
    { key: "dwrite", color: "#ff5d73", label: "Escrita" },
  ], { fmt: fmtRate });
  renderLineChart("liveNetChart", hist, [
    { key: "rx", color: "#79b4ff", label: "Entrada (in)" },
    { key: "tx", color: "#f3b23c", label: "Saída (out)" },
  ], { fmt: fmtRate });
  renderRateBars("liveIfaces", latest.net.ifaces || [], (row) => row.rx_bps + row.tx_bps, (row) =>
    `↓ ${fmtRate(row.rx_bps)} · ↑ ${fmtRate(row.tx_bps)}`
  );
  renderRateBars("liveDisks", latest.disk.devices || [], (row) => row.read_bps + row.write_bps, (row) =>
    `R ${fmtRate(row.read_bps)} · W ${fmtRate(row.write_bps)}`
  );
  const top = latest.top || {};
  renderTopTable("topCpu", top.cpu, [
    { label: "Processo", render: procLabel },
    { label: "PID", mono: true, render: (r) => r.pid },
    { label: "CPU", mono: true, render: (r) => fmtPct(r.cpu) },
    { label: "Estado", mono: true, render: (r) => r.state },
  ]);
  renderTopTable("topMem", top.mem, [
    { label: "Processo", render: procLabel },
    { label: "PID", mono: true, render: (r) => r.pid },
    { label: "RSS", mono: true, render: (r) => fmtBytes(r.rss) },
    { label: "Thr", mono: true, render: (r) => fmtNum(r.threads) },
  ]);
  renderTopTable("topDisk", top.disk, [
    { label: "Processo", render: procLabel },
    { label: "PID", mono: true, render: (r) => r.pid },
    { label: "Read", mono: true, render: (r) => fmtRate(r.disk_read) },
    { label: "Write", mono: true, render: (r) => fmtRate(r.disk_write) },
  ]);
  renderTopTable("topNet", top.net, [
    { label: "Processo", render: procLabel },
    { label: "PID", mono: true, render: (r) => r.pid },
    { label: "Sockets", mono: true, render: (r) => fmtNum(r.sockets) },
    { label: "CPU", mono: true, render: (r) => fmtPct(r.cpu) },
  ]);
  renderTopTable("topLoad", top.load, [
    { label: "Processo", render: procLabel },
    { label: "PID", mono: true, render: (r) => r.pid },
    { label: "Estado", mono: true, render: (r) => r.state },
    { label: "CPU", mono: true, render: (r) => fmtPct(r.cpu) },
    { label: "Score", mono: true, render: (r) => r.load_score },
  ]);
  renderLiveExtras(payload.journal);
}

function renderLiveBeacons(s, pulse) {
  const cpuOk = s.cpu.busy < 70;
  const cpuWarn = s.cpu.busy < 90;
  const loadOk = s.load.min1 < s.ncpu;
  const loadWarn = s.load.min1 < s.ncpu * 1.5;
  const memOk = s.mem.pct < 80;
  const memWarn = s.mem.pct < 92;
  const ioOk = s.cpu.iowait < 15;
  const ioWarn = s.cpu.iowait < 35;
  const psi = s.psi || {};
  const psiMem = Number(psi.memory_some || 0);
  const items = [
    { label: "CPU", hint: `${fmtPct(s.cpu.user)} user`, value: fmtPct(s.cpu.busy), state: lampOf(cpuOk, cpuWarn) },
    { label: "Load 1", hint: `${s.load.min5.toFixed(2)} / ${s.load.min15.toFixed(2)}`, value: s.load.min1.toFixed(2), state: lampOf(loadOk, loadWarn) },
    { label: "RAM", hint: fmtBytes(s.mem.available) + " livre", value: fmtPct(s.mem.pct), state: lampOf(memOk, memWarn) },
    { label: "PSI mem", hint: "pressão de memória", value: psiMem.toFixed(2), state: lampOf(psiMem < 5, psiMem < 20) },
    { label: "I/O wait", hint: "espera de disco", value: fmtPct(s.cpu.iowait), state: lampOf(ioOk, ioWarn) },
    { label: "Journal", hint: pulse?.top?.app || "erros recentes", value: fmtNum(pulse?.errors_15m || 0), state: pulse?.state || "ok" },
  ];
  $("liveBeacons").innerHTML = items.map((b) => `
    <article class="beacon">
      <span class="lamp ${b.state}"></span>
      <div>
        <b>${b.label}</b>
        <small>${b.hint}</small>
      </div>
      <em>${b.value}</em>
    </article>
  `).join("");
}

function renderLiveKpis(s, pulse) {
  const cpuClass = kpiTone(s.cpu.busy < 70, s.cpu.busy < 90);
  const loadClass = kpiTone(s.load.min1 < s.ncpu, s.load.min1 < s.ncpu * 1.5);
  const memClass = kpiTone(s.mem.pct < 80, s.mem.pct < 92);
  const psi = s.psi || {};
  const psiMem = Number(psi.memory_some || 0);
  const psiClass = kpiTone(psiMem < 5, psiMem < 20);
  const journalClass = pulse?.state === "bad" ? "is-bad" : pulse?.state === "warn" ? "is-warn" : "";
  $("liveKpis").innerHTML = `
    <article class="kpi kpi--health ${cpuClass}">
      <span>CPU</span>
      <strong>${fmtPct(s.cpu.busy)}</strong>
      <small>${fmtPct(s.cpu.user)} user · ${fmtPct(s.cpu.system)} sys · ${s.ncpu} núcleos</small>
    </article>
    <article class="kpi kpi--health ${loadClass}">
      <span>Load average</span>
      <strong>${s.load.min1.toFixed(2)}</strong>
      <small>5m ${s.load.min5.toFixed(2)} · 15m ${s.load.min15.toFixed(2)} · ${s.load.runnable}/${s.load.tasks} run</small>
    </article>
    <article class="kpi kpi--health ${memClass}">
      <span>Memória</span>
      <strong>${fmtPct(s.mem.pct)}</strong>
      <small>${fmtBytes(s.mem.used)} / ${fmtBytes(s.mem.total)}</small>
    </article>
    <article class="kpi kpi--health ${psiClass}">
      <span>PSI memória</span>
      <strong>${psiMem.toFixed(2)}</strong>
      <small>full ${Number(psi.memory_full || 0).toFixed(2)} · I/O ${Number(psi.io_some || 0).toFixed(2)}</small>
    </article>
    <article class="kpi kpi--health ${journalClass}">
      <span>Journal 15 min</span>
      <strong>${fmtNum(pulse?.errors_15m || 0)}</strong>
      <small>${pulse?.top ? escapeHtml(pulse.top.app) : "sem pico recente"}</small>
    </article>
    <article class="kpi">
      <span>Rede</span>
      <strong>${fmtRate((s.net.rx_bps || 0) + (s.net.tx_bps || 0))}</strong>
      <small>↓ ${fmtRate(s.net.rx_bps)} · ↑ ${fmtRate(s.net.tx_bps)}</small>
    </article>
  `;
}

function renderLiveExtras(pulse) {
  const oom = (pulse?.oom_events || state.report?.oom?.events || []).slice(-12).reverse();
  const oomEl = $("liveOom");
  if (oomEl) {
    if (!oom.length) {
      oomEl.innerHTML = `<p class="empty">Nenhum OOM no recorte atual do journal.</p>`;
    } else {
      oomEl.innerHTML = `
        <table class="live-table">
          <thead><tr><th>Processo</th><th>Quando</th><th>Unidade</th></tr></thead>
          <tbody>
            ${oom.map((row) => `
              <tr>
                <td>${escapeHtml(row.proc)}</td>
                <td class="mono">${relative(row.t)}</td>
                <td>${escapeHtml(row.unit || "")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    }
  }
  const box = $("liveJournalPulse");
  if (!box) return;
  const top = pulse?.top;
  box.innerHTML = `
    <div class="pulse">
      <p><strong>${pulse?.state === "bad" ? "O journal está gritando." : pulse?.state === "warn" ? "O journal está inquieto." : "O journal está calmo."}</strong></p>
      <p>${fmtNum(pulse?.errors_15m || 0)} erros em 15 min · ${fmtNum(pulse?.failed || 0)} unidades falhas · ${fmtNum(pulse?.oom || 0)} OOM · ${fmtNum(pulse?.new_boot || 0)} novos neste boot</p>
      ${top ? `<p>Maior impacto agora: <b>${escapeHtml(top.app || "")}</b> — ${escapeHtml(top.title || "")}</p>` : ""}
    </div>
  `;
}

function renderLiveCores(cores) {
  const el = $("liveCores");
  if (!cores.length) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = cores.map((pct, i) => {
    const hot = pct >= 85 ? "is-fire" : pct >= 60 ? "is-hot" : "";
    return `<span class="core ${hot}" title="CPU ${i}: ${fmtPct(pct)}"><em style="--h:${Math.min(100, pct)}%"></em><span>${i}</span></span>`;
  }).join("");
}

function renderRateBars(id, rows, valueOf, extraOf) {
  const el = $(id);
  if (!rows.length) {
    el.innerHTML = `<p class="empty">Sem tráfego no intervalo.</p>`;
    return;
  }
  const max = Math.max(1, ...rows.map(valueOf));
  el.innerHTML = rows.slice(0, 8).map((row) => {
    const value = valueOf(row);
    const state = value > max * 0.7 && value > 1 ? "warn" : "";
    return `
      <div class="bar ${state}">
        <b title="${escapeAttr(row.name)}">${escapeHtml(row.name)}</b>
        <i><em style="width:${Math.max(4, (value / max) * 100)}%"></em></i>
        <span>${extraOf(row)}</span>
      </div>
    `;
  }).join("");
}

const DISK_HUES = ["#9dff6a", "#79b4ff", "#c4b5fd", "#f3b23c", "#ff5d73", "#5eead4", "#fb923c", "#38bdf8", "#a3e635", "#f472b6"];

function currentDiskNode() {
  return state.diskFocus[state.diskFocus.length - 1] || state.disk?.tree || null;
}

function findDiskNode(node, path) {
  if (!node) return null;
  if (node.path === path) return node;
  for (const child of node.children || []) {
    const hit = findDiskNode(child, path);
    if (hit) return hit;
  }
  return null;
}

function diskStackTo(root, path) {
  const stack = [];
  function walk(node) {
    stack.push(node);
    if (node.path === path && node.kind !== "files") return true;
    for (const child of node.children || []) {
      if (child.kind === "files" || child.kind === "other") continue;
      if (walk(child)) return true;
    }
    stack.pop();
    return false;
  }
  return root && walk(root) ? stack : [root];
}

function polar(cx, cy, r, a) {
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function arcPath(cx, cy, r0, r1, a0, a1) {
  const sweep = a1 - a0;
  if (sweep <= 0.0008) return "";
  const large = sweep > Math.PI ? 1 : 0;
  const [x0, y0] = polar(cx, cy, r1, a0);
  const [x1, y1] = polar(cx, cy, r1, a1);
  const [x2, y2] = polar(cx, cy, r0, a1);
  const [x3, y3] = polar(cx, cy, r0, a0);
  return `M${x0.toFixed(2)},${y0.toFixed(2)} A${r1},${r1} 0 ${large} 1 ${x1.toFixed(2)},${y1.toFixed(2)} L${x2.toFixed(2)},${y2.toFixed(2)} A${r0},${r0} 0 ${large} 0 ${x3.toFixed(2)},${y3.toFixed(2)} Z`;
}

async function loadDisk(refresh = false) {
  const q = new URLSearchParams();
  if (state.diskRoot) q.set("root", state.diskRoot);
  if (refresh) q.set("refresh", "1");
  try {
    const res = await api(`/api/disk?${q.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const payload = await res.json();
    state.disk = payload;
    if (!state.diskRoot) state.diskRoot = payload.root;
    if (payload.status === "scanning") {
      if (state.tab === "disk" && !diskTimer) diskTimer = setInterval(() => loadDisk(false), 800);
    } else if (diskTimer) {
      clearInterval(diskTimer);
      diskTimer = 0;
    }
    if (payload.status === "ready" && payload.tree) {
      if (!state.diskFocus.length || state.diskFocus[0].path !== payload.tree.path) {
        state.diskFocus = [payload.tree];
        state.diskSelected = payload.tree.path;
        state.diskOpen = new Set();
        inspectDisk(payload.tree.path, false);
      }
    }
    if (state.tab === "disk") renderDisk();
  } catch (err) {
    if (state.tab !== "disk") return;
    $("banner").hidden = false;
    $("banner").textContent = `Não foi possível medir o disco: ${err.message}`;
  }
}

function renderDisk() {
  const d = state.disk;
  if (!d) return;
  const fs = d.fs || {};
  const tree = currentDiskNode();
  const scanning = d.status === "scanning";
  $("clock").textContent = scanning ? "medindo…" : fmtTime(new Date().toISOString());
  $("diskPath").value = state.diskRoot || d.root || "";
  $("diskMeta").textContent = scanning
    ? `${d.progress?.current || d.root} · ${fmtNum(d.progress?.dirs || 0)} pastas`
    : `${d.root} · ${d.elapsed || 0}s · v${d.version || ""}`;
  const usedPct = fs.pct || 0;
  $("diskBeacons").innerHTML = [
    { label: "Ocupado", hint: "neste volume", value: fmtPct(usedPct), state: lampOf(usedPct < 80, usedPct < 92) },
    { label: "Livre", hint: "disponível", value: fmtBytes(fs.free || 0), state: "ok" },
  ].map((b) => `
    <article class="beacon">
      <span class="lamp ${b.state}"></span>
      <div><b>${b.label}</b><small>${b.hint}</small></div>
      <em>${b.value}</em>
    </article>
  `).join("");
  renderDiskTargets(d.targets || []);
  const scanned = tree?.size || d.progress?.bytes || 0;
  $("diskKpis").innerHTML = `
    <article class="kpi kpi--health ${kpiTone(usedPct < 80, usedPct < 92)}">
      <span>Volume</span>
      <strong>${fmtPct(usedPct)}</strong>
      <small>${fmtBytes(fs.used || 0)} de ${fmtBytes(fs.total || 0)}</small>
    </article>
    <article class="kpi">
      <span>${scanning ? "Medindo" : "Nesta pasta"}</span>
      <strong>${fmtBytes(scanned)}</strong>
      <small>${escapeHtml(tree?.path || d.root || "")}</small>
    </article>
    <article class="kpi">
      <span>Pastas</span>
      <strong>${fmtNum(tree?.dirs || d.progress?.dirs || 0)}</strong>
      <small>${scanning ? "encontradas até agora" : "abaixo deste nível"}</small>
    </article>
    <article class="kpi">
      <span>Arquivos</span>
      <strong>${fmtNum(tree?.files || d.progress?.files || 0)}</strong>
      <small>${scanning ? "contados até agora" : "abaixo deste nível"}</small>
    </article>
    <article class="kpi">
      <span>Livre</span>
      <strong>${fmtBytes(fs.free || 0)}</strong>
      <small>neste sistema de arquivos</small>
    </article>
  `;
  renderDiskCrumb();
  renderDiskTable();
  renderDiskChart(tree);
  renderDiskTop(d.top || []);
  renderDiskInspect();
  const viewBtns = document.querySelectorAll("#diskView [data-disk-view]");
  viewBtns.forEach((btn) => btn.classList.toggle("is-on", btn.dataset.diskView === state.diskView));
}

function renderDiskTargets(targets) {
  const el = $("diskTargets");
  el.innerHTML = targets.map((row) => {
    const on = (state.diskRoot || state.disk?.root) === row.path;
    return `<button type="button" data-disk-root="${escapeAttr(row.path)}" class="${on ? "is-on" : ""}">${escapeHtml(row.label)}</button>`;
  }).join("");
}

function renderDiskCrumb() {
  const el = $("diskCrumb");
  if (!state.diskFocus.length) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = state.diskFocus.map((node, i) => {
    const last = i === state.diskFocus.length - 1;
    const label = i === 0 ? node.path : node.name;
    if (last) return `<span>${escapeHtml(label)}</span>`;
    return `<button type="button" data-disk-level="${i}">${escapeHtml(label)}</button><span>/</span>`;
  }).join("");
}

function usageClass(pct) {
  if (pct >= 40) return "is-bad";
  if (pct >= 18) return "is-warn";
  return "";
}

function diskRowId(row) {
  return `${row.path}|${row.kind || "dir"}|${row.name}`;
}

function shadeHex(hex, factor) {
  const n = parseInt(hex.slice(1), 16);
  const ch = (v) => Math.max(0, Math.min(255, Math.round(v * factor)));
  const r = ch((n >> 16) & 255);
  const g = ch((n >> 8) & 255);
  const b = ch(n & 255);
  return `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`;
}

function flattenDiskTree(node, parentSize, depth, acc) {
  const kids = node?.children || [];
  for (const row of kids) {
    const id = diskRowId(row);
    const hasKids = row.kind === "dir" && (row.children || []).some((c) => c.size > 0);
    const open = state.diskOpen.has(id);
    acc.push({
      row,
      pct: (row.size / Math.max(parentSize, 1)) * 100,
      depth,
      hasKids,
      open,
      id,
    });
    if (open && hasKids) flattenDiskTree(row, Math.max(row.size, 1), depth + 1, acc);
  }
}

function expandDiskPath(path) {
  const root = state.disk?.tree;
  if (!root) return;
  function walk(node, ids) {
    ids.push(diskRowId(node));
    if (node.path === path && node.kind !== "files") {
      ids.forEach((id) => state.diskOpen.add(id));
      return true;
    }
    for (const child of node.children || []) {
      if (walk(child, ids)) return true;
    }
    ids.pop();
    return false;
  }
  walk(root, []);
}

function renderDiskTable() {
  const el = $("diskTable");
  const root = state.disk?.tree;
  if (!root) {
    el.innerHTML = `<p class="empty">${state.disk?.status === "scanning" ? "Medindo o disco…" : "Nada para mostrar neste nível."}</p>`;
    return;
  }
  const rows = [];
  flattenDiskTree(root, Math.max(root.size, 1), 0, rows);
  if (!rows.length) {
    el.innerHTML = `<p class="empty">${state.disk?.status === "scanning" ? "Medindo o disco…" : "Nada para mostrar neste nível."}</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table disk-tree">
      <thead>
        <tr>
          <th>Pasta</th>
          <th>Uso</th>
          <th>%</th>
          <th>Tamanho</th>
          <th>Conteúdo</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${rows.map((item) => {
          const { row, pct, depth, hasKids, open, id } = item;
          const selected = row.path === state.diskSelected && row.kind !== "files" ? "is-on" : "";
          const twist = hasKids
            ? `<button type="button" class="tree-twist" data-disk-toggle="${escapeAttr(id)}" aria-label="${open ? "Recolher" : "Expandir"}">${open ? "▾" : "▸"}</button>`
            : `<span class="tree-twist"></span>`;
          const inspect = row.kind === "dir"
            ? `<button type="button" class="btn-ai" data-inspect="${escapeAttr(row.path)}">Inspecionar</button>`
            : "";
          const contents = row.kind === "dir"
            ? `${fmtNum((row.dirs || 0) + (row.files || 0))}`
            : (row.kind === "files" ? fmtNum(row.files || 0) : "—");
          return `
            <tr data-disk-path="${escapeAttr(row.path)}" data-disk-kind="${row.kind || "dir"}" class="${selected}">
              <td>
                <span class="tree-pad" style="--d:${depth}">
                  ${twist}
                  <span class="folder-name">
                    ${escapeHtml(row.name)}
                    <small>${row.kind === "files" ? "arquivos neste nível" : (row.kind === "other" ? "demais itens" : "")}</small>
                  </span>
                </span>
              </td>
              <td><div class="usage ${usageClass(pct)}"><b style="width:${Math.max(3, pct)}%"></b></div></td>
              <td class="mono">${fmtPct(pct)}</td>
              <td class="mono">${fmtBytes(row.size)}</td>
              <td class="mono">${contents}</td>
              <td>${inspect}</td>
            </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderDiskChart(node) {
  if (state.diskView === "tiles") renderTreemap(node);
  else renderSunburst(node);
}

function renderSunburst(node) {
  const el = $("diskChart");
  if (!node) {
    el.innerHTML = `<p class="empty">${state.disk?.status === "scanning" ? "Montando o mapa…" : "Sem dados."}</p>`;
    return;
  }
  const w = 640;
  const cx = 320;
  const cy = 320;
  const ring = 42;
  const hole = 72;
  const slices = [];
  const tau = Math.PI * 2;
  const start0 = -Math.PI / 2;
  function visit(item, depth, a0, a1, color) {
    if (depth > 0 && a1 - a0 > 0.004) {
      slices.push({ item, depth, a0, a1, color });
    }
    const kids = item.children || [];
    const total = Math.max(item.size, 1);
    let a = a0;
    kids.forEach((kid, i) => {
      const span = (a1 - a0) * (kid.size / total);
      const kidColor = depth === 0 ? DISK_HUES[i % DISK_HUES.length] : shadeHex(color, 0.82 + (i % 3) * 0.06);
      visit(kid, depth + 1, a, a + span, kidColor);
      a += span;
    });
  }
  visit(node, 0, start0, start0 + tau, DISK_HUES[0]);
  const paths = slices.map((slice) => {
    const r0 = hole + (slice.depth - 1) * ring;
    const r1 = hole + slice.depth * ring - 1.2;
    const d = arcPath(cx, cy, r0, r1, slice.a0, slice.a1);
    if (!d) return "";
    const on = slice.item.path === state.diskSelected ? "is-on" : "";
    const title = `${slice.item.name} · ${fmtBytes(slice.item.size)}`;
    return `<path class="${on}" data-disk-path="${escapeAttr(slice.item.path)}" data-disk-kind="${slice.item.kind || "dir"}" d="${d}" fill="${slice.color}">
      <title>${escapeHtml(title)}</title>
    </path>`;
  }).join("");
  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${w}" role="img" aria-label="Mapa de uso de disco em anéis">
      <circle class="sunburst-hub" cx="${cx}" cy="${cy}" r="${hole - 8}" fill="#10151c" stroke="rgba(231,238,247,.08)" data-disk-up="1"/>
      ${paths}
      <text x="${cx}" y="${cy - 8}" text-anchor="middle" fill="#e8eef6" font-size="15" font-family="Sora" pointer-events="none">${escapeHtml((node.name || "").slice(0, 18))}</text>
      <text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="#9dff6a" font-size="13" font-family="IBM Plex Mono" pointer-events="none">${fmtBytes(node.size)}</text>
    </svg>
  `;
}

function layoutTiles(items, x, y, w, h, depth, parentColor, rects, horizontal) {
  const row = items.filter((it) => it.size > 0);
  if (!row.length || w < 2 || h < 2) return;
  const total = row.reduce((sum, it) => sum + it.size, 0) || 1;
  let offset = 0;
  row.forEach((item, i) => {
    const frac = item.size / total;
    const color = depth === 0 ? DISK_HUES[i % DISK_HUES.length] : shadeHex(parentColor, 0.78 + (i % 4) * 0.07);
    let rx;
    let ry;
    let rw;
    let rh;
    if (horizontal) {
      rx = x + offset;
      ry = y;
      rw = w * frac;
      rh = h;
      offset += rw;
    } else {
      rx = x;
      ry = y + offset;
      rw = w;
      rh = h * frac;
      offset += rh;
    }
    const kids = (item.children || []).filter((c) => c.size > 0);
    const pad = 1.15;
    if (kids.length && depth < 5 && rw > 8 && rh > 8) {
      layoutTiles(kids, rx + pad, ry + pad, Math.max(rw - pad * 2, 1), Math.max(rh - pad * 2, 1), depth + 1, color, rects, !horizontal);
    } else {
      rects.push({ item, x: rx, y: ry, w: rw, h: rh, color, depth });
    }
  });
}

function renderTreemap(node) {
  const el = $("diskChart");
  if (!node) {
    el.innerHTML = `<p class="empty">${state.disk?.status === "scanning" ? "Montando o mapa…" : "Sem dados."}</p>`;
    return;
  }
  const w = 720;
  const h = 520;
  const rects = [];
  layoutTiles(node.children || [node], 8, 8, w - 16, h - 16, 0, DISK_HUES[0], rects, true);
  const cells = rects.map((cell) => {
    if (cell.w < 2 || cell.h < 2) return "";
    const on = cell.item.path === state.diskSelected ? "is-on" : "";
    const label = cell.w > 64 && cell.h > 28
      ? `<text x="${cell.x + 6}" y="${cell.y + 16}" fill="#07090d" font-size="11" font-family="Sora">${escapeHtml(cell.item.name.slice(0, 18))}</text>
         <text x="${cell.x + 6}" y="${cell.y + 30}" fill="#10210c" font-size="10" font-family="IBM Plex Mono">${fmtBytes(cell.item.size)}</text>`
      : "";
    return `<g data-disk-path="${escapeAttr(cell.item.path)}" data-disk-kind="${cell.item.kind || "dir"}">
      <rect class="${on}" x="${cell.x.toFixed(2)}" y="${cell.y.toFixed(2)}" width="${Math.max(cell.w - 0.8, 1).toFixed(2)}" height="${Math.max(cell.h - 0.8, 1).toFixed(2)}" rx="3" fill="${cell.color}">
        <title>${escapeHtml(cell.item.name)} · ${fmtBytes(cell.item.size)}</title>
      </rect>
      ${label}
    </g>`;
  }).join("");
  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Mapa quadriculado de uso de disco">
      ${cells}
    </svg>
  `;
}

function renderDiskTop(rows) {
  const el = $("diskTop");
  if (!rows.length) {
    el.innerHTML = `<p class="empty">${state.disk?.status === "scanning" ? "Ainda agrupando pastas…" : "Sem ofensores."}</p>`;
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.size));
  el.innerHTML = `
    <table class="live-table">
      <thead><tr><th>Pasta</th><th>Uso</th><th>Tamanho</th><th></th></tr></thead>
      <tbody>
        ${rows.map((row) => `
          <tr>
            <td><span class="folder-name">${escapeHtml(row.name)}<small>${escapeHtml(row.path)}</small></span></td>
            <td><div class="usage ${usageClass((row.size / max) * 100)}"><b style="width:${Math.max(4, (row.size / max) * 100)}%"></b></div></td>
            <td class="mono">${fmtBytes(row.size)}</td>
            <td><button type="button" class="btn-ai" data-inspect="${escapeAttr(row.path)}">Inspecionar</button></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderDiskInspect() {
  const hint = $("diskInspectHint");
  const actions = $("diskInspectActions");
  const el = $("diskInspect");
  const info = state.diskInspect;
  const selected = state.diskSelected || currentDiskNode()?.path;
  if (!info || info.error) {
    hint.textContent = info?.message || "Escolha uma pasta na pizza ou na tabela";
    actions.innerHTML = selected
      ? `<button type="button" class="btn-ai" data-inspect="${escapeAttr(selected)}">Inspecionar</button>
         <button type="button" class="ghost" data-open-dir="${escapeAttr(selected)}">Abrir pasta</button>`
      : "";
    el.innerHTML = `<p class="empty">O conteúdo aparece aqui depois de inspecionar.</p>`;
    return;
  }
  hint.textContent = `${info.path} · ${fmtNum(info.dir_count)} pastas · ${fmtNum(info.file_count)} arquivos nesta pasta`;
  actions.innerHTML = `
    <button type="button" class="btn-ai" data-inspect="${escapeAttr(info.path)}">Inspecionar</button>
    <button type="button" class="ghost" data-open-dir="${escapeAttr(info.path)}">Abrir pasta</button>
  `;
  const files = info.files || [];
  const dirs = (info.dirs || []).slice(0, 12);
  if (!files.length && !dirs.length) {
    el.innerHTML = `<p class="empty">Pasta vazia ou sem permissão.</p>`;
    return;
  }
  el.innerHTML = `
    <table class="live-table">
      <thead><tr><th>Nome</th><th>Tipo</th><th>Tamanho</th><th></th></tr></thead>
      <tbody>
        ${dirs.map((row) => `
          <tr>
            <td>${escapeHtml(row.name)}</td>
            <td>pasta</td>
            <td class="mono">—</td>
            <td><button type="button" class="btn-ai" data-inspect="${escapeAttr(row.path)}">Inspecionar</button></td>
          </tr>
        `).join("")}
        ${files.map((row) => `
          <tr>
            <td>${escapeHtml(row.name)}</td>
            <td>arquivo</td>
            <td class="mono">${fmtBytes(row.size)}</td>
            <td></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

async function inspectDisk(path, drill = true) {
  if (!path) return;
  const tree = state.disk?.tree;
  const node = findDiskNode(tree, path);
  state.diskSelected = path;
  if (drill && node && node.kind === "dir") {
    const stack = diskStackTo(tree, path);
    if (stack?.length) state.diskFocus = stack;
  }
  expandDiskPath(path);
  renderDisk();
  try {
    const res = await api(`/api/disk/ls?path=${encodeURIComponent(path)}`);
    const payload = await res.json();
    if (state.diskSelected !== path) return;
    state.diskInspect = payload;
    renderDiskInspect();
  } catch (err) {
    state.diskInspect = { error: "ls_failed", message: err.message };
    renderDiskInspect();
  }
}

async function openDiskPath(path) {
  try {
    const res = await api("/api/disk/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    const payload = await res.json();
    if (!res.ok) {
      $("banner").hidden = false;
      $("banner").textContent = payload.message || "Não foi possível abrir a pasta.";
    }
  } catch (err) {
    $("banner").hidden = false;
    $("banner").textContent = err.message;
  }
}

function bind() {
  document.querySelector(".tabs").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-tab]");
    if (!btn) return;
    setTab(btn.dataset.tab);
  });
  $("hostCurrent").addEventListener("click", (ev) => {
    ev.stopPropagation();
    const menu = $("hostMenu");
    const willOpen = menu.hidden;
    menu.hidden = !willOpen;
    $("hostCurrent").setAttribute("aria-expanded", willOpen ? "true" : "false");
    if (willOpen) {
      renderHostList();
      const filter = $("hostFilter");
      if (filter && !filter.parentElement.hidden) filter.focus();
    }
  });
  $("hostList").addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-host]");
    if (btn) selectHost(btn.dataset.host);
  });
  $("hostFilter").addEventListener("input", (ev) => {
    state.hostFilter = ev.target.value;
    renderHostList();
  });
  $("hostManageBtn").addEventListener("click", (ev) => {
    ev.stopPropagation();
    openHostModal();
  });
  $("hostAdd").addEventListener("click", addRemoteHost);
  $("hostNewName").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("hostNewAddr").focus();
  });
  $("hostNewAddr").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("hostNewUser").focus();
  });
  $("hostNewUser").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("hostNewPass").focus();
  });
  $("hostNewPass").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") addRemoteHost();
  });
  $("hostModalClose").addEventListener("click", () => { $("hostModal").hidden = true; });
  $("hostModal").addEventListener("click", (ev) => {
    if (ev.target.id === "hostModal") $("hostModal").hidden = true;
  });
  $("hostLocalSave").addEventListener("click", () => {
    const name = $("hostLocalName").value.trim();
    if (name) renameHost("local", name);
  });
  $("hostRemoteList").addEventListener("click", (ev) => {
    const renameBtn = ev.target.closest("[data-host-rename]");
    if (renameBtn) {
      const row = (state.hosts || []).find((h) => h.id === renameBtn.dataset.hostRename);
      const next = window.prompt("Nome deste host", row?.name || "");
      if (next && next.trim()) renameHost(renameBtn.dataset.hostRename, next.trim());
      return;
    }
    const removeBtn = ev.target.closest("[data-host-remove]");
    if (removeBtn) removeHost(removeBtn.dataset.hostRemove);
  });
  document.addEventListener("click", (ev) => {
    if (ev.target.closest("#hostBar")) return;
    closeHostMenu();
  });
  $("ranges").addEventListener("click", onSinceClick);
  $("serviceRanges").addEventListener("click", onSinceClick);
  $("refreshBtn").addEventListener("click", () => {
    if (state.tab === "live") loadLive();
    else if (state.tab === "disk") {
      state.diskFocus = [];
      state.diskInspect = null;
      state.diskOpen = new Set();
      loadDisk(true);
    } else if (state.tab === "services") {
      loadUnits();
      if (state.unitSelected) loadUnitLogs();
      if (state.report) renderFailedUnits(state.report.failed_units || []);
    } else if (state.tab === "machine") {
      loadMachine(true);
    } else loadReport();
  });
  $("diskTargets").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-disk-root]");
    if (!btn) return;
    state.diskRoot = btn.dataset.diskRoot;
    state.diskFocus = [];
    state.diskInspect = null;
    state.diskOpen = new Set();
    loadDisk(true);
  });
  $("diskScanBtn").addEventListener("click", () => {
    const path = $("diskPath").value.trim();
    if (!path) return;
    state.diskRoot = path;
    state.diskFocus = [];
    state.diskInspect = null;
    state.diskOpen = new Set();
    loadDisk(true);
  });
  $("diskPath").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("diskScanBtn").click();
  });
  $("viewDisk").addEventListener("click", (ev) => {
    const viewBtn = ev.target.closest("[data-disk-view]");
    if (viewBtn) {
      state.diskView = viewBtn.dataset.diskView;
      renderDisk();
      return;
    }
    const toggle = ev.target.closest("[data-disk-toggle]");
    if (toggle) {
      ev.preventDefault();
      ev.stopPropagation();
      const id = toggle.dataset.diskToggle;
      if (state.diskOpen.has(id)) state.diskOpen.delete(id);
      else state.diskOpen.add(id);
      renderDiskTable();
      return;
    }
    const inspect = ev.target.closest("[data-inspect]");
    if (inspect) {
      inspectDisk(inspect.dataset.inspect, true);
      return;
    }
    const openBtn = ev.target.closest("[data-open-dir]");
    if (openBtn) {
      openDiskPath(openBtn.dataset.openDir);
      return;
    }
    const up = ev.target.closest("[data-disk-up]");
    if (up && state.diskFocus.length > 1) {
      state.diskFocus = state.diskFocus.slice(0, -1);
      inspectDisk(currentDiskNode().path, false);
      return;
    }
    const level = ev.target.closest("[data-disk-level]");
    if (level) {
      const idx = Number(level.dataset.diskLevel);
      state.diskFocus = state.diskFocus.slice(0, idx + 1);
      inspectDisk(state.diskFocus[idx].path, false);
      return;
    }
    const slice = ev.target.closest("[data-disk-path]");
    if (slice) inspectDisk(slice.dataset.diskPath, slice.dataset.diskKind === "dir");
  });
  $("search").addEventListener("input", (ev) => {
    state.query = ev.target.value;
    renderIssues();
  });
  $("appFilter").addEventListener("change", (ev) => {
    state.app = ev.target.value;
    renderIssues();
  });
  $("sortFilter").addEventListener("change", (ev) => {
    state.sort = ev.target.value;
    renderIssues();
  });
  $("sevFilters").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-sev]");
    if (!btn) return;
    const id = btn.dataset.sev;
    const defaults = new Set(["emerg", "alert", "crit", "err", "warning"]);
    if (state.severities.size === 1 && state.severities.has(id)) {
      state.severities = defaults;
    } else {
      state.severities = new Set([id]);
    }
    renderSevFilters(state.report.severity);
    renderIssues();
  });
  $("bootFilter").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-boot]");
    if (!btn) return;
    state.bootOnly = btn.dataset.boot === "new";
    for (const node of $("bootFilter").querySelectorAll("button")) node.classList.toggle("is-on", node === btn);
    renderIssues();
  });
  $("failedUnits").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-unit]");
    if (tr) openUnitLogs(tr.dataset.unit, "");
  });
  $("unitList").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-unit]");
    if (tr) openUnitLogs(tr.dataset.unit, "");
  });
  $("unitSearch").addEventListener("input", (ev) => {
    state.unitQuery = ev.target.value;
    renderUnitList();
  });
  $("unitStateFilter").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-unit-state]");
    if (!btn) return;
    state.unitState = btn.dataset.unitState;
    renderUnitFilters();
    renderUnitList();
  });
  $("unitLogRefresh").addEventListener("click", () => {
    if (state.unitSelected) loadUnitLogs();
  });
  $("unitDisable").addEventListener("click", () => {
    disableSelectedUnit();
  });
  $("unitAi").addEventListener("click", (ev) => {
    if (ev.target.closest("[data-open-ai]")) {
      openAiModal();
      return;
    }
    if (ev.target.id === "unitTipsRefresh") requestUnitTips(true);
  });
  $("appsChart").addEventListener("click", (ev) => {
    const bar = ev.target.closest("[data-open-unit],[data-open-ident]");
    if (!bar) return;
    openUnitLogs(bar.dataset.openUnit || "", bar.dataset.openIdent || "");
  });
  $("unitsChart").addEventListener("click", (ev) => {
    const bar = ev.target.closest("[data-open-unit],[data-open-ident]");
    if (!bar) return;
    openUnitLogs(bar.dataset.openUnit || "", bar.dataset.openIdent || "");
  });
  $("bootNew").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-id]");
    if (tr && tr.dataset.id) openDrawer(tr.dataset.id);
  });
  $("issueBody").addEventListener("click", (ev) => {
    const tipsBtn = ev.target.closest("button[data-tips]");
    if (tipsBtn) {
      ev.preventDefault();
      ev.stopPropagation();
      const id = tipsBtn.dataset.tips;
      openDrawer(id);
      requestTips(id);
      return;
    }
    const tr = ev.target.closest("tr[data-id]");
    if (tr) openDrawer(tr.dataset.id);
  });
  $("issueBody").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" && ev.key !== " ") return;
    const tr = ev.target.closest("tr[data-id]");
    if (!tr) return;
    ev.preventDefault();
    openDrawer(tr.dataset.id);
  });
  $("drawerClose").addEventListener("click", () => { $("drawer").hidden = true; });
  $("drawer").addEventListener("click", (ev) => {
    if (ev.target.id === "drawer") $("drawer").hidden = true;
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "/" && document.activeElement.tagName !== "INPUT" && state.tab === "journal") {
      ev.preventDefault();
      $("search").focus();
    }
    if (ev.key === "Escape") {
      $("drawer").hidden = true;
      $("aiModal").hidden = true;
      $("hostModal").hidden = true;
      closeHostMenu();
    }
  });
  $("tipsRefresh").addEventListener("click", () => {
    if (state.selected) requestTips(state.selected, true);
  });
  $("tipsBody").addEventListener("click", (ev) => {
    if (ev.target.closest("[data-open-ai]")) openAiModal();
  });
  $("machineTipsBtn").addEventListener("click", () => requestMachineTips(true));
  $("machineAi").addEventListener("click", (ev) => {
    if (ev.target.closest("[data-open-ai]")) openAiModal();
  });
  $("logoutBtn").addEventListener("click", async () => {
    try {
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
    } catch {
      /* still leave */
    }
    window.location.replace("/login");
  });
  $("aiStatusBtn").addEventListener("click", openAiModal);
  $("aiClose").addEventListener("click", () => { $("aiModal").hidden = true; });
  $("aiModal").addEventListener("click", (ev) => {
    if (ev.target.id === "aiModal") $("aiModal").hidden = true;
  });
  $("aiProvider").addEventListener("change", () => {
    const p = $("aiProvider").value;
    $("aiHint").textContent = `Crie a chave em ${AI_SIGNUP[p] || AI_SIGNUP.groq}`;
  });
  $("aiSave").addEventListener("click", async () => {
    const api_key = $("aiKey").value.trim();
    const provider = $("aiProvider").value;
    if (!api_key) {
      $("aiHint").textContent = "Cole a chave antes de salvar.";
      return;
    }
    const res = await api("/api/ai", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider, api_key }),
    });
    const payload = await res.json();
    if (!res.ok) {
      $("aiHint").textContent = payload.message || "Não foi possível salvar.";
      return;
    }
    state.ai = payload;
    $("aiKey").value = "";
    state.tips = {};
    state.machineTips = null;
    paintAiStatus();
    $("aiModal").hidden = true;
    if (state.selected) requestTips(state.selected, true);
    if (state.tab === "machine") requestMachineTips(true);
  });
  $("aiForget").addEventListener("click", async () => {
    const res = await api("/api/ai", { method: "DELETE" });
    if (res.ok) state.ai = await res.json();
    state.tips = {};
    state.machineTips = null;
    paintAiStatus();
    if (state.tab === "machine") renderMachineAi();
    $("aiHint").textContent = "Chave removida. Cole uma nova para continuar.";
    $("aiCurrent").hidden = true;
  });
}

async function ensureSession() {
  try {
    const res = await fetch("/api/session", { credentials: "same-origin" });
    const data = await res.json();
    const btn = $("logoutBtn");
    if (data.required && !data.user) {
      window.location.replace("/login");
      return false;
    }
    if (btn) {
      btn.hidden = !data.required;
      if (data.user) btn.title = data.user;
    }
    return true;
  } catch {
    return true;
  }
}

ensureSession().then((ok) => {
  if (!ok) return;
  bind();
  loadHosts(true).then(() => {
    loadAiStatus();
    loadUnits();
    loadReport();
  });
});
setInterval(() => {
  if (state.tab === "journal") loadReport(true);
}, 30000);
unitTimer = setInterval(() => {
  if (state.tab === "services") loadUnits(true);
}, 15000);
setInterval(() => loadHosts(true), 20000);
