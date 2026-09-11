(() => {
  "use strict";

  // ---------- Theme ----------
  const root = document.documentElement;
  const themeToggle = document.getElementById("themeToggle");
  const iconSun = document.getElementById("iconSun");
  const iconMoon = document.getElementById("iconMoon");

  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
      root.setAttribute("data-theme", theme);
    } else {
      root.removeAttribute("data-theme");
    }
    const isDark = theme === "dark" || (theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    iconSun.hidden = isDark;
    iconMoon.hidden = !isDark;
  }

  function currentTheme() {
    try { return localStorage.getItem("ipscann-theme") || "system"; } catch { return "system"; }
  }

  applyTheme(currentTheme());
  themeToggle.addEventListener("click", () => {
    const isDark = !iconMoon.hidden;
    const next = isDark ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("ipscann-theme", next); } catch { /* ignore */ }
  });

  // ---------- Elements ----------
  const ifaceSelect = document.getElementById("ifaceSelect");
  const cidrInput = document.getElementById("cidrInput");
  const scanBtn = document.getElementById("scanBtn");
  const stopBtn = document.getElementById("stopBtn");
  const scanStateEl = document.getElementById("scanState");

  const portScanToggle = document.getElementById("portScanToggle");
  const passesInput = document.getElementById("passesInput");
  const timeoutInput = document.getElementById("timeoutInput");
  const concurrencyInput = document.getElementById("concurrencyInput");

  const progressSection = document.getElementById("progressSection");
  const progressLabel = document.getElementById("progressLabel");
  const progressStats = document.getElementById("progressStats");
  const progressFill = document.getElementById("progressFill");

  const conflictBanner = document.getElementById("conflictBanner");
  const conflictTitle = document.getElementById("conflictTitle");
  const conflictList = document.getElementById("conflictList");

  const searchInput = document.getElementById("searchInput");
  const resultsSummary = document.getElementById("resultsSummary");
  const exportBtn = document.getElementById("exportBtn");
  const resultsBody = document.getElementById("resultsBody");
  const emptyState = document.getElementById("emptyState");
  const rowTemplate = document.getElementById("rowTemplate");
  const table = document.getElementById("resultsTable");

  // ---------- State ----------
  let hosts = new Map(); // ip -> host object
  let currentScanId = null;
  let eventSource = null;
  let sortKey = "ip";
  let sortDir = 1;
  let filterText = "";

  // ---------- Interfaces ----------
  async function loadInterfaces() {
    try {
      const res = await fetch("/api/interfaces");
      const ifaces = await res.json();
      ifaceSelect.innerHTML = "";
      if (!Array.isArray(ifaces) || ifaces.length === 0) {
        const opt = document.createElement("option");
        opt.textContent = "No active interfaces found";
        ifaceSelect.appendChild(opt);
        return;
      }
      for (const iface of ifaces) {
        const opt = document.createElement("option");
        opt.value = iface.cidr;
        opt.textContent = `${iface.name} — ${iface.ip} (${iface.cidr})`;
        ifaceSelect.appendChild(opt);
      }
      cidrInput.value = ifaces[0].cidr;
    } catch (err) {
      console.error("failed to load interfaces", err);
    }
  }

  ifaceSelect.addEventListener("change", () => {
    if (ifaceSelect.value) cidrInput.value = ifaceSelect.value;
  });

  // ---------- Scan lifecycle ----------
  function setScanState(state) {
    scanStateEl.className = "pill pill-" + state;
    scanStateEl.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  }

  function resetResults() {
    hosts = new Map();
    conflictList.innerHTML = "";
    conflictBanner.hidden = true;
    renderTable();
  }

  scanBtn.addEventListener("click", startScan);
  stopBtn.addEventListener("click", stopScan);

  async function startScan() {
    const cidr = cidrInput.value.trim();
    if (!cidr) {
      cidrInput.focus();
      return;
    }

    resetResults();
    scanBtn.disabled = true;
    stopBtn.hidden = false;
    exportBtn.disabled = true;
    progressSection.hidden = false;
    progressFill.style.width = "0%";
    progressLabel.textContent = "Starting scan…";
    progressStats.textContent = "";
    setScanState("running");

    const opts = {
      cidr,
      portScan: portScanToggle.checked,
      passes: clampInt(passesInput.value, 2, 1, 5),
      timeoutMs: clampInt(timeoutInput.value, 700, 100, 5000),
      concurrency: clampInt(concurrencyInput.value, 128, 1, 512),
    };

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(opts),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      currentScanId = data.id;
      streamScan(currentScanId);
    } catch (err) {
      progressLabel.textContent = "Failed to start scan: " + err.message;
      finishScanUI("error");
    }
  }

  async function stopScan() {
    if (!currentScanId) return;
    try {
      await fetch(`/api/scan/${currentScanId}/stop`, { method: "POST" });
    } catch (err) {
      console.error("failed to stop scan", err);
    }
  }

  function streamScan(id) {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`/api/scan/${id}/stream`);

    eventSource.addEventListener("status", (evt) => {
      const data = JSON.parse(evt.data);
      updateProgress(data.status);
    });

    eventSource.addEventListener("host", (evt) => {
      const data = JSON.parse(evt.data);
      upsertHost(data.host);
    });

    eventSource.addEventListener("done", (evt) => {
      const data = JSON.parse(evt.data);
      updateProgress(data.status);
      finishScanUI(data.status.state);
    });

    eventSource.onerror = () => {
      // The server closes the stream normally once the job finishes;
      // treat an otherwise-idle connection error as "done" defensively.
      if (scanBtn.disabled) finishScanUI("done");
    };
  }

  function finishScanUI(state) {
    scanBtn.disabled = false;
    stopBtn.hidden = true;
    exportBtn.disabled = hosts.size === 0;
    setScanState(state === "running" ? "done" : state);
    if (eventSource) { eventSource.close(); eventSource = null; }
  }

  function updateProgress(status) {
    if (!status) return;
    const pct = status.total > 0 ? Math.min(100, Math.round((status.scanned / status.total) * 100)) : 0;
    progressFill.style.width = pct + "%";

    const elapsed = formatElapsed(status.elapsedMs || 0);
    const passInfo = status.passes > 1 ? `pass ${status.pass || 1}/${status.passes} · ` : "";
    progressLabel.textContent = status.state === "running"
      ? `Scanning… ${passInfo}${pct}%`
      : stateLabel(status.state);
    progressStats.textContent = `${status.scanned}/${status.total} checked · ${status.found} found · ${status.conflicts} conflict${status.conflicts === 1 ? "" : "s"} · ${elapsed}`;

    if (status.error) progressLabel.textContent = "Error: " + status.error;
    renderConflictBanner(status.conflicts || 0);
  }

  function stateLabel(state) {
    switch (state) {
      case "done": return "Scan complete";
      case "cancelled": return "Scan stopped";
      case "error": return "Scan failed";
      default: return "Scanning…";
    }
  }

  function formatElapsed(ms) {
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    const rem = s % 60;
    return `${String(m).padStart(2, "0")}:${String(rem).padStart(2, "0")}`;
  }

  function clampInt(v, def, min, max) {
    let n = parseInt(v, 10);
    if (Number.isNaN(n)) n = def;
    return Math.min(max, Math.max(min, n));
  }

  // ---------- Host table ----------
  function upsertHost(host) {
    hosts.set(host.ip, host);
    renderTable();
  }

  function renderConflictBanner(count) {
    if (!count) {
      conflictBanner.hidden = true;
      return;
    }
    conflictBanner.hidden = false;
    conflictTitle.textContent = `${count} IP conflict${count === 1 ? "" : "s"} detected`;
    conflictList.innerHTML = "";
    const conflicted = [...hosts.values()].filter((h) => h.conflict).sort((a, b) => a.ip.localeCompare(b.ip));
    for (const h of conflicted) {
      const li = document.createElement("li");
      if (h.conflictReason === "duplicate-ip") {
        li.textContent = `${h.ip} answered from multiple MAC addresses: ${(h.conflictWith || []).join(", ")}`;
      } else {
        li.textContent = `${h.ip} shares its MAC address (${h.mac || "?"}) with: ${(h.conflictWith || []).join(", ")}`;
      }
      conflictList.appendChild(li);
    }
  }

  function sortedFilteredHosts() {
    const q = filterText.trim().toLowerCase();
    let list = [...hosts.values()];
    if (q) {
      list = list.filter((h) =>
        (h.ip || "").toLowerCase().includes(q) ||
        (h.hostname || "").toLowerCase().includes(q) ||
        (h.mac || "").toLowerCase().includes(q) ||
        (h.vendor || "").toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey];
      if (sortKey === "ip") { av = ipToNumber(a.ip); bv = ipToNumber(b.ip); }
      if (typeof av === "string") av = av.toLowerCase();
      if (typeof bv === "string") bv = bv.toLowerCase();
      if (av === undefined || av === null || av === "") av = sortKey === "latencyMs" ? -1 : "";
      if (bv === undefined || bv === null || bv === "") bv = sortKey === "latencyMs" ? -1 : "";
      if (av < bv) return -1 * sortDir;
      if (av > bv) return 1 * sortDir;
      return 0;
    });
    return list;
  }

  function ipToNumber(ip) {
    return (ip || "0.0.0.0").split(".").reduce((acc, part) => acc * 256 + (parseInt(part, 10) || 0), 0);
  }

  function renderTable() {
    const list = sortedFilteredHosts();
    resultsBody.innerHTML = "";
    const frag = document.createDocumentFragment();

    for (const h of list) {
      const row = rowTemplate.content.firstElementChild.cloneNode(true);
      if (h.conflict) row.classList.add("conflict-row");

      const dot = row.querySelector(".dot");
      if (h.conflict) dot.classList.add("dot-conflict");
      else if (h.method === "tcp") dot.classList.add("dot-tcp");

      row.querySelector(".ip-cell").textContent = h.ip;
      row.querySelector(".hostname-cell").textContent = h.hostname || "";
      row.querySelector(".mac-cell").textContent = h.mac || "";
      row.querySelector(".vendor-cell").textContent = h.vendor && h.vendor !== "Unknown" ? h.vendor : "";

      const osCell = row.querySelector(".os-cell");
      if (h.os && h.os.label && h.os.label !== "Unknown") {
        osCell.textContent = h.os.label;
        if (h.os.confidence) {
          osCell.appendChild(document.createTextNode(" "));
          const conf = document.createElement("span");
          conf.className = "os-confidence";
          conf.textContent = `(${h.os.confidence})`;
          osCell.appendChild(conf);
        }
      } else {
        osCell.textContent = "";
      }

      row.querySelector(".latency-cell").textContent = h.latencyMs ? `${h.latencyMs} ms` : "";
      row.querySelector(".ports-cell").textContent = (h.openPorts && h.openPorts.length) ? h.openPorts.join(", ") : "";

      const flagsCell = row.querySelector(".flags-cell");
      if (h.conflict) {
        const badge = document.createElement("span");
        badge.className = "flag-badge";
        badge.textContent = h.conflictReason === "duplicate-mac" ? "Dup MAC" : "IP Conflict";
        flagsCell.appendChild(badge);
      }

      frag.appendChild(row);
    }
    resultsBody.appendChild(frag);

    emptyState.style.display = hosts.size === 0 ? "flex" : "none";
    table.style.display = hosts.size === 0 ? "none" : "table";
    resultsSummary.textContent = hosts.size ? `${list.length} of ${hosts.size} shown` : "";
    exportBtn.disabled = hosts.size === 0 || !currentScanId;
  }

  searchInput.addEventListener("input", () => {
    filterText = searchInput.value;
    renderTable();
  });

  for (const th of table.querySelectorAll("th.sortable")) {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (sortKey === key) {
        sortDir *= -1;
      } else {
        sortKey = key;
        sortDir = 1;
      }
      for (const other of table.querySelectorAll("th.sortable")) {
        other.classList.remove("sort-asc", "sort-desc");
      }
      th.classList.add(sortDir === 1 ? "sort-asc" : "sort-desc");
      renderTable();
    });
  }

  exportBtn.addEventListener("click", () => {
    if (!currentScanId) return;
    window.location.href = `/api/scan/${currentScanId}/export.csv`;
  });

  // ---------- Tools modal (per-host: OS guess, ping, ports/services, traceroute, WoL, quick links) ----------
  const toolsOverlay = document.getElementById("toolsOverlay");
  const toolsModalTitle = document.getElementById("toolsModalTitle");
  const toolsModalSubtitle = document.getElementById("toolsModalSubtitle");
  const toolsCloseBtn = document.getElementById("toolsCloseBtn");
  const osGuessBody = document.getElementById("osGuessBody");
  const pingRunBtn = document.getElementById("pingRunBtn");
  const pingBody = document.getElementById("pingBody");
  const portScanRunBtn = document.getElementById("portScanRunBtn");
  const portScanBody = document.getElementById("portScanBody");
  const deepScanRunBtn = document.getElementById("deepScanRunBtn");
  const deepScanServiceVersion = document.getElementById("deepScanServiceVersion");
  const deepScanOSDetection = document.getElementById("deepScanOSDetection");
  const deepScanNote = document.getElementById("deepScanNote");
  const deepScanBody = document.getElementById("deepScanBody");
  const tracerouteRunBtn = document.getElementById("tracerouteRunBtn");
  const tracerouteBody = document.getElementById("tracerouteBody");
  const wolRunBtn = document.getElementById("wolRunBtn");
  const wolResult = document.getElementById("wolResult");
  const quickLinksBody = document.getElementById("quickLinksBody");

  let toolHost = null;
  let toolOpenPorts = [];
  let tracerouteSource = null;
  let capabilities = { nmapAvailable: false, isRoot: false };

  async function loadCapabilities() {
    try {
      const res = await fetch("/api/capabilities");
      capabilities = await res.json();
    } catch {
      /* deep scan section just stays disabled */
    }
  }

  resultsBody.addEventListener("click", (e) => {
    const btn = e.target.closest(".tools-btn");
    if (!btn) return;
    const row = btn.closest("tr");
    const ip = row.querySelector(".ip-cell").textContent;
    const host = hosts.get(ip);
    if (host) openToolsModal(host);
  });

  function openToolsModal(host) {
    toolHost = host;
    toolOpenPorts = (host.openPorts || []).slice();

    toolsModalTitle.textContent = host.ip;
    const bits = [];
    if (host.hostname) bits.push(host.hostname);
    if (host.mac) bits.push(host.mac);
    if (host.vendor && host.vendor !== "Unknown") bits.push(host.vendor);
    toolsModalSubtitle.textContent = bits.join(" · ") || "No additional identity information yet";

    renderOSGuess(host.os);
    pingBody.innerHTML = "";
    portScanBody.innerHTML = "";
    tracerouteBody.innerHTML = "";
    deepScanBody.innerHTML = "";
    wolResult.textContent = "";
    wolRunBtn.disabled = !host.mac;
    renderQuickLinks();
    renderDeepScanNote();

    toolsOverlay.hidden = false;
    document.addEventListener("keydown", onModalKeydown);
  }

  function closeToolsModal() {
    toolsOverlay.hidden = true;
    document.removeEventListener("keydown", onModalKeydown);
    if (tracerouteSource) {
      tracerouteSource.close();
      tracerouteSource = null;
    }
    toolHost = null;
  }

  function onModalKeydown(e) {
    if (e.key === "Escape") closeToolsModal();
  }

  toolsCloseBtn.addEventListener("click", closeToolsModal);
  toolsOverlay.addEventListener("click", (e) => {
    if (e.target === toolsOverlay) closeToolsModal();
  });

  function renderOSGuess(os) {
    osGuessBody.innerHTML = "";
    if (!os || !os.label) {
      osGuessBody.innerHTML = '<span class="muted-line">No data yet — this host hasn’t replied to ICMP.</span>';
      return;
    }
    const line = document.createElement("div");
    line.textContent = os.label + " ";
    if (os.confidence) {
      const conf = document.createElement("span");
      conf.className = "os-confidence";
      conf.textContent = `(${os.confidence} confidence)`;
      line.appendChild(conf);
    }
    osGuessBody.appendChild(line);
    if (os.signals && os.signals.length) {
      const ul = document.createElement("ul");
      ul.className = "signal-list";
      for (const s of os.signals) {
        const li = document.createElement("li");
        li.textContent = s;
        ul.appendChild(li);
      }
      osGuessBody.appendChild(ul);
    }
  }

  async function refreshOSGuess() {
    if (!toolHost) return;
    try {
      const res = await fetch("/api/tools/osguess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: toolHost.ip, vendor: toolHost.vendor, openPorts: toolOpenPorts, ttl: toolHost.ttl || 0 }),
      });
      const data = await res.json();
      if (res.ok) renderOSGuess(data.os);
    } catch {
      /* best effort */
    }
  }

  pingRunBtn.addEventListener("click", async () => {
    if (!toolHost) return;
    pingRunBtn.disabled = true;
    pingBody.innerHTML = '<span class="muted-line">Pinging…</span>';
    try {
      const res = await fetch("/api/tools/ping", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: toolHost.ip, count: 4 }),
      });
      const stats = await res.json();
      if (!res.ok) throw new Error(stats.error || `HTTP ${res.status}`);
      renderPingResult(stats);
      if (stats.ttl) {
        toolHost.ttl = stats.ttl;
        await refreshOSGuess();
      }
    } catch (err) {
      pingBody.innerHTML = `<span class="muted-line">Ping failed: ${escapeHtml(err.message)}</span>`;
    } finally {
      pingRunBtn.disabled = false;
    }
  });

  function renderPingResult(stats) {
    if (!stats.received) {
      pingBody.innerHTML = `<span class="muted-line">No replies (${stats.sent} sent, 100% loss)</span>`;
      return;
    }
    pingBody.innerHTML = "";
    const line = document.createElement("div");
    line.className = "mono";
    line.textContent = `min/avg/max ${stats.minMs}/${stats.avgMs}/${stats.maxMs} ms · ${stats.lossPct}% loss (${stats.received}/${stats.sent})`;
    pingBody.appendChild(line);
  }

  portScanRunBtn.addEventListener("click", async () => {
    if (!toolHost) return;
    portScanRunBtn.disabled = true;
    portScanBody.innerHTML = '<span class="muted-line">Scanning ports…</span>';
    try {
      const res = await fetch("/api/tools/portscan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: toolHost.ip }),
      });
      const ports = await res.json();
      if (!res.ok) throw new Error(ports.error || `HTTP ${res.status}`);
      toolOpenPorts = ports.map((p) => p.port);
      renderQuickLinks();
      refreshOSGuess();

      if (ports.length === 0) {
        portScanBody.innerHTML = '<span class="muted-line">No open ports found.</span>';
        return;
      }
      portScanBody.innerHTML = '<span class="muted-line">Identifying services…</span>';
      const svcRes = await fetch("/api/tools/service", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: toolHost.ip, ports: toolOpenPorts.slice(0, 30) }),
      });
      const services = await svcRes.json();
      renderPortTable(svcRes.ok ? services : ports);
    } catch (err) {
      portScanBody.innerHTML = `<span class="muted-line">Port scan failed: ${escapeHtml(err.message)}</span>`;
    } finally {
      portScanRunBtn.disabled = false;
    }
  });

  function renderPortTable(rows) {
    portScanBody.innerHTML = "";
    const table = document.createElement("table");
    table.innerHTML = "<thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>";
    const tbody = document.createElement("tbody");
    for (const r of rows) {
      const tr = document.createElement("tr");
      const tdPort = document.createElement("td");
      tdPort.className = "mono";
      tdPort.textContent = r.port;
      const tdService = document.createElement("td");
      tdService.textContent = r.service || "";
      const tdBanner = document.createElement("td");
      tdBanner.className = "mono";
      tdBanner.textContent = r.banner || (r.tls ? "(TLS)" : "");
      tr.append(tdPort, tdService, tdBanner);
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    portScanBody.appendChild(table);
  }

  tracerouteRunBtn.addEventListener("click", () => {
    if (toolHost) runTraceroute(toolHost.ip);
  });

  async function runTraceroute(ip) {
    tracerouteRunBtn.disabled = true;
    tracerouteBody.innerHTML = "";
    const list = document.createElement("ul");
    list.className = "hop-list";
    tracerouteBody.appendChild(list);

    try {
      const res = await fetch("/api/tools/traceroute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

      if (tracerouteSource) tracerouteSource.close();
      tracerouteSource = new EventSource(`/api/tools/traceroute/${data.id}/stream`);

      tracerouteSource.addEventListener("hop", (evt) => {
        const { hop } = JSON.parse(evt.data);
        const li = document.createElement("li");
        const num = document.createElement("span");
        num.className = "hop-num";
        num.textContent = hop.number;
        const rest = document.createElement("span");
        if (hop.timedOut) {
          rest.className = "hop-timeout";
          rest.textContent = "* * *";
        } else {
          rest.textContent = hop.ip + (hop.rttMs ? `  ${hop.rttMs} ms` : "");
        }
        li.append(num, rest);
        list.appendChild(li);
      });
      tracerouteSource.addEventListener("error", (evt) => {
        try {
          const { error } = JSON.parse(evt.data);
          const li = document.createElement("li");
          li.className = "muted-line";
          li.textContent = "Traceroute failed: " + error;
          list.appendChild(li);
        } catch {
          /* connection-level SSE error, not a traceroute error event */
        }
      });
      tracerouteSource.addEventListener("done", () => {
        tracerouteRunBtn.disabled = false;
        if (tracerouteSource) {
          tracerouteSource.close();
          tracerouteSource = null;
        }
      });
    } catch (err) {
      tracerouteBody.innerHTML = `<span class="muted-line">Traceroute failed: ${escapeHtml(err.message)}</span>`;
      tracerouteRunBtn.disabled = false;
    }
  }

  function renderDeepScanNote() {
    if (!capabilities.nmapAvailable) {
      deepScanNote.textContent = 'nmap isn’t installed — install it with “brew install nmap” to enable real OS fingerprinting and full version detection here.';
      deepScanRunBtn.disabled = true;
      deepScanServiceVersion.disabled = true;
      deepScanOSDetection.disabled = true;
      return;
    }
    deepScanRunBtn.disabled = false;
    deepScanServiceVersion.disabled = false;
    deepScanOSDetection.disabled = false;
    deepScanNote.textContent = capabilities.isRoot
      ? "Running as root — full OS detection is available."
      : 'Not running as root — nmap will likely skip OS detection. Quit and relaunch with "sudo" for it.';
  }

  deepScanRunBtn.addEventListener("click", async () => {
    if (!toolHost || !capabilities.nmapAvailable) return;
    deepScanRunBtn.disabled = true;
    deepScanBody.innerHTML = '<span class="muted-line">Running nmap… this can take up to a minute.</span>';
    try {
      const res = await fetch("/api/tools/deepscan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ip: toolHost.ip,
          serviceVersion: deepScanServiceVersion.checked,
          osDetection: deepScanOSDetection.checked,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      renderDeepScanResult(data);
    } catch (err) {
      deepScanBody.innerHTML = `<span class="muted-line">Deep scan failed: ${escapeHtml(err.message)}</span>`;
    } finally {
      deepScanRunBtn.disabled = false;
    }
  });

  function renderDeepScanResult(result) {
    deepScanBody.innerHTML = "";
    if (result.osMatches && result.osMatches.length) {
      const osDiv = document.createElement("div");
      osDiv.className = "mono";
      osDiv.textContent = "OS: " + result.osMatches.map((m) => `${m.name} (${m.accuracy}%)`).join(" / ");
      deepScanBody.appendChild(osDiv);
    }
    if (result.ports && result.ports.length) {
      const table = document.createElement("table");
      table.innerHTML = "<thead><tr><th>Port</th><th>Service</th><th>Product / version</th></tr></thead>";
      const tbody = document.createElement("tbody");
      for (const p of result.ports) {
        const tr = document.createElement("tr");
        const tdPort = document.createElement("td");
        tdPort.className = "mono";
        tdPort.textContent = `${p.port}/${p.protocol}`;
        const tdService = document.createElement("td");
        tdService.textContent = p.service || "";
        const tdVersion = document.createElement("td");
        tdVersion.textContent = [p.product, p.version, p.extraInfo].filter(Boolean).join(" ");
        tr.append(tdPort, tdService, tdVersion);
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      deepScanBody.appendChild(table);
    }
    if (!deepScanBody.children.length) {
      deepScanBody.innerHTML = '<span class="muted-line">nmap found nothing to report.</span>';
    }
  }

  wolRunBtn.addEventListener("click", async () => {
    if (!toolHost || !toolHost.mac) return;
    wolRunBtn.disabled = true;
    wolResult.textContent = "Sending…";
    try {
      const res = await fetch("/api/tools/wol", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mac: toolHost.mac, cidr: cidrInput.value.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      wolResult.textContent = "Magic packet sent.";
    } catch (err) {
      wolResult.textContent = "Failed: " + err.message;
    } finally {
      wolRunBtn.disabled = false;
    }
  });

  function renderQuickLinks() {
    quickLinksBody.innerHTML = "";
    if (!toolHost) return;
    const ip = toolHost.ip;
    const ports = new Set(toolOpenPorts);
    const links = [];
    if (ports.has(445) || ports.has(139)) links.push(["Open shared folder", `smb://${ip}`]);
    if (ports.has(548)) links.push(["Open shared folder (AFP)", `afp://${ip}`]);
    if (ports.has(631) || ports.has(9100) || ports.has(515)) {
      links.push(["Open printer", `http://${ip}:${ports.has(631) ? 631 : 80}`]);
    }
    if (ports.has(3389)) links.push(["Remote Desktop", `rdp://${ip}`]);
    if (ports.has(5900) || ports.has(5901)) links.push(["VNC / Screen Sharing", `vnc://${ip}`]);
    if (ports.has(22)) links.push(["SSH", `ssh://${ip}`]);
    if (ports.has(443)) links.push(["HTTPS admin page", `https://${ip}`]);
    else if (ports.has(80) || ports.has(8080)) links.push(["HTTP admin page", `http://${ip}${ports.has(80) ? "" : ":8080"}`]);

    if (links.length === 0) {
      quickLinksBody.innerHTML = '<span class="muted-line">Run a port scan to surface quick-open links (shared folders, printers, remote desktop…).</span>';
      return;
    }
    for (const [label, href] of links) {
      const a = document.createElement("a");
      a.href = href;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = label;
      quickLinksBody.appendChild(a);
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ---------- Init ----------
  setScanState("idle");
  renderTable();
  loadInterfaces();
  loadCapabilities();
})();
