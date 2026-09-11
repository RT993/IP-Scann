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

  // ---------- Init ----------
  setScanState("idle");
  renderTable();
  loadInterfaces();
})();
