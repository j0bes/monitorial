const RISKY_PORTS = {
  21: "credentials transmitted in cleartext",
  23: "unencrypted traffic",
  135: "Windows attack surface (RPC)",
  139: "legacy file sharing (NetBIOS)",
  445: "frequent ransomware target (SMB)",
  3389: "remote desktop, brute-force target",
  5900: "often poorly secured desktop access",
  6379: "often configured without authentication",
  27017: "often configured without authentication",
};

async function startScan() {
    const btn = document.getElementById("btn-scan");
    btn.disabled = true;
    document.getElementById("progress-fill").style.width = `0%`
    document.getElementById("progress-label").textContent = "starting";
    const res = await fetch("/api/scan", {
        method: 'POST',
        headers: {"Content-Type": "application/json"}
    })
    const data = await res.json()
    console.log("Scan started: " + data.scan_id)

    progressBar(data)
}

async function progressBar(data){
    const label = document.getElementById("progress-label");
    const btn = document.getElementById("btn-scan");

    const stop = (text) => {
        clearInterval(interval);
        label.textContent = text;
        btn.disabled = false;
    };

    const interval = setInterval(async () => {
        try {
            const call = await fetch(`/api/scan/${data.scan_id}/progress`);
            if (!call.ok) throw new Error(`HTTP ${call.status}`);
            const p = await call.json();

            const pct = Math.floor(p.percentage);
            document.getElementById("progress-fill").style.width = `${pct}%`;
            label.textContent = `${pct}%`;

            if (p.status === "failed") return stop("failed");

            if (p.done) {
                document.getElementById("progress-fill").style.width = "100%";
                clearInterval(interval);
                await refreshHistory();
                await loadScan(data.scan_id);
                stop("done");
            }
        } catch (err) {
            console.error(err);
            stop("error");
        }
    }, 2000);
}

const ipToNum = (ip) => ip.split(".").reduce((n, o) => n * 256 + Number(o), 0);

const COMMON_SERVICES = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
  110: "pop3", 123: "ntp", 139: "netbios-ssn", 143: "imap", 443: "https",
  445: "smb", 993: "imaps", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
  8080: "http-alt", 8443: "https-alt",  135: "msrpc", 5900: "vnc", 6379: "redis", 27017: "mongodb",
};

function normalizePorts(ports) {
  return Object.entries(ports || {})
    .map(([port, info]) => {
      const num = Number(port);
      const guess = COMMON_SERVICES[num];
      const name = info?.service ?? (guess ? `${guess}?` : "-");
      const detail = [info?.product, info?.version].filter(Boolean).join(" ");
      return {
        port: num,
        protocol: info?.protocol ?? "tcp",
        service: detail ? `${name} (${detail})` : name,
      };
    })
    .sort((a, b) => a.port - b.port);
}

const modal = document.getElementById("host-modal");
const hostsBody = document.getElementById("hosts-body");
let currentHosts = []; // rempli par loadScan()
const riskBody = document.getElementById("risk-body");
const plural = (n) => (n > 1 ? "s" : "");

function renderRisks(hosts) {
  riskBody.replaceChildren();
  let hostCount = 0;
  let portCount = 0;

  for (const host of hosts) {
    const risky = host.ports.filter((p) => RISKY_PORTS[p.port]);
    if (risky.length === 0) continue;
    hostCount++;

    risky.forEach((p, i) => {
      portCount++;
      const tr = document.createElement("tr");
      tr.dataset.ip = host.ip;
      tr.tabIndex = 0;

      const machine = document.createElement("td");
      machine.className = "host__ip";
      if (i === 0) { // la machine n'apparaît que sur la première ligne de son groupe
        machine.textContent = host.hostname ? `${host.ip} (${host.hostname})` : host.ip;
      }

      const portCell = document.createElement("td");
      const chip = document.createElement("span");
      chip.className = "port port--risk";
      chip.textContent = p.port;
      portCell.append(chip);

      if (p.isNew) portCell.append(newBadge());

      const service = document.createElement("td");
      service.textContent = p.service;

      const why = document.createElement("td");
      why.textContent = RISKY_PORTS[p.port];

      tr.append(machine, portCell, service, why);
      riskBody.append(tr);
    });
  }

  const empty = document.getElementById("risk-empty");
  empty.textContent = hosts.length ? "no risky port detected" : "empty";
  empty.hidden = portCount > 0;
  document.getElementById("risk-wrap").hidden = portCount === 0;
  document.getElementById("security-meta").textContent = portCount
    ? `${portCount} port${plural(portCount)}, ${hostCount} machine${plural(hostCount)}`
    : "-";
}

// Clic ou Entrée sur une ligne : ouvre la carte de la machine
riskBody.addEventListener("click", openFromRow);
riskBody.addEventListener("keydown", (e) => {
  if (e.key === "Enter") openFromRow(e);
});

function openHostModal(host) {
  document.getElementById("modal-title").textContent = host.hostname || host.ip;
  document.getElementById("modal-ip").textContent = host.hostname ? host.ip : "hostname inconnu";
  document.getElementById("modal-mac").textContent = host.mac ? host.mac.toUpperCase() : "-";

  const tbody = document.getElementById("modal-ports");
  tbody.replaceChildren();

  if (host.ports.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.className = "muted";
    td.textContent = "no open ports";
    tr.append(td);
    tbody.append(tr);
  }

  for (const p of host.ports) {
    const tr = document.createElement("tr");
    const risk = RISKY_PORTS[p.port];
    if (risk) {
      tr.classList.add("is-risky");
      tr.title = risk;
    }
    for (const value of [p.port, p.protocol, p.service]) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    tbody.append(tr);
  }

  modal.showModal();
}

// Ouverture : clic ou Entrée sur une ligne du tableau
function openFromRow(e) {
  const row = e.target.closest("tr[data-ip]");
  if (!row) return;
  const host = currentHosts.find((h) => h.ip === row.dataset.ip);
  if (host) openHostModal(host);
}

hostsBody.addEventListener("click", openFromRow);
hostsBody.addEventListener("keydown", (e) => {
  if (e.key === "Enter") openFromRow(e);
});

// Fermeture : bouton, clic sur le fond flouté (Échap est géré nativement)
document.getElementById("modal-close").addEventListener("click", () => modal.close());
modal.addEventListener("click", (e) => {
  if (e.target === modal) modal.close();
});

function renderHosts(hosts) {
  const tbody = document.getElementById("hosts-body");
  const tplRow = document.getElementById("tpl-host-row");
  const tplPort = document.getElementById("tpl-port");

  tbody.replaceChildren(); // supprime aussi les lignes d'exemple

  for (const host of hosts) {
    const row = tplRow.content.firstElementChild.cloneNode(true);
    row.dataset.ip = host.ip;
    const ipCell = row.querySelector(".host__ip");
    ipCell.textContent = host.ip;
    if (host.isNew) ipCell.append(newBadge());

    const name = row.querySelector(".host__name");
    name.textContent = host.hostname || "-";
    name.classList.toggle("muted", !host.hostname);

    const cell = row.querySelector(".host__ports");
    if (host.ports.length === 0) {
      cell.textContent = "-";
      cell.classList.add("muted");
    }
    for (const p of host.ports) {
      const chip = tplPort.content.firstElementChild.cloneNode(true);
      chip.textContent = p.port;
      cell.append(chip);
    }

    tbody.append(row);
  }

  document.getElementById("hosts-empty").hidden = hosts.length > 0;
}

function renderStats(data, hosts) {
  const portCount = hosts.reduce((n, h) => n + h.ports.length, 0);

  document.getElementById("stat-machines").textContent = hosts.length;
  document.getElementById("stat-ports").textContent = portCount;
  document.getElementById("stat-date").textContent = formatDate(data.timestamp);
  document.getElementById("hosts-meta").textContent = `scan #${data.id}`;
}

async function fetchScan(scanId) {
  const res = await fetch(`/api/scan/${scanId}/hosts`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();

  const hosts = Object.entries(data.hosts)
    .map(([ip, h]) => ({
      ip,
      hostname: h.hostname,
      mac: h.mac,
      ports: normalizePorts(h.ports),
    }))
    .sort((a, b) => ipToNum(a.ip) - ipToNum(b.ip));

  return { data, hosts };
}

// id du scan juste avant celui-ci dans l'historique (le plus récent en premier)
function previousScanId(scanId) {
  const i = historyScans.findIndex((s) => String(s.id) === String(scanId));
  return i >= 0 && historyScans[i + 1] ? historyScans[i + 1].id : null;
}

// une machine est identifiée par son MAC, ou son IP si le MAC est absent
const hostKey = (h) => h.mac || h.ip;

function markNew(hosts, prevHosts) {
  if (!prevHosts) return; // pas de scan précédent : aucun tag
  const before = new Map(
    prevHosts.map((h) => [hostKey(h), new Set(h.ports.map((p) => p.port))])
  );
  for (const h of hosts) {
    const known = before.get(hostKey(h));
    h.isNew = !known;
    for (const p of h.ports) p.isNew = !known || !known.has(p.port);
  }
}

function newBadge() {
  const b = document.createElement("span");
  b.className = "tag-new";
  b.textContent = "new";
  return b;
}

async function loadScan(scanId) {
  const { data, hosts } = await fetchScan(scanId);

  // l'échec du scan précédent ne doit pas bloquer l'affichage
  const prevId = previousScanId(data.id);
  let prevHosts = null;
  if (prevId) {
    try {
      prevHosts = (await fetchScan(prevId)).hosts;
    } catch (err) {
      console.error(err);
    }
  }
  markNew(hosts, prevHosts);

  currentHosts = hosts;
  renderHosts(currentHosts);
  renderRisks(currentHosts);
  renderStats(data, currentHosts);

  currentScanId = String(data.id);
  currentTimestamp = data.timestamp;
  exportBtn.disabled = false;
  localStorage.setItem(STORAGE_KEY, currentScanId);
  highlightActive();
}

const STORAGE_KEY = "monitorial:current-scan";
const historyList = document.getElementById("history-list");
let currentScanId = null;
let historyScans = [];

function formatDate(ts) {
  return new Date(ts).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}

function highlightActive() {
  for (const btn of historyList.querySelectorAll(".history-item")) {
    const active = btn.dataset.scanId === String(currentScanId);
    btn.classList.toggle("is-active", active);
    if (active) btn.setAttribute("aria-current", "true");
    else btn.removeAttribute("aria-current");
  }
}

function renderHistory(scans) {
  const tpl = document.getElementById("tpl-history-item");
  historyList.replaceChildren(); // supprime aussi les items d'exemple

  for (const s of scans) {
    const item = tpl.content.firstElementChild.cloneNode(true);
    item.querySelector(".history-item").dataset.scanId = s.id;
    item.querySelector(".history-item__date").textContent = formatDate(s.timestamp);
    item.querySelector(".history-item__meta").textContent = `scan #${s.id}`;
    historyList.append(item);
  }

  document.getElementById("history-empty").hidden = scans.length > 0;
  highlightActive();
}

async function refreshHistory() {
  const res = await fetch("/api/scans");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  historyScans = await res.json(); // le plus récent en premier
  renderHistory(historyScans);
  return historyScans;
}

function resetView() {
  currentHosts = [];
  currentScanId = null;
  exportBtn.disabled = true;
  renderHosts([]);
  renderRisks([]); // vide le tableau et affiche "aucune donnée"
  document.getElementById("stat-machines").textContent = 0;
  document.getElementById("stat-ports").textContent = 0;
  document.getElementById("stat-date").textContent = "-";
  document.getElementById("hosts-meta").textContent = "-";
}

// Clic sur un scan de l'historique
historyList.addEventListener("click", (e) => {
  const btn = e.target.closest(".history-item");
  if (btn) loadScan(btn.dataset.scanId).catch(console.error);
});

// Boutons de la top bar
document.getElementById("btn-scan").addEventListener("click", startScan);
document.getElementById("btn-last").addEventListener("click", () => {
  if (historyScans[0]) loadScan(historyScans[0].id).catch(console.error);
});

// Démarrage : scan mémorisé s'il existe encore, sinon le plus récent, sinon "aucune donnée"
async function init() {
  try {
    const scans = await refreshHistory();
    const saved = localStorage.getItem(STORAGE_KEY);
    const target = scans.find((s) => String(s.id) === saved) ?? scans[0];
    if (!target) return resetView();
    await loadScan(target.id);
  } catch (err) {
    console.error(err);
    resetView();
  }
}

let currentTimestamp = null;
const exportBtn = document.getElementById("btn-export");

function exportJson() {
  if (currentScanId === null) return;

  const payload = {
    scan_id: currentScanId,
    timestamp: currentTimestamp,
    hosts: currentHosts.map(({ ip, hostname, mac, ports }) => ({
      ip,
      hostname,
      mac,
      ports: ports.map(({ port, protocol, service }) => ({ port, protocol, service })),
    })),
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `monit-scan-${currentScanId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

exportBtn.addEventListener("click", exportJson);

init();