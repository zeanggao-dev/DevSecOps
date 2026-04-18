async function api(path, method = "GET", body = null) {
  const opts = { method, headers: { "Accept": "application/json" } };
  if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json();
  return { status: res.status, ok: res.ok, data };
}

function showJson(nodeId, obj) {
  const n = document.getElementById(nodeId);
  if (!n) {
    return;
  }
  n.textContent = JSON.stringify(obj, null, 2);
}

function setBanner(nodeId, blocked, text) {
  const n = document.getElementById(nodeId);
  if (!n) {
    return;
  }
  n.className = blocked ? "banner blocked" : "banner allowed";
  n.textContent = text;
}

async function loadControls(nodeId) {
  const r = await api("/api/controls");
  showJson(nodeId, r.data);
  return r.data;
}

async function runSuite(suite, outputNode) {
  const sourceVm = document.getElementById("sourceVm")?.value || "attacker-vm";
  const r = await api("/api/execute", "POST", { test_type: suite, source_vm: sourceVm });
  showJson(outputNode, r.data);
}

async function simulateSqli() {
  const sourceVm = document.getElementById("sourceVm")?.value || "attacker-vm";
  const q = document.getElementById("sqliInput").value;
  const r = await api(`/demo/search?q=${encodeURIComponent(q)}&source_vm=${encodeURIComponent(sourceVm)}`);
  showJson("attackOutput", r.data);
  setBanner("attackBanner", r.status === 403 || r.data.blocked, r.status === 403 ? "Blocked by security controls (WAF/IPS enforce)" : "Request allowed by policy (demo vulnerable behavior visible)");
}

async function simulateTraversal() {
  const sourceVm = document.getElementById("sourceVm")?.value || "attacker-vm";
  const p = document.getElementById("traversalInput").value;
  const r = await api(`/demo/file?path=${encodeURIComponent(p)}&source_vm=${encodeURIComponent(sourceVm)}`);
  showJson("attackOutput", r.data);
  setBanner("attackBanner", r.status === 403 || r.data.blocked, r.status === 403 ? "Traversal blocked by security controls" : "Traversal allowed in demo path");
}

async function updateControl(name) {
  const mode = document.getElementById(`mode_${name}`).value;
  const enabled = mode !== "disabled";
  const realMode = mode === "disabled" ? "detect" : mode;
  const r = await api("/api/control/update", "POST", { control: name, enabled, mode: realMode });
  showJson("controlOutput", r.data);
  await loadControlTable();
}

async function loadControlTable() {
  const res = await api("/api/controls");
  const controls = res.data.controls || {};
  const tbody = document.getElementById("controlRows");
  if (!tbody) {
    return;
  }
  tbody.innerHTML = "";
  Object.keys(controls).forEach((k) => {
    const c = controls[k];
    const tr = document.createElement("tr");
    const mode = c.enabled ? c.mode : "disabled";
    tr.innerHTML = `<td>${k}</td><td>${c.enabled}</td><td>${c.mode}</td><td><select id="mode_${k}"><option value="enforce">enforce</option><option value="detect">detect</option><option value="disabled">disabled</option></select></td><td><button onclick="updateControl('${k}')">Apply</button></td>`;
    tbody.appendChild(tr);
    const sel = document.getElementById(`mode_${k}`);
    if (sel) {
      sel.value = mode;
    }
  });
}

async function loadDashboard() {
  const health = await api("/api/health");
  const report = await api("/api/report");
  const events = await api("/api/events?limit=15");

  document.getElementById("serviceState").textContent = health.data.status || "unknown";
  document.getElementById("kpiTests").textContent = String(report.data.total_tests || 0);
  document.getElementById("kpiBlocked").textContent = String(report.data.total_blocked || 0);
  document.getElementById("kpiDetected").textContent = String(report.data.total_detected || 0);
  showJson("eventsFeed", events.data);
}

async function loadEvents() {
  const ev = await api("/api/events?limit=100");
  showJson("eventsOutput", ev.data);
}
