const API_URL = window.PHISHGUARD_API_URL;
const pages = [...document.querySelectorAll(".page")];
const navItems = [...document.querySelectorAll(".nav-item")];
const sidebar = document.getElementById("sidebar");
const modal = document.getElementById("modal");
let csrfToken = "";
let historyData = [];
let bulkData = [];
let settings = {};
let historyTimer;
let notificationData = [];

const titles = {
  dashboard: "Dashboard", scanner: "URL Scanner", analytics: "Analytics",
  threats: "Threat Intelligence", history: "Scan History", bulk: "Bulk Scanner",
  reports: "Reports", model: "Analysis Method", users: "Account", settings: "Settings"
};

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  headers.set("Accept", "application/json");
  const response = await fetch(`${API_URL}${path}`, {
    ...options, method, headers, credentials: "include"
  });
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body = await response.json();
      message = body.error || message;
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
    if (response.status === 401) window.location.href = "index.html";
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

function toast(title = "Done", text = "Your changes have been saved.") {
  const node = document.getElementById("toast");
  document.getElementById("toastTitle").textContent = title;
  document.getElementById("toastText").textContent = text;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 3500);
}

function showPage(name) {
  if (!titles[name]) return;
  pages.forEach(page => page.classList.toggle("active", page.id === `page-${name}`));
  navItems.forEach(item => item.classList.toggle("active", item.dataset.page === name));
  document.getElementById("pageTitle").textContent = titles[name];
  sidebar.classList.remove("open");
  document.body.classList.remove("sidebar-open");
  const menuButton = document.getElementById("menuBtn");
  menuButton?.setAttribute("aria-expanded", "false");
  menuButton?.setAttribute("aria-label", "Open navigation menu");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

navItems.forEach(item => item.addEventListener("click", () => showPage(item.dataset.page)));
document.querySelectorAll("[data-page-target]").forEach(element =>
  element.addEventListener("click", () => showPage(element.dataset.pageTarget)));
document.getElementById("menuBtn")?.addEventListener("click", event => {
  const isOpen = sidebar.classList.toggle("open");
  document.body.classList.toggle("sidebar-open", isOpen);
  event.currentTarget.setAttribute("aria-expanded", String(isOpen));
  event.currentTarget.setAttribute("aria-label", isOpen ? "Close navigation menu" : "Open navigation menu");
});
document.body.addEventListener("click", event => {
  if (!sidebar.classList.contains("open") || sidebar.contains(event.target) ||
      event.target.closest("#menuBtn")) return;
  sidebar.classList.remove("open");
  document.body.classList.remove("sidebar-open");
  const menuButton = document.getElementById("menuBtn");
  menuButton.setAttribute("aria-expanded", "false");
  menuButton.setAttribute("aria-label", "Open navigation menu");
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && sidebar.classList.contains("open")) {
    sidebar.classList.remove("open");
    document.body.classList.remove("sidebar-open");
    const menuButton = document.getElementById("menuBtn");
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.setAttribute("aria-label", "Open navigation menu");
  }
});

function resultLabel(result) {
  return {
    safe: "Safe",
    phishing: "Phishing",
    malicious: "Malicious"
  }[result] || result;
}

function badgeClass(result) {
  if (result === "safe") return "green";
  if (result === "malicious") return "red";
  return "yellow";
}

function addCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value == null ? "" : String(value);
  if (className) cell.className = className;
  row.appendChild(cell);
  return cell;
}

function createBadge(result) {
  const badge = document.createElement("span");
  badge.className = `badge ${badgeClass(result)}`;
  badge.textContent = resultLabel(result);
  return badge;
}

function openModal(title, message, actions = []) {
  const content = document.getElementById("modalContent");
  content.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = title;
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  content.append(heading, paragraph);
  for (const action of actions) {
    const button = document.createElement("button");
    button.className = action.className || "secondary-btn";
    button.textContent = action.label;
    button.addEventListener("click", action.onClick);
    content.appendChild(button);
  }
  modal.classList.remove("hidden");
}

function closeModal() {
  modal.classList.add("hidden");
}

document.getElementById("modalClose").addEventListener("click", closeModal);
modal.addEventListener("click", event => {
  if (event.target === modal) closeModal();
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape") closeModal();
});

function formatDate(value) {
  const date = new Date(`${value.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderHistory(rows = historyData) {
  const body = document.querySelector("#historyTable tbody");
  if (!body) return;
  body.replaceChildren();
  if (!rows.length) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 6;
    cell.textContent = "No scans match these filters yet.";
    return;
  }
  for (const scan of rows) {
    const row = body.insertRow();
    addCell(row, scan.url, "url-cell");
    row.insertCell().appendChild(createBadge(scan.result));
    addCell(row, `${scan.risk_score}/100`);
    addCell(row, formatDate(scan.created_at));
    const action = row.insertCell();
    const view = document.createElement("button");
    view.className = "text-btn";
    view.textContent = "Details";
    view.addEventListener("click", () => showScanDetails(scan));
    action.appendChild(view);
  }
}

function showScanDetails(scan) {
  const content = document.getElementById("modalContent");
  content.replaceChildren();
  const title = document.createElement("h2");
  title.textContent = `${resultLabel(scan.result)} · Risk ${scan.risk_score}/100`;
  const url = document.createElement("p");
  url.textContent = scan.url;
  url.className = "detail-url";
  const list = document.createElement("ul");
  for (const signal of scan.signals || []) {
    const item = document.createElement("li");
    item.textContent = signal;
    list.appendChild(item);
  }
  const remove = document.createElement("button");
  remove.className = "secondary-btn danger-btn";
  remove.textContent = "Delete scan";
  remove.addEventListener("click", async () => {
    try {
      await api(`/history/${scan.id}`, { method: "DELETE" });
      closeModal();
      await refreshData();
      toast("Scan deleted", "The record was removed from your history.");
    } catch (error) {
      toast("Could not delete scan", error.message);
    }
  });
  const close = document.createElement("button");
  close.className = "primary-btn";
  close.textContent = "Close";
  close.addEventListener("click", closeModal);
  content.append(title, url, list, remove, close);
  modal.classList.remove("hidden");
}

function historySearchRefresh() {
  clearTimeout(historyTimer);
  historyTimer = setTimeout(() => loadHistory().catch(error =>
    toast("History search failed", error.message)), 180);
}

async function loadHistory(append = false) {
  const filters = document.querySelectorAll("#page-history .filter");
  const offset = append ? historyData.length : 0;
  const params = new URLSearchParams({
    limit: "100",
    offset: String(offset),
    q: document.getElementById("historySearch").value.trim()
  });
  if (filters[0].value !== "All Results") {
    params.set("result", {
      Safe: "safe",
      Phishing: "phishing",
      Malicious: "malicious"
    }[filters[0].value]);
  }
  const days = { Today: "1", "7 Days": "7", "30 Days": "30" }[filters[1].value];
  if (days) params.set("days", days);
  const data = await api(`/history?${params}`);
  historyData = append ? historyData.concat(data.scans) : data.scans;
  renderHistory(historyData);
  document.getElementById("historyCount").textContent =
    `Showing ${historyData.length} of ${data.total} scans`;
  document.getElementById("loadMoreHistory").classList.toggle("hidden", historyData.length >= data.total);
}

function setStat(card, value, caption) {
  card.querySelector("strong").textContent = Number(value || 0).toLocaleString();
  const small = card.querySelector("small");
  if (small) small.textContent = caption;
}

function renderAnalytics(data) {
  const summary = data.summary;
  const total = summary.total || 0;
  const stats = document.querySelectorAll("#page-dashboard .stat-card");
  setStat(stats[0], total, "Your saved URL scans");
  setStat(stats[1], summary.safe, "Low-risk URL patterns");
  setStat(stats[2], summary.phishing, "Moderate-risk URL patterns");
  setStat(stats[3], summary.malicious, "High-risk URL patterns");

  const classified = total || 1;
  const safePercent = (summary.safe || 0) * 100 / classified;
  const phishingPercent = (summary.phishing || 0) * 100 / classified;
  const donut = document.querySelector(".donut");
  donut.style.background = `conic-gradient(var(--green) 0 ${safePercent}%, var(--orange) ${safePercent}% ${safePercent + phishingPercent}%, var(--red) ${safePercent + phishingPercent}% 100%)`;
  document.querySelector(".donut strong").textContent = `${total ? Math.round(safePercent) : 0}%`;
  document.querySelector(".legend").replaceChildren();
  [
    ["Safe", summary.safe, "safe"],
    ["Phishing", summary.phishing, "phish"],
    ["Malicious", summary.malicious, "malicious"]
  ].forEach(([label, count, color]) => {
    const item = document.createElement("span");
    const dot = document.createElement("i");
    dot.className = `dot ${color}`;
    const value = document.createElement("b");
    value.textContent = `${count || 0} · ${Math.round((count || 0) * 100 / classified)}%`;
    item.append(dot, ` ${label} `, value);
    document.querySelector(".legend").appendChild(item);
  });

  const chart = document.getElementById("activityChart");
  const max = Math.max(1, ...data.activity.map(day => day.total));
  chart.replaceChildren();
  data.activity.forEach(day => {
    const column = document.createElement("div");
    column.className = "bar-col";
    const bar = document.createElement("i");
    bar.style.height = `${Math.max(3, day.total * 100 / max)}%`;
    bar.title = `${day.total} scans · ${day.threats} flagged`;
    const label = document.createElement("span");
    const date = new Date(`${day.day}T12:00:00`);
    label.textContent = data.activity.length > 7 ? date.getDate() : date.toLocaleDateString(undefined, { weekday: "short" });
    label.title = date.toLocaleDateString();
    column.append(bar, label);
    chart.appendChild(column);
  });

  const analyticsStats = document.querySelectorAll("#page-analytics .stat-card");
  const detected = (summary.phishing || 0) + (summary.malicious || 0);
  analyticsStats[0].querySelector("strong").textContent = `${total ? Math.round(detected * 100 / total) : 0}%`;
  analyticsStats[0].querySelector("small").textContent = `${detected} flagged scans`;
  analyticsStats[1].querySelector("strong").textContent = `${summary.average_risk || 0}`;
  analyticsStats[1].querySelector("small").textContent = "Average risk score / 100";
  analyticsStats[2].querySelector("strong").textContent = `${total}`;
  analyticsStats[2].querySelector("small").textContent = "Saved scans analyzed";
  analyticsStats[3].querySelector("strong").textContent = "Local";
  analyticsStats[3].querySelector("small").textContent = "Heuristic URL checks";

  const recent = document.querySelector(".threat-list");
  recent.replaceChildren();
  const threats = data.recent_threats;
  if (!threats.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No flagged URLs in your scan history.";
    recent.appendChild(empty);
  }
  threats.slice(0, 5).forEach(scan => {
    const row = document.createElement("div");
    row.className = "threat-row";
    const marker = document.createElement("span");
    marker.className = `threat-icon ${scan.result === "malicious" ? "red-bg" : "orange-bg"}`;
    marker.textContent = "!";
    const details = document.createElement("div");
    const domain = document.createElement("b");
    domain.textContent = scan.url;
    const date = document.createElement("small");
    date.textContent = `${resultLabel(scan.result)} · ${formatDate(scan.created_at)}`;
    const risk = document.createElement("strong");
    risk.className = "risk high";
    risk.textContent = scan.risk_score;
    details.append(domain, date);
    row.append(marker, details, risk);
    recent.appendChild(row);
  });

  const alertCount = document.getElementById("notificationCount");
  notificationData = threats;
  alertCount.textContent = threats.length;
  alertCount.classList.toggle("hidden", threats.length === 0);
  renderThreatSignals(summary);
  document.getElementById("reportTotal").textContent = total.toLocaleString();
  document.getElementById("reportFlagged").textContent = detected.toLocaleString();
  document.getElementById("reportRisk").textContent = `${summary.average_risk || 0}/100`;
  renderAnalyticsCharts(data);
}

function renderAnalyticsCharts(data) {
  const days = data.activity;
  const max = Math.max(1, ...days.map(day => day.threats));
  const points = days.map((day, index) =>
    `${days.length === 1 ? 350 : index * 700 / (days.length - 1)},${220 - day.threats * 180 / max}`).join(" ");
  const svg = document.querySelector(".line-chart svg");
  svg.replaceChildren();
  const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  line.setAttribute("points", points);
  line.setAttribute("fill", "none");
  line.setAttribute("stroke", "currentColor");
  line.setAttribute("stroke-width", "4");
  svg.appendChild(line);

  const summary = data.summary;
  const total = Math.max(1, summary.total || 0);
  const bars = document.querySelectorAll(".horizontal-bars > div");
  const categories = [
    ["Safe", summary.safe || 0],
    ["Phishing", summary.phishing || 0],
    ["Malicious", summary.malicious || 0]
  ];
  bars.forEach((bar, index) => {
    const [label, count] = categories[index];
    bar.querySelector("span").textContent = label;
    bar.querySelector("b").textContent = count;
    bar.querySelector("i").style.width = `${count * 100 / total}%`;
  });
}

function renderThreatSignals(summary) {
  const table = document.querySelector("#page-threats .source-table");
  if (!table) return;
  table.replaceChildren();
  const entries = [
    ["URL pattern analysis", "On-device service", `${summary.total} scans`, "Heuristic signals"],
    ["Phishing feed", "Not connected", "—", "No external data"],
    ["Malware feed", "Not connected", "—", "No external data"]
  ];
  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "source-row";
    entry.forEach(value => {
      const cell = document.createElement("span");
      cell.textContent = value;
      row.appendChild(cell);
    });
    table.appendChild(row);
  }
}

function selectedActivityDays() {
  return document.querySelector(".select-small")?.value === "Last 30 days" ? 30 : 7;
}

async function refreshData() {
  const selectedDays = selectedActivityDays();
  const [analytics] = await Promise.all([
    api(`/analytics?days=${selectedDays}`), loadHistory()
  ]);
  renderAnalytics(analytics);
}

async function loadSettings() {
  const data = await api("/settings");
  settings = data.settings;
  document.querySelectorAll(".toggle-row input").forEach((input, index) =>
    input.checked = Boolean(settings[toggleKeys[index]]));
}

function paintScan(scan) {
  const box = document.getElementById("scanResult");
  box.classList.remove("hidden");
  document.getElementById("resultLabel").textContent = resultLabel(scan.result).toUpperCase();
  document.getElementById("resultLabel").style.color =
    scan.result === "malicious" ? "var(--red)" : scan.result === "phishing" ? "var(--orange)" : "var(--green)";
  document.getElementById("resultUrl").textContent = scan.url;
  document.getElementById("scoreValue").textContent = scan.risk_score;
  const color = scan.result === "malicious" ? "var(--red)" : scan.result === "phishing" ? "var(--orange)" : "var(--green)";
  document.getElementById("scoreRing").style.background =
    `conic-gradient(${color} 0 ${scan.risk_score}%, var(--border) ${scan.risk_score}% 100%)`;
  document.getElementById("domainRep").textContent = resultLabel(scan.result);
  document.getElementById("protocolResult").textContent = scan.protocol || "—";
  const signals = document.getElementById("signalList");
  signals.replaceChildren();
  (scan.signals || []).forEach(text => {
    const item = document.createElement("div");
    item.className = `signal ${scan.risk_score >= 30 ? "warn" : "safe-signal"}`;
    item.textContent = text;
    signals.appendChild(item);
  });
  const recommendation = document.querySelector(".recommendation p");
  recommendation.textContent = scan.risk_score >= 30
    ? "Avoid entering credentials or downloading files. Verify the domain through an official source."
    : "No configured URL-pattern warnings were found. This heuristic check cannot guarantee a URL is safe.";
}

async function runScan(value) {
  const url = value.trim();
  const progress = document.getElementById("scanProgress");
  if (!url) {
    toast("Enter a URL", "Add a URL before starting a scan.");
    return;
  }
  progress.classList.remove("hidden");
  document.getElementById("scanResult").classList.add("hidden");
  document.getElementById("progressText").textContent = "Checking URL structure and risk signals";
  document.getElementById("progressPercent").textContent = "…";
  try {
    const scan = await api("/scan", { method: "POST", body: JSON.stringify({ url }) });
    paintScan(scan);
    await refreshData();
    toast("Scan complete", `${resultLabel(scan.result)} · risk ${scan.risk_score}/100${scan.saved ? " · saved to history" : " · history storage is off"}.`);
  } catch (error) {
    toast("Scan failed", error.message);
  } finally {
    progress.classList.add("hidden");
  }
}

document.getElementById("scanBtn")?.addEventListener("click", () =>
  runScan(document.getElementById("scannerUrl").value));
document.getElementById("scannerUrl")?.addEventListener("keydown", event => {
  if (event.key === "Enter") runScan(event.currentTarget.value);
});
document.getElementById("quickScan")?.addEventListener("click", () => {
  const value = document.getElementById("quickUrl").value;
  showPage("scanner");
  document.getElementById("scannerUrl").value = value;
  runScan(value);
});
document.getElementById("quickUrl")?.addEventListener("keydown", event => {
  if (event.key === "Enter") document.getElementById("quickScan").click();
});

document.getElementById("historySearch")?.addEventListener("input", historySearchRefresh);
document.querySelectorAll("#page-history .filter").forEach(filter =>
  filter.addEventListener("change", historySearchRefresh));
document.getElementById("loadMoreHistory")?.addEventListener("click", async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await loadHistory(true);
  } catch (error) {
    toast("Could not load older scans", error.message);
  } finally {
    button.disabled = false;
  }
});
document.getElementById("clearHistory")?.addEventListener("click", async () => {
  if (!historyData.length || !confirm("Permanently delete all of your saved scan history?")) return;
  try {
    await api("/history", { method: "DELETE" });
    await refreshData();
    toast("History cleared", "All saved scans were deleted.");
  } catch (error) {
    toast("Could not clear history", error.message);
  }
});

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadFile(path, filename, accept) {
  const headers = new Headers({ Accept: accept });
  if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(`${API_URL}${path}`, { credentials: "include", headers });
  if (!response.ok) {
    let message = `Download failed (${response.status}).`;
    try {
      message = (await response.json()).error || message;
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
    throw new Error(message);
  }
  downloadBlob(await response.blob(), filename);
}

document.querySelector("#page-analytics .secondary-btn")?.addEventListener("click", async () => {
  try {
    await downloadFile("/history/export.csv", "phishguard-scan-history.csv", "text/csv");
    toast("CSV downloaded", "Your saved scan history was exported.");
  } catch (error) {
    toast("Export failed", error.message);
  }
});

function renderBulk(scans) {
  const body = document.getElementById("bulkBody");
  body.replaceChildren();
  scans.forEach(scan => {
    const row = body.insertRow();
    addCell(row, scan.url, "url-cell");
    row.insertCell().appendChild(createBadge(scan.result));
    addCell(row, scan.risk_score);
  });
  const counts = {
    safe: scans.filter(scan => scan.result === "safe").length,
    phishing: scans.filter(scan => scan.result === "phishing").length,
    malicious: scans.filter(scan => scan.result === "malicious").length
  };
  const statistics = document.querySelector("#bulkResults .bulk-stats");
  statistics.replaceChildren();
  [
    [scans.length, "Total", ""],
    [counts.safe, "Safe", "safe-stat"],
    [counts.phishing, "Phishing", "phish-stat"],
    [counts.malicious, "Malicious", "mal-stat"]
  ].forEach(([count, label, className], index) => {
    const item = document.createElement("span");
    if (className) item.className = className;
    const value = document.createElement("b");
    if (index === 0) value.id = "bulkTotal";
    value.textContent = count;
    item.append(value, label);
    statistics.appendChild(item);
  });
  document.getElementById("bulkResults").classList.remove("hidden");
}

document.getElementById("bulkDemo")?.addEventListener("click", async () => {
  const file = document.getElementById("csvFile").files[0];
  if (!file) {
    toast("Choose a CSV file", "Select a CSV containing one URL per row.");
    return;
  }
  const button = document.getElementById("bulkDemo");
  button.disabled = true;
  try {
    const data = await api("/bulk-scan", { method: "POST", body: (() => {
      const form = new FormData();
      form.append("file", file);
      return form;
    })() });
    bulkData = data.scans;
    renderBulk(bulkData);
    await refreshData();
    toast("Bulk scan complete", `${data.total} URLs analyzed${data.saved ? " and saved to history." : "; history storage is off."}`);
  } catch (error) {
    toast("Bulk scan failed", error.message);
  } finally {
    button.disabled = false;
  }
});
document.getElementById("csvFile")?.addEventListener("change", event => {
  const file = event.currentTarget.files[0];
  if (file) document.querySelector(".upload-box small").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
});
document.getElementById("downloadBulk")?.addEventListener("click", () => {
  if (!bulkData.length) return toast("No results", "Run a CSV scan before exporting its results.");
  const escape = value => `"${String(value).replace(/"/g, '""')}"`;
  const content = [["URL", "Threat type", "Risk score"], ...bulkData.map(scan =>
    [scan.url, resultLabel(scan.result), scan.risk_score])].map(row => row.map(escape).join(",")).join("\r\n");
  downloadBlob(new Blob([`\uFEFF${content}`], { type: "text/csv;charset=utf-8" }), "phishguard-bulk-results.csv");
});

async function generatePDF(type) {
  try {
    await downloadFile(`/reports/${type}.pdf`, `PhishGuard_${type}_Report.pdf`, "application/pdf");
    toast("PDF downloaded", "Your report contains your saved scan data.");
  } catch (error) {
    toast("Report failed", error.message);
  }
}
document.getElementById("generateReport")?.addEventListener("click", () => generatePDF("url"));
document.querySelectorAll(".report-card [data-report]").forEach(button =>
  button.addEventListener("click", () => generatePDF(button.dataset.report)));

const toggleKeys = ["store_history", "critical_alerts"];
document.querySelectorAll(".toggle-row input").forEach((input, index) => {
  input.addEventListener("change", async () => {
    const previous = { ...settings };
    const key = toggleKeys[index];
    settings[key] = input.checked;
    try {
      const data = await api("/settings", { method: "PUT", body: JSON.stringify(settings) });
      settings = data.settings;
      if (key === "critical_alerts") {
        const analytics = await api(`/analytics?days=${selectedActivityDays()}`);
        renderAnalytics(analytics);
      }
      toast("Setting saved", "Your preference is stored in your account.");
    } catch (error) {
      settings = previous;
      input.checked = !input.checked;
      toast("Could not save setting", error.message);
    }
  });
});

function profileForm() {
  const userName = document.getElementById("profileName").textContent;
  const userEmail = document.getElementById("profileEmail").textContent;
  const content = document.getElementById("modalContent");
  content.innerHTML = `
    <h2>Manage your account</h2>
    <form id="profileForm" class="modal-form">
      <label for="profileEditName">Full name</label><input id="profileEditName" name="name" required maxlength="80">
      <label for="profileEditEmail">Email address</label><input id="profileEditEmail" name="email" type="email" required>
      <label for="profileCurrentPassword">Current password</label><input id="profileCurrentPassword" name="current_password" type="password" required autocomplete="current-password">
      <button class="primary-btn" type="submit">Save changes</button>
      <button class="secondary-btn danger-btn" id="deleteAccount" type="button">Delete account</button>
    </form>`;
  content.querySelector("#profileEditName").value = userName;
  content.querySelector("#profileEditEmail").value = userEmail;
  content.querySelector("#profileForm").addEventListener("submit", async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const data = await api("/profile", { method: "PUT", body: JSON.stringify(Object.fromEntries(form)) });
      setCurrentUser(data.user);
      closeModal();
      toast("Profile updated", "Your account details were saved.");
    } catch (error) {
      toast("Profile update failed", error.message);
    }
  });
  content.querySelector("#deleteAccount").addEventListener("click", async () => {
    if (!confirm("Permanently delete your account and all saved scan data?")) return;
    const password = content.querySelector("#profileCurrentPassword").value;
    try {
      await api("/me", { method: "DELETE", body: JSON.stringify({ password }) });
      window.location.href = "index.html";
    } catch (error) {
      toast("Account deletion failed", error.message);
    }
  });
  modal.classList.remove("hidden");
}

function setCurrentUser(user) {
  document.getElementById("profileName").textContent = user.name;
  document.getElementById("accountName").textContent = user.name;
  document.getElementById("profileEmail").textContent = user.email;
  document.querySelector(".page-heading h1").textContent = `Welcome, ${user.name.split(" ")[0]}.`;
  document.querySelector(".user-mini b").textContent = user.name;
  document.querySelector(".user-mini small").textContent = user.email;
}

document.getElementById("profileBtn")?.addEventListener("click", profileForm);
document.querySelector(".users-manage-btn")?.addEventListener("click", profileForm);
document.getElementById("notifyBtn")?.addEventListener("click", () => {
  const threats = notificationData;
  const content = document.getElementById("modalContent");
  content.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = "Recent flagged scans";
  content.appendChild(heading);
  if (!threats.length) {
    const message = document.createElement("p");
    message.textContent = "No flagged URLs in your saved scan history.";
    content.appendChild(message);
  }
  threats.forEach(scan => {
    const item = document.createElement("p");
    item.textContent = `${resultLabel(scan.result)} · ${scan.url} · risk ${scan.risk_score}/100`;
    content.appendChild(item);
  });
  modal.classList.remove("hidden");
});

document.getElementById("themeBtn").addEventListener("click", () => {
  const light = document.body.classList.toggle("light");
  localStorage.setItem("phishguard-theme", light ? "light" : "dark");
  document.getElementById("themeBtn").innerHTML = light ? "☀ <span>Light</span>" : "☾ <span>Dark</span>";
});
document.querySelector(".select-small")?.addEventListener("change", async () => {
  try {
    const days = selectedActivityDays();
    document.getElementById("activityRangeLabel").textContent = `URL scans over the last ${days} days`;
    renderAnalytics(await api(`/analytics?days=${days}`));
  } catch (error) {
    toast("Analytics could not be refreshed", error.message);
  }
});
if (localStorage.getItem("phishguard-theme") === "light") {
  document.body.classList.add("light");
  document.getElementById("themeBtn").innerHTML = "☀ <span>Light</span>";
}

document.getElementById("logoutBtn").addEventListener("click", async () => {
  try {
    await api("/logout", { method: "POST", body: "{}" });
    window.location.href = "index.html";
  } catch (error) {
    toast("Logout failed", error.message);
  }
});

async function initialize() {
  try {
    const data = await api("/me");
    csrfToken = data.csrf_token;
    setCurrentUser(data.user);
    await Promise.all([refreshData(), loadSettings()]);
  } catch (error) {
    if (!error.message.includes("log in") && !error.message.includes("session expired")) {
      toast("Could not load dashboard", error.message);
    }
  }
}

initialize();
