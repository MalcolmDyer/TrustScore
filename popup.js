document.addEventListener("DOMContentLoaded", init);

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const evaluation = await requestScore(tab?.id);
  const settings = await requestSettings();
  renderProfile(settings);
  renderEvaluation(evaluation, settings);
  renderHistory();

  const allowlistBtn = document.getElementById("allowlistBtn");
  allowlistBtn.addEventListener("click", async () => {
    if (!evaluation?.hostname) return;
    const allow = !settings.allowlist?.some((item) => evaluation.hostname.endsWith(item));
    const result = await toggleAllowlist(evaluation.hostname, allow);
    settings.allowlist = result.allowlist;
    updateAllowlistButton(evaluation.hostname, settings.allowlist);
  });
}

function renderProfile(settings) {
  const label = document.getElementById("profileLabel");
  const readable = settings?.sensitivity || "normal";
  label.textContent = `${readable.charAt(0).toUpperCase()}${readable.slice(1)} mode`;
}

function renderEvaluation(evaluation, settings) {
  const scoreValue = document.getElementById("scoreValue");
  const tierLabel = document.getElementById("tierLabel");
  const urlLabel = document.getElementById("urlLabel");
  const allowlistBtn = document.getElementById("allowlistBtn");

  if (!evaluation) {
    scoreValue.textContent = "--";
    tierLabel.textContent = "No data yet";
    urlLabel.textContent = "Open a page to scan.";
    allowlistBtn.disabled = true;
    return;
  }

  scoreValue.textContent = evaluation.score;
  scoreValue.style.background = tierColor(evaluation.tier);
  tierLabel.textContent = labelForTier(evaluation.tier);
  urlLabel.textContent = evaluation.hostname || evaluation.url || "";

  document.getElementById("urlRisk").textContent = `${evaluation.breakdown.urlRisk} / ${evaluation.breakdown.urlWeight}`;
  document.getElementById("behaviorRisk").textContent = `${evaluation.breakdown.behaviorRisk} / ${evaluation.breakdown.behaviorWeight}`;
  document.getElementById("domRisk").textContent = `${evaluation.breakdown.domRisk} / ${evaluation.breakdown.domWeight}`;
  document.getElementById("sslRisk").textContent = `${evaluation.breakdown.sslRisk} / ${evaluation.breakdown.sslWeight}`;

  const reasons = evaluation.reasons?.slice(0, 6) || [];
  const reasonsList = document.getElementById("reasonsList");
  reasonsList.innerHTML = reasons.length
    ? reasons.map((reason) => `<div class="item">• ${escapeHtml(reason)}</div>`).join("")
    : '<div class="muted">No major risks detected.</div>';

  updateAllowlistButton(evaluation.hostname, settings?.allowlist || []);
}

function updateAllowlistButton(hostname, allowlist) {
  const button = document.getElementById("allowlistBtn");
  if (!hostname) {
    button.disabled = true;
    button.textContent = "Allowlist domain";
    return;
  }
  const isAllowed = allowlist?.some((item) => hostname.endsWith(item));
  button.textContent = isAllowed ? "Remove from allowlist" : "Allowlist domain";
  button.disabled = false;
}

async function renderHistory() {
  const { trustscore_history: history = [] } = await chrome.storage.local.get("trustscore_history");
  const list = document.getElementById("historyList");
  if (!history.length) {
    list.innerHTML = '<div class="muted">No history yet.</div>';
    return;
  }

  list.innerHTML = history
    .slice(0, 5)
    .map((entry) => {
      const date = new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      return `
        <div class="entry">
          <span>${escapeHtml(entry.hostname || "unknown")}</span>
          <span class="tag ${entry.tier}">${entry.score}</span>
        </div>
        <div class="muted" style="font-size:11px">${date}</div>
      `;
    })
    .join("");
}

function tierColor(tier) {
  if (tier === "trusted") return "linear-gradient(135deg, #22c55e, #16a34a)";
  if (tier === "caution") return "linear-gradient(135deg, #eab308, #ca8a04)";
  return "linear-gradient(135deg, #ef4444, #dc2626)";
}

function labelForTier(tier) {
  if (tier === "trusted") return "Trusted";
  if (tier === "caution") return "Caution";
  return "High risk";
}

function escapeHtml(str = "") {
  return str.replace(/[&<>"']/g, (char) => {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" };
    return map[char] || char;
  });
}

function requestScore(tabId) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "getScoreForTab", tabId }, resolve);
  });
}

function requestSettings() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "getSettings" }, resolve);
  });
}

function toggleAllowlist(domain, allow) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "toggleAllowlist", domain, allow }, resolve);
  });
}
