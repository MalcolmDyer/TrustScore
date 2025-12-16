document.addEventListener("DOMContentLoaded", init);

async function init() {
  const settings = await getSettings();
  bindSensitivity(settings.sensitivity);
  bindAllowlist(settings.allowlist || []);
  bindBackend(settings.enableBackend);

  document.querySelectorAll('input[name="sensitivity"]').forEach((radio) => {
    radio.addEventListener("change", async () => {
      await saveSettings({ sensitivity: radio.value });
    });
  });

  document.getElementById("allowlistForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("allowlistInput");
    const domain = normalizeDomain(input.value);
    if (!domain) {
      input.value = "";
      input.placeholder = "Enter a valid domain like example.com";
      return;
    }
    await toggleAllowlist(domain, true);
    input.value = "";
    const updated = await getSettings();
    bindAllowlist(updated.allowlist || []);
  });

  document.getElementById("backendToggle").addEventListener("change", async (event) => {
    await saveSettings({ enableBackend: event.target.checked });
  });
}

function bindSensitivity(value) {
  const match = document.querySelector(`input[name="sensitivity"][value="${value}"]`);
  if (match) match.checked = true;
}

function bindAllowlist(list) {
  const container = document.getElementById("allowlistList");
  if (!list.length) {
    container.innerHTML = '<div class="hint">No domains on the allowlist yet.</div>';
    return;
  }

  container.innerHTML = list
    .map(
      (domain) => `
      <div class="item">
        <span>${escapeHtml(domain)}</span>
        <button data-domain="${escapeHtml(domain)}">Remove</button>
      </div>`
    )
    .join("");

  container.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const domain = btn.getAttribute("data-domain");
      await toggleAllowlist(domain, false);
      const updated = await getSettings();
      bindAllowlist(updated.allowlist || []);
    });
  });
}

function bindBackend(enabled) {
  document.getElementById("backendToggle").checked = Boolean(enabled);
}

function escapeHtml(str = "") {
  return str.replace(/[&<>"']/g, (char) => {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" };
    return map[char] || char;
  });
}

function normalizeDomain(value = "") {
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    const hostname = parsed.hostname.toLowerCase().replace(/^\./, "");
    if (!hostname || hostname.includes("..") || !/^[a-z0-9.-]+$/.test(hostname)) {
      return "";
    }
    return hostname;
  } catch (err) {
    return "";
  }
}

function getSettings() {
  return new Promise((resolve) => chrome.runtime.sendMessage({ type: "getSettings" }, resolve));
}

function saveSettings(partial) {
  return new Promise((resolve) =>
    chrome.runtime.sendMessage({ type: "saveSettings", settings: partial }, resolve)
  );
}

function toggleAllowlist(domain, allow) {
  return new Promise((resolve) =>
    chrome.runtime.sendMessage({ type: "toggleAllowlist", domain, allow }, resolve)
  );
}
