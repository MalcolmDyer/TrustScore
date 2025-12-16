const DEFAULT_SETTINGS = {
  sensitivity: "normal", // strict | normal | relaxed
  allowlist: [],
  enableBackend: false
};

const SCORE_CACHE = new Map(); // tabId -> last evaluation
const RECENT_HISTORY_KEY = "trustscore_history";
const SETTINGS_KEY = "settings";
const MAX_HISTORY = 25;

const PROFILE_MULTIPLIERS = {
  strict: { url: 1.1, dom: 1.05, behavior: 1.2, ssl: 1.1 },
  normal: { url: 1.0, dom: 1.0, behavior: 1.0, ssl: 1.0 },
  relaxed: { url: 0.85, dom: 0.9, behavior: 0.85, ssl: 0.9 }
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "pageSignals") {
    handlePageSignals(message.payload, sender).then(sendResponse);
    return true;
  }

  if (message?.type === "getScoreForTab") {
    const entry = SCORE_CACHE.get(message.tabId || sender?.tab?.id || 0) || null;
    sendResponse(entry);
    return false;
  }

  if (message?.type === "getSettings") {
    loadSettings().then(sendResponse);
    return true;
  }

  if (message?.type === "saveSettings") {
    saveSettings(message.settings).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (message?.type === "toggleAllowlist") {
    toggleAllowlist(message.domain, message.allow).then(sendResponse);
    return true;
  }

  return false;
});

async function loadSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const merged = { ...DEFAULT_SETTINGS, ...(stored[SETTINGS_KEY] || {}) };
  merged.allowlist = normalizeAllowlist(merged.allowlist);
  await chrome.storage.local.set({ [SETTINGS_KEY]: merged });
  return merged;
}

async function saveSettings(settings) {
  const current = await loadSettings();
  const merged = { ...current, ...settings };
  await chrome.storage.local.set({ [SETTINGS_KEY]: merged });
  return merged;
}

async function toggleAllowlist(domain, allow) {
  const settings = await loadSettings();
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    return { allowlist: settings.allowlist };
  }
  const set = new Set(settings.allowlist || []);
  if (allow) {
    set.add(normalized);
  } else {
    set.delete(normalized);
  }
  settings.allowlist = Array.from(set);
  await saveSettings(settings);
  return { allowlist: settings.allowlist };
}

async function handlePageSignals(payload, sender) {
  const tabId = sender?.tab?.id || 0;
  const settings = await loadSettings();
  const evaluation = computeTrustScore(payload, settings);
  SCORE_CACHE.set(tabId, evaluation);
  persistHistory(evaluation).catch(() => {});
  return evaluation;
}

function computeTrustScore(payload, settings) {
  const multipliers = PROFILE_MULTIPLIERS[settings.sensitivity] || PROFILE_MULTIPLIERS.normal;
  const urlResult = evaluateUrlSignals(payload.urlInfo);
  const domResult = evaluateDomSignals(payload.domFindings || {}, payload.urlInfo);
  const behaviorResult = evaluateBehaviorSignals(payload.behaviorFindings || {});
  const sslResult = evaluateSslSignals(payload.sslInfo || {}, payload.domFindings || {});

  const weighted = {
    url: urlResult.risk * multipliers.url,
    dom: domResult.risk * multipliers.dom,
    behavior: behaviorResult.risk * multipliers.behavior,
    ssl: sslResult.risk * multipliers.ssl
  };

  let totalRisk = weighted.url + weighted.dom + weighted.behavior + weighted.ssl;
  const allowlisted = isAllowlisted(settings.allowlist, payload.urlInfo.hostname);
  if (allowlisted) {
    totalRisk *= 0.35;
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - totalRisk)));
  const tier = classifyTier(score);

  const breakdown = {
    urlRisk: round(urlResult.risk),
    domRisk: round(domResult.risk),
    behaviorRisk: round(behaviorResult.risk),
    sslRisk: round(sslResult.risk),
    urlWeight: 30,
    domWeight: 25,
    behaviorWeight: 30,
    sslWeight: 15
  };

  const evaluation = {
    score,
    tier,
    breakdown,
    allowlisted,
    url: payload.urlInfo?.href,
    hostname: payload.urlInfo?.hostname,
    timestamp: Date.now(),
    reasons: [
      ...urlResult.reasons,
      ...domResult.reasons,
      ...behaviorResult.reasons,
      ...sslResult.reasons
    ]
  };

  if (allowlisted) {
    evaluation.reasons.push("Domain on allowlist — risks dampened.");
  }

  return evaluation;
}

function evaluateUrlSignals(info = {}) {
  let risk = 0;
  const reasons = [];

  if (info.protocol !== "https:") {
    risk += info.hasSensitivePath ? 12 : 8;
    reasons.push("Page not served over HTTPS.");
  }

  if (info.isIpAddress) {
    risk += 6;
    reasons.push("Website uses a raw IP address.");
  }

  if (info.hasSuspiciousSubdomain) {
    risk += 10;
    reasons.push("Suspicious subdomain structure (brand in subdomain or deep nesting).");
  }

  if (info.brandLookalike) {
    risk += 8;
    reasons.push("Brand lookalike detected in domain or title.");
  }

  if (info.hasSensitivePath) {
    risk += 5;
    reasons.push("Sensitive path (login/payment) detected.");
  }

  if (info.hasSuspiciousQuery) {
    risk += 5;
    reasons.push("Suspicious query parameters found.");
  }

  return { risk: cap(risk, 30), reasons };
}

function evaluateDomSignals(findings = {}, urlInfo = {}) {
  let risk = 0;
  const reasons = [];

  if (findings.hasPasswordField) {
    risk += 6;
    reasons.push("Password fields detected on page.");
  }

  if (findings.hasCreditCardField) {
    risk += 6;
    reasons.push("Credit card inputs detected.");
  }

  if (findings.hasPersonalInfoField) {
    risk += 4;
    reasons.push("Personal information fields present.");
  }

  if ((findings.suspiciousTextHits || []).length) {
    const hits = cap(findings.suspiciousTextHits.length * 2, 8);
    risk += hits;
    reasons.push("Suspicious call-to-action text found.");
  }

  if ((findings.brandMentions || []).length && urlInfo.brandLookalike) {
    risk += 4;
    reasons.push("Brand mentions mismatch visible domain.");
  }

  if (findings.externalFormActions > 0) {
    risk += 5;
    reasons.push("Form submits to different domain.");
  }

  if (findings.hiddenIframes > 0) {
    risk += 4;
    reasons.push("Hidden iframe with form or external source detected.");
  }

  return { risk: cap(risk, 25), reasons };
}

function evaluateBehaviorSignals(findings = {}) {
  let risk = 0;
  const reasons = [];

  const redirectRisk = cap((findings.redirectAttempts || 0) * 10, 20);
  if (redirectRisk) {
    risk += redirectRisk;
    reasons.push("Unexpected redirect attempts detected.");
  }

  const autoSubmitRisk = cap((findings.autoFormSubmits || 0) * 8, 16);
  if (autoSubmitRisk) {
    risk += autoSubmitRisk;
    reasons.push("Form auto-submission observed.");
  }

  const iframeRisk = cap((findings.iframeFormLoads || 0) * 6, 12);
  if (iframeRisk) {
    risk += iframeRisk;
    reasons.push("Hidden iframe loading external form.");
  }

  if (findings.keyboardInterception) {
    risk += 5;
    reasons.push("Keyboard interception on sensitive inputs.");
  }

  if (findings.clipboardAccess) {
    risk += 5;
    reasons.push("Clipboard access near credential fields.");
  }

  return { risk: cap(risk, 30), reasons };
}

function evaluateSslSignals(info = {}, domFindings = {}) {
  let risk = 0;
  const reasons = [];

  if (!info.usesHttps) {
    risk += domFindings.hasPasswordField ? 12 : 8;
    reasons.push("Page not secured with HTTPS.");
  }

  if (info.mixedContent) {
    risk += 5;
    reasons.push("Mixed content detected (HTTP resources on HTTPS page).");
  }

  return { risk: cap(risk, 15), reasons };
}

function classifyTier(score) {
  if (score >= 80) return "trusted";
  if (score >= 50) return "caution";
  return "high-risk";
}

function cap(value, max) {
  return Math.min(value, max);
}

function round(value) {
  return Math.round(value * 10) / 10;
}

function isAllowlisted(allowlist = [], hostname = "") {
  const target = normalizeDomain(hostname);
  if (!target) return false;
  return allowlist.some((item) => target === item || target.endsWith(`.${item}`));
}

async function persistHistory(entry) {
  const stored = await chrome.storage.local.get(RECENT_HISTORY_KEY);
  const list = stored[RECENT_HISTORY_KEY] || [];
  list.unshift({
    hostname: entry.hostname,
    score: entry.score,
    tier: entry.tier,
    timestamp: entry.timestamp
  });
  const trimmed = list.slice(0, MAX_HISTORY);
  await chrome.storage.local.set({ [RECENT_HISTORY_KEY]: trimmed });
}

function normalizeDomain(domain) {
  if (!domain) return null;
  try {
    const parsed = new URL(domain.includes("://") ? domain : `https://${domain}`);
    const hostname = parsed.hostname.toLowerCase().replace(/^\./, "");
    if (!hostname || hostname.includes("..") || !/^[a-z0-9.-]+$/.test(hostname)) {
      return null;
    }
    return hostname;
  } catch (err) {
    return null;
  }
}

function normalizeAllowlist(list = []) {
  const set = new Set();
  list.forEach((item) => {
    const normalized = normalizeDomain(item);
    if (normalized) set.add(normalized);
  });
  return Array.from(set);
}
