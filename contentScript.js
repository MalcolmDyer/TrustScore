(function () {
  if (window !== window.top) return;
  if (window.__trustscoreInjected) return;
  window.__trustscoreInjected = true;

  const brands = [
    "apple",
    "google",
    "microsoft",
    "amazon",
    "paypal",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "facebook",
    "instagram",
    "coinbase",
    "binance"
  ];

  const suspiciousText = [
    "sign in",
    "verify your account",
    "update payment",
    "confirm identity",
    "wallet connect",
    "unlock wallet",
    "password reset",
    "account suspended",
    "security alert"
  ];

  const behaviorFindings = {
    redirectAttempts: 0,
    autoFormSubmits: 0,
    iframeFormLoads: 0,
    keyboardInterception: false,
    clipboardAccess: false
  };

  let lastEvaluation = null;
  let pendingSend = null;
  let bypassForSession = sessionStorage.getItem(bypassKey()) === "true";

  injectStyles();
  setupBehaviorObservers();
  setupDomObserver();
  sendSignals();

  function bypassKey() {
    return `trustscore:bypass:${location.hostname}`;
  }

  function setupBehaviorObservers() {
    const originalAssign = window.location.assign.bind(window.location);
    window.location.assign = (...args) => {
      behaviorFindings.redirectAttempts += 1;
      scheduleSend();
      return originalAssign(...args);
    };

    const originalReplace = window.location.replace.bind(window.location);
    window.location.replace = (...args) => {
      behaviorFindings.redirectAttempts += 1;
      scheduleSend();
      return originalReplace(...args);
    };

    const originalPushState = history.pushState.bind(history);
    history.pushState = (...args) => {
      behaviorFindings.redirectAttempts += 1;
      scheduleSend();
      return originalPushState(...args);
    };

    const originalReplaceState = history.replaceState.bind(history);
    history.replaceState = (...args) => {
      behaviorFindings.redirectAttempts += 1;
      scheduleSend();
      return originalReplaceState(...args);
    };

    document.addEventListener(
      "submit",
      (event) => {
        if (!event.isTrusted) {
          behaviorFindings.autoFormSubmits += 1;
          scheduleSend();
        }
      },
      true
    );

    document.addEventListener(
      "keydown",
      (event) => {
        if (!event.isTrusted && isSensitiveInput(event.target)) {
          behaviorFindings.keyboardInterception = true;
          scheduleSend();
        }
      },
      true
    );

    ["copy", "cut", "paste"].forEach((type) => {
      document.addEventListener(
        type,
        (event) => {
          if (!event.isTrusted && isSensitiveInput(event.target)) {
            behaviorFindings.clipboardAccess = true;
            scheduleSend();
          }
        },
        true
      );
    });
  }

  function setupDomObserver() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node.tagName === "IFRAME" && isHiddenIframe(node)) {
            behaviorFindings.iframeFormLoads += 1;
          }
        });
      }
      scheduleSend();
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  function isHiddenIframe(node) {
    if (!(node instanceof HTMLIFrameElement)) return false;
    const rect = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    const hidden =
      rect.width < 5 ||
      rect.height < 5 ||
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0";
    const externalSrc =
      node.src && !node.src.startsWith(location.origin) && !node.src.startsWith("/");
    let hasForm = false;
    try {
      hasForm = Boolean(node.contentDocument?.querySelector("form"));
    } catch (err) {
      hasForm = false;
    }
    return hidden && (externalSrc || hasForm);
  }

  function isSensitiveInput(target) {
    if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
      return false;
    }
    const type = target.type?.toLowerCase() || "";
    const name = target.name?.toLowerCase() || "";
    return (
      type === "password" ||
      name.includes("pass") ||
      name.includes("card") ||
      name.includes("account") ||
      name.includes("wallet")
    );
  }

  function gatherSignals() {
    const url = new URL(location.href);
    const hostname = url.hostname || "";

    const urlInfo = {
      href: url.href,
      protocol: url.protocol,
      hostname,
      path: url.pathname,
      query: url.search,
      isIpAddress: /^[0-9.]+$/.test(hostname),
      hasSuspiciousSubdomain: hasSuspiciousSubdomain(hostname),
      hasSensitivePath: hasSensitivePath(url.pathname),
      hasSuspiciousQuery: hasSuspiciousQuery(url.search),
      brandLookalike: brandLookalike(hostname)
    };

    const domFindings = scanDom();
    const sslInfo = {
      usesHttps: location.protocol === "https:",
      mixedContent: detectMixedContent()
    };

    return {
      urlInfo,
      domFindings,
      behaviorFindings,
      sslInfo
    };
  }

  function scanDom() {
    const inputs = Array.from(document.querySelectorAll("input, textarea"));
    const forms = Array.from(document.querySelectorAll("form"));
    const bodyText = document.body?.innerText?.toLowerCase() || "";

    const hasPasswordField = inputs.some((input) => (input.type || "").toLowerCase() === "password");
    const hasCreditCardField = inputs.some((input) => {
      const name = (input.name || "").toLowerCase();
      const placeholder = (input.placeholder || "").toLowerCase();
      return (
        name.includes("card") ||
        name.includes("cc") ||
        placeholder.includes("card") ||
        (input.maxLength >= 14 && input.maxLength <= 19 && input.inputMode === "numeric")
      );
    });

    const hasPersonalInfoField = inputs.some((input) => {
      const name = (input.name || "").toLowerCase();
      const placeholder = (input.placeholder || "").toLowerCase();
      return (
        name.includes("ssn") ||
        name.includes("social") ||
        name.includes("passport") ||
        name.includes("bank") ||
        placeholder.includes("ssn") ||
        placeholder.includes("passport")
      );
    });

    const suspiciousTextHits = suspiciousText.filter((phrase) => bodyText.includes(phrase));
    const brandMentions = brands.filter((brand) => bodyText.includes(brand));

    const externalFormActions = forms.filter((form) => {
      if (!form.action) return false;
      try {
        const actionUrl = new URL(form.action, location.href);
        return actionUrl.hostname !== location.hostname;
      } catch (err) {
        return false;
      }
    }).length;

    const hiddenIframes = Array.from(document.querySelectorAll("iframe")).filter((iframe) =>
      isHiddenIframe(iframe)
    ).length;

    return {
      hasPasswordField,
      hasCreditCardField,
      hasPersonalInfoField,
      suspiciousTextHits,
      brandMentions,
      externalFormActions,
      hiddenIframes
    };
  }

  function detectMixedContent() {
    if (location.protocol !== "https:") return false;
    return (
      document.querySelector('img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]') !==
      null
    );
  }

  function hasSensitivePath(pathname = "") {
    const lowered = pathname.toLowerCase();
    return (
      lowered.includes("login") ||
      lowered.includes("signin") ||
      lowered.includes("account") ||
      lowered.includes("payment") ||
      lowered.includes("checkout") ||
      lowered.includes("wallet")
    );
  }

  function hasSuspiciousQuery(search = "") {
    const lowered = search.toLowerCase();
    return (
      lowered.includes("redirect") ||
      lowered.includes("token") ||
      lowered.includes("session") ||
      lowered.includes("verify") ||
      lowered.includes("update")
    );
  }

  function hasSuspiciousSubdomain(hostname) {
    const parts = hostname.split(".");
    const subdomain = parts.slice(0, -2).join(".").toLowerCase();
    const depth = subdomain ? subdomain.split(".").length : 0;
    const brandInSubdomain = brands.some((brand) => subdomain.includes(brand));
    return depth >= 2 || brandInSubdomain;
  }

  function brandLookalike(hostname) {
    const base = hostname.split(".").slice(-2)[0] || "";
    return brands.some((brand) => hostname.includes(brand) && !base.includes(brand));
  }

  function sendSignals() {
    const payload = gatherSignals();
    try {
      chrome.runtime.sendMessage({ type: "pageSignals", payload }, (response) => {
        if (chrome.runtime.lastError || !response) return;
        lastEvaluation = response;
        renderUi(response);
      });
    } catch (err) {
      // Ignore failures if messaging is unavailable.
    }
  }

  function scheduleSend() {
    if (pendingSend) {
      clearTimeout(pendingSend);
    }
    pendingSend = setTimeout(sendSignals, 800);
  }

  function renderUi(evaluation) {
    renderWidget(evaluation);
    renderBanner(evaluation);
  }

  function renderWidget(evaluation) {
    let widget = document.getElementById("trustscore-widget");
    if (!widget) {
      widget = document.createElement("div");
      widget.id = "trustscore-widget";
      widget.innerHTML = `
        <div class="ts-widget-body">
          <div class="ts-score"></div>
          <div class="ts-meta">
            <div class="ts-label">TrustScore</div>
            <div class="ts-tier"></div>
            <button class="ts-reasons-toggle" type="button">Reasons</button>
          </div>
        </div>
        <div class="ts-reasons-panel hidden"></div>
      `;
      document.body.appendChild(widget);

      widget.querySelector(".ts-reasons-toggle").addEventListener("click", () => {
        widget.querySelector(".ts-reasons-panel").classList.toggle("hidden");
      });
    }

    const color = tierColor(evaluation.tier);
    widget.querySelector(".ts-score").textContent = evaluation.score;
    widget.querySelector(".ts-score").style.background = color;
    widget.querySelector(".ts-tier").textContent = labelForTier(evaluation.tier);

    const reasonsPanel = widget.querySelector(".ts-reasons-panel");
    reasonsPanel.innerHTML = evaluation.reasons
      .slice(0, 6)
      .map((reason) => `<div class="ts-reason">• ${escapeHtml(reason)}</div>`)
      .join("") || "<div class=\"ts-reason\">No significant risks detected.</div>";
  }

  function renderBanner(evaluation) {
    let banner = document.getElementById("trustscore-banner");
    if (evaluation.score >= 50 || bypassForSession) {
      banner?.remove();
      return;
    }

    if (!banner) {
      banner = document.createElement("div");
      banner.id = "trustscore-banner";
      banner.innerHTML = `
        <div class="ts-banner-text">
          <div class="ts-banner-title">Warning: Low TrustScore</div>
          <div class="ts-banner-sub">This site may be unsafe. Review the reasons before proceeding.</div>
        </div>
        <div class="ts-banner-actions">
          <button class="ts-banner-details">Show reasons</button>
          <button class="ts-banner-proceed">Proceed anyway</button>
        </div>
      `;
      document.body.appendChild(banner);

      banner.querySelector(".ts-banner-details").addEventListener("click", () => {
        document.getElementById("trustscore-widget")?.querySelector(".ts-reasons-toggle")?.click();
        banner.scrollIntoView({ behavior: "smooth", block: "start" });
      });

      banner.querySelector(".ts-banner-proceed").addEventListener("click", () => {
        bypassForSession = true;
        sessionStorage.setItem(bypassKey(), "true");
        banner.remove();
      });
    }
  }

  function tierColor(tier) {
    switch (tier) {
      case "trusted":
        return "linear-gradient(135deg, #16a34a, #22c55e)";
      case "caution":
        return "linear-gradient(135deg, #ca8a04, #eab308)";
      default:
        return "linear-gradient(135deg, #dc2626, #ef4444)";
    }
  }

  function labelForTier(tier) {
    if (tier === "trusted") return "Trusted";
    if (tier === "caution") return "Caution";
    return "High Risk";
  }

  function escapeHtml(str = "") {
    return str.replace(/[&<>"']/g, (char) => {
      const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
      };
      return map[char] || char;
    });
  }

  function injectStyles() {
    if (document.getElementById("trustscore-styles")) return;
    const style = document.createElement("style");
    style.id = "trustscore-styles";
    style.textContent = `
      #trustscore-widget {
        position: fixed;
        bottom: 16px;
        right: 16px;
        z-index: 2147483646;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        color: #0f172a;
        width: 220px;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.2);
        border-radius: 14px;
        overflow: hidden;
        background: #fff;
        border: 1px solid rgba(148, 163, 184, 0.35);
      }
      #trustscore-widget .ts-widget-body {
        display: flex;
        gap: 12px;
        align-items: center;
        padding: 12px;
      }
      #trustscore-widget .ts-score {
        width: 64px;
        height: 64px;
        border-radius: 12px;
        color: #fff;
        font-weight: 700;
        display: grid;
        place-items: center;
        font-size: 20px;
        box-shadow: inset 0 -6px 16px rgba(0,0,0,0.12);
      }
      #trustscore-widget .ts-meta {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      #trustscore-widget .ts-label {
        font-size: 12px;
        color: #475569;
        letter-spacing: 0.02em;
      }
      #trustscore-widget .ts-tier {
        font-size: 16px;
        font-weight: 700;
      }
      #trustscore-widget .ts-reasons-toggle {
        align-self: flex-start;
        border: none;
        background: #0ea5e9;
        color: #fff;
        border-radius: 8px;
        padding: 6px 10px;
        font-size: 12px;
        cursor: pointer;
        transition: opacity 0.2s ease, transform 0.1s ease;
      }
      #trustscore-widget .ts-reasons-toggle:hover {
        opacity: 0.9;
      }
      #trustscore-widget .ts-reasons-toggle:active {
        transform: translateY(1px);
      }
      #trustscore-widget .ts-reasons-panel {
        border-top: 1px solid rgba(148, 163, 184, 0.35);
        background: #f8fafc;
        max-height: 240px;
        overflow: auto;
        padding: 10px 12px;
      }
      #trustscore-widget .ts-reasons-panel.hidden {
        display: none;
      }
      #trustscore-widget .ts-reason {
        font-size: 12px;
        color: #0f172a;
        margin-bottom: 6px;
      }
      #trustscore-banner {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 2147483645;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        padding: 12px 16px;
        background: linear-gradient(90deg, #7f1d1d, #b91c1c);
        color: #fff;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25);
      }
      #trustscore-banner .ts-banner-title {
        font-weight: 700;
        font-size: 16px;
      }
      #trustscore-banner .ts-banner-sub {
        font-size: 13px;
        opacity: 0.92;
      }
      #trustscore-banner .ts-banner-actions {
        display: flex;
        gap: 8px;
      }
      #trustscore-banner button {
        border: none;
        border-radius: 10px;
        padding: 8px 12px;
        font-size: 13px;
        cursor: pointer;
        font-weight: 600;
      }
      #trustscore-banner .ts-banner-details {
        background: #f8fafc;
        color: #0f172a;
      }
      #trustscore-banner .ts-banner-proceed {
        background: rgba(255, 255, 255, 0.14);
        color: #fff;
        border: 1px solid rgba(255, 255, 255, 0.28);
      }
      @media (max-width: 600px) {
        #trustscore-widget {
          left: 12px;
          right: 12px;
          bottom: 12px;
        }
        #trustscore-banner {
          flex-direction: column;
          align-items: flex-start;
        }
      }
    `;
    document.head.appendChild(style);
  }
})();
