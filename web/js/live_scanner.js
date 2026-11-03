/**
 * Live Incident Analyzer Module
 * Handles single email scans, preset attack scenarios, real-time metrics,
 * indicator evidence snippets, and actionable mitigation playbooks.
 */

const CORE_INDICATOR_METADATA = {
  reply_to_mismatch: {
    title: "Fake Sender Address",
    desc: "Replies go to a different email address than the sender."
  },
  ip_in_url: {
    title: "IP Number Link",
    desc: "Web link uses numbers instead of a real website name."
  },
  suspicious_tld: {
    title: "Risky Website Ending",
    desc: "Domain uses a risky ending like .xyz, .top, or .club."
  },
  urgency_words: {
    title: "Urgent Pressure Words",
    desc: "Tries to rush or scare you into clicking immediately."
  },
  executable_attachment: {
    title: "Dangerous File Attached",
    desc: "Attachment (.exe, .scr) can harm your device."
  },
  no_https: {
    title: "Insecure Link (HTTP)",
    desc: "Link has no security lock. Passwords can be stolen."
  },
  long_url: {
    title: "Suspicious Long Link",
    desc: "Extra-long link used to hide the real destination."
  }
};

let currentLiveAnalysisData = null;

function setupLiveScanner() {
  loadLivePresets();
  setupTextareaCounters();
  setupFormSubmission();
  setupClearButton();
}

// 1. Load Presets
async function loadLivePresets() {
  const container = document.getElementById("presets-row");
  if (!container) return;

  try {
    const res = await fetch("/api/presets");
    const data = await res.json();
    const presets = data.presets || [];

    container.innerHTML = presets.map((p, idx) => `
      <button type="button" class="preset-chip ${idx === 0 ? 'active' : ''}" data-index="${idx}">
        ${p.name.replace(/^\d+\.\s*/, '')}
      </button>
    `).join('');

    container.querySelectorAll(".preset-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        container.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active"));
        chip.classList.add("active");

        const idx = parseInt(chip.dataset.index, 10);
        const preset = presets[idx];
        const textarea = document.getElementById("email-content");
        if (textarea && preset) {
          textarea.value = preset.text;
          updateTextareaCounters();
          showToast(`Loaded: ${chip.textContent.trim()}`);
          document.getElementById("scanner-form").dispatchEvent(new Event("submit"));
        }
      });
    });

    // Auto-load first preset on load
    if (presets.length > 0) {
      const textarea = document.getElementById("email-content");
      if (textarea && !textarea.value) {
        textarea.value = presets[0].text;
        updateTextareaCounters();
        document.getElementById("scanner-form").dispatchEvent(new Event("submit"));
      }
    }
  } catch (err) {
    console.error("Error loading presets:", err);
  }
}

// 2. Textarea Character & Line Counters
function setupTextareaCounters() {
  const textarea = document.getElementById("email-content");
  if (!textarea) return;

  textarea.addEventListener("input", updateTextareaCounters);
}

function updateTextareaCounters() {
  const textarea = document.getElementById("email-content");
  const disp = document.getElementById("char-count-disp");
  if (!textarea || !disp) return;

  const text = textarea.value;
  const chars = text.length;
  const lines = text ? text.split("\n").length : 0;
  disp.textContent = `${chars.toLocaleString()} characters | ${lines} lines`;
}

function setupClearButton() {
  const btn = document.getElementById("btn-clear-scanner");
  const textarea = document.getElementById("email-content");
  if (btn && textarea) {
    btn.addEventListener("click", () => {
      textarea.value = "";
      updateTextareaCounters();
      document.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active"));
      showToast("Input cleared.");
    });
  }
}

// 3. Form Submission
function setupFormSubmission() {
  const form = document.getElementById("scanner-form");
  const textarea = document.getElementById("email-content");
  const btn = document.getElementById("btn-scan");

  if (!form || !textarea || !btn) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = textarea.value.trim();
    if (!content) {
      showToast("Please paste an email to scan.");
      return;
    }

    btn.disabled = true;
    btn.innerHTML = `<span class="btn-spinner"></span> Checking email...`;

    const start = performance.now();

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: content, include_adversarial: true })
      });

      const data = await res.json();
      const latency = Math.round(performance.now() - start);

      // Update telemetry badges
      const latBadge = document.getElementById("scan-latency-badge");
      if (latBadge) latBadge.textContent = `${latency}ms`;
      const headerLat = document.getElementById("header-latency-disp");
      if (headerLat) headerLat.textContent = `${latency}ms`;

      currentLiveAnalysisData = data;
      renderLiveAssessment(data);

      showToast(`Scan complete: ${data.final_verdict}`);

    } catch (err) {
      console.error("Scan error:", err);
      showToast("Error checking email.");
    } finally {
      btn.disabled = false;
      btn.innerHTML = `
        <svg class="ui-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
        </svg>
        <span>Check Email</span>
      `;
    }
  });
}

// 4. Render Live Assessment
function renderLiveAssessment(data) {
  const verdict = data.final_verdict || "Safe";
  const verdictLower = verdict.toLowerCase();

  // 1. Verdict Box
  const box = document.getElementById("verdict-box");
  if (box) {
    box.className = `verdict-box ${verdictLower}`;
  }
  const tag = document.getElementById("verdict-tag");
  if (tag) {
    if (verdict === "Phishing") tag.textContent = "DANGER DETECTED";
    else if (verdict === "Suspicious") tag.textContent = "WARNING: SUSPICIOUS";
    else tag.textContent = "SAFE EMAIL";
  }
  const title = document.getElementById("verdict-title");
  if (title) {
    if (verdict === "Phishing") title.textContent = "PHISHING (SCAM)";
    else if (verdict === "Suspicious") title.textContent = "SUSPICIOUS";
    else title.textContent = "SAFE";
  }
  const summary = document.getElementById("verdict-summary");
  if (summary) summary.textContent = data.summary_explanation || "Scan complete.";

  // Pill
  const pill = document.getElementById("verdict-pill");
  if (pill) {
    pill.textContent = `RESULT: ${verdict.toUpperCase()}`;
    pill.style.color = verdict === "Phishing" ? "var(--threat-phish)" : (verdict === "Suspicious" ? "var(--threat-suspicious)" : "var(--threat-safe)");
  }

  // 2. Metrics & Bars
  const riskVal = data.risk_index !== undefined ? data.risk_index : 0;
  const confVal = data.confidence_percentage !== undefined ? data.confidence_percentage : 0;

  const metricRisk = document.getElementById("metric-risk");
  if (metricRisk) {
    metricRisk.textContent = `${riskVal} / 100`;
    metricRisk.style.color = riskVal >= 60 ? "var(--threat-phish)" : (riskVal >= 30 ? "var(--threat-suspicious)" : "var(--threat-safe)");
  }

  const riskFill = document.getElementById("meter-risk-fill");
  if (riskFill) {
    riskFill.style.width = `${riskVal}%`;
    riskFill.style.background = riskVal >= 60 ? "var(--threat-phish)" : (riskVal >= 30 ? "var(--threat-suspicious)" : "var(--threat-safe)");
  }

  const metricConf = document.getElementById("metric-conf");
  if (metricConf) metricConf.textContent = `${confVal}%`;

  const confFill = document.getElementById("meter-conf-fill");
  if (confFill) {
    confFill.style.width = `${confVal}%`;
    confFill.style.background = confVal >= 75 ? "var(--accent-cyan)" : "var(--threat-suspicious)";
  }

  // 3. Simple Action Recommendations
  const recContainer = document.getElementById("recommendations-container");
  if (recContainer && data.recommendations) {
    recContainer.innerHTML = data.recommendations.map(r => `
      <div class="rec-item ${r.level || 'INFO'}">
        <div>
          <div class="rec-title">${escapeHtmlLive(r.action)}</div>
          <div class="rec-detail">${escapeHtmlLive(r.detail)}</div>
        </div>
      </div>
    `).join('');
  }

  // 4. Indicators Grid with Evidence Snippets
  const grid = document.getElementById("indicators-grid");
  if (grid && data.features) {
    const evidence = data.evidence || {};
    grid.innerHTML = Object.keys(CORE_INDICATOR_METADATA).map(key => {
      const meta = CORE_INDICATOR_METADATA[key];
      const isFlagged = data.features[key] === 1;

      let snippetText = "";
      if (isFlagged && evidence[key]) {
        const ev = evidence[key];
        snippetText = Array.isArray(ev) ? ev.join(', ') : String(ev);
        if (snippetText.length > 60) snippetText = snippetText.substring(0, 60) + "...";
      }

      return `
        <div class="indicator-card ${isFlagged ? 'flagged' : ''}">
          <div class="indicator-top">
            <span class="indicator-title">${escapeHtmlLive(meta.title)}</span>
            ${isFlagged ? '<span class="badge-threat phish" style="font-size: 9.5px;">RISK FOUND</span>' : '<span class="badge-threat safe" style="font-size: 9.5px;">SAFE</span>'}
          </div>
          <div class="indicator-desc">${escapeHtmlLive(meta.desc)}</div>
          ${snippetText ? `<div class="indicator-snippet">Found: ${escapeHtmlLive(snippetText)}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  // 5. Reasoning Text
  const reasoningElem = document.getElementById("reasoning-text");
  if (reasoningElem) {
    const bc = data.modules?.unit_3_expert_system?.backward_chaining;
    if (bc && bc.explanation) {
      reasoningElem.textContent = bc.explanation;
    } else {
      reasoningElem.textContent = data.summary_explanation || "No risks or scam signs found.";
    }
  }
}

function escapeHtmlLive(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
