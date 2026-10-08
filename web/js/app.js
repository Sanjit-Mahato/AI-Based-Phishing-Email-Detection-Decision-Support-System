/**
 * PhishRadar - Single Page Threat Intelligence Controller
 * Blue & White Enterprise Cyber Security Dashboard
 */

const INDICATOR_DETAILS = {
  reply_to_mismatch: {
    title: "Reply-To Address Mismatch",
    desc: "Return-path destination differs from verified sender header domain."
  },
  ip_in_url: {
    title: "Direct IP Address in URL",
    desc: "Destination link uses raw IP address instead of legitimate registered domain."
  },
  suspicious_tld: {
    title: "High-Risk / Suspicious TLD",
    desc: "Domain uses high-abuse top-level domain (.xyz, .club, .top, etc.)."
  },
  urgency_words: {
    title: "Psychological Urgency Triggers",
    desc: "Aggressive coercive wording detected attempting to force impulsive action."
  },
  executable_attachment: {
    title: "Dangerous Executable Payload",
    desc: "Attachment contains binary or executable script (.exe, .scr, .iso, etc.)."
  },
  no_https: {
    title: "Unencrypted Protocol (HTTP)",
    desc: "Hyperlink lacks SSL/TLS encryption, exposing credentials to interception."
  },
  long_url: {
    title: "Abnormally Long / Obfuscated URL",
    desc: "Link length exceeds 75 characters with excessive obfuscation parameters."
  }
};

document.addEventListener("DOMContentLoaded", () => {
  loadPresets();
  setupScannerForm();
  loadBenchmarkData();
});

// Load Presets
async function loadPresets() {
  const container = document.getElementById("presets-row");
  if (!container) return;

  try {
    const res = await fetch("/api/presets");
    const data = await res.json();
    const presets = data.presets || [];

    container.innerHTML = presets.map((p, idx) => `
      <button type="button" class="preset-chip" data-index="${idx}">
        ${p.name.replace(/^\d+\.\s*/, '')}
      </button>
    `).join('');

    container.querySelectorAll(".preset-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        const idx = parseInt(chip.dataset.index, 10);
        const preset = presets[idx];
        const textarea = document.getElementById("email-content");
        if (textarea && preset) {
          textarea.value = preset.text;
          showToast(`Loaded scenario: ${chip.textContent.trim()}`);
          document.getElementById("scanner-form").dispatchEvent(new Event("submit"));
        }
      });
    });

    // Auto-load first preset on load
    if (presets.length > 0) {
      document.getElementById("email-content").value = presets[0].text;
      document.getElementById("scanner-form").dispatchEvent(new Event("submit"));
    }
  } catch (err) {
    console.error("Error loading presets:", err);
  }
}

// Form Submission & Analysis
function setupScannerForm() {
  const form = document.getElementById("scanner-form");
  const textarea = document.getElementById("email-content");
  const btn = document.getElementById("btn-scan");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = textarea.value.trim();
    if (!content) {
      showToast("Please enter or paste email text to analyze.");
      return;
    }

    btn.disabled = true;
    btn.innerHTML = `<span>⏳</span> Analyzing threat vectors...`;

    const start = performance.now();

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: content, include_adversarial: true })
      });

      const data = await res.json();
      const latency = Math.round(performance.now() - start);

      document.getElementById("scan-latency").textContent = `${latency}ms LATENCY`;
      renderAssessment(data);
      showToast(`Scan complete: Verdict is ${data.final_verdict}`);
    } catch (err) {
      console.error("Scan error:", err);
      showToast("Error communicating with detection engine.");
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<span>⚡</span> Analyze Threat Now`;
    }
  });
}

// Render Results onto the Single Page
function renderAssessment(data) {
  const verdict = data.final_verdict || "Safe";
  const verdictLower = verdict.toLowerCase();

  // 1. Verdict Box
  const box = document.getElementById("verdict-box");
  box.className = `verdict-box ${verdictLower}`;
  document.getElementById("verdict-tag").textContent = `${verdict.toUpperCase()} DETECTED`;
  document.getElementById("verdict-title").textContent = verdict.toUpperCase();
  document.getElementById("verdict-summary").textContent = data.summary_explanation || "Evaluation complete.";

  // Pill
  const pill = document.getElementById("verdict-pill");
  if (pill) {
    pill.textContent = `VERDICT: ${verdict.toUpperCase()}`;
    pill.style.color = verdict === "Phishing" ? "var(--danger-red)" : (verdict === "Suspicious" ? "var(--warning-amber)" : "var(--success-green)");
  }

  // 2. Metrics
  document.getElementById("metric-risk").textContent = `${data.risk_index} / 100`;
  document.getElementById("metric-conf").textContent = `${data.confidence_percentage}%`;

  // 3. Actionable Security Recommendations
  const recContainer = document.getElementById("recommendations-container");
  if (recContainer && data.recommendations) {
    recContainer.innerHTML = data.recommendations.map(r => `
      <div class="rec-item ${r.level}">
        <div>
          <div class="rec-title">${r.action}</div>
          <div class="rec-detail">${r.detail}</div>
        </div>
      </div>
    `).join('');
  }

  // 4. Indicators Grid
  const grid = document.getElementById("indicators-grid");
  if (grid && data.features) {
    const evidence = data.evidence || {};
    grid.innerHTML = Object.keys(INDICATOR_DETAILS).map(key => {
      const meta = INDICATOR_DETAILS[key];
      const isFlagged = data.features[key] === 1;

      let snippetText = "";
      if (isFlagged && evidence[key]) {
        const ev = evidence[key];
        snippetText = Array.isArray(ev) ? ev.join(', ') : String(ev);
        if (snippetText.length > 55) snippetText = snippetText.substring(0, 55) + "...";
      }

      return `
        <div class="indicator-card ${isFlagged ? 'flagged' : ''}">
          <div class="indicator-top">
            <span class="indicator-title">${meta.title}</span>
            ${isFlagged ? '<span class="badge-flagged">FLAGGED</span>' : '<span class="badge-clean">CLEAN</span>'}
          </div>
          <div class="indicator-desc">${meta.desc}</div>
          ${snippetText ? `<div class="indicator-snippet">Evidence: ${snippetText}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  // 5. Reasoning Text
  const reasoningElem = document.getElementById("reasoning-text");
  if (reasoningElem) {
    const bc = data.modules?.unit_3_expert_system?.backward_chaining;
    if (bc && bc.explanation) {
      reasoningElem.textContent = `Deduction: ${bc.explanation}`;
    } else {
      reasoningElem.textContent = data.summary_explanation || "No anomalous risk indicators met threat criteria.";
    }
  }

  // 6. Adversarial Matrix Table
  const advTableBody = document.querySelector("#adv-table tbody");
  const advData = data.modules?.unit_2_adversarial;
  if (advTableBody && advData?.tactics_matrix) {
    advTableBody.innerHTML = advData.tactics_matrix.map(row => {
      const statusBadge = row.evades_baseline 
        ? `<span style="color: var(--danger-red); font-weight: 700;">Evades Standard</span>` 
        : `<span style="color: var(--success-green); font-weight: 600;">Blocked</span>`;

      return `
        <tr>
          <td style="font-weight: 600;">${row.name}</td>
          <td><code style="font-size: 11px; color: var(--blue-primary);">${row.suppressed_features.join(', ')}</code></td>
          <td>${row.baseline_verdict} (Score ${row.baseline_score})</td>
          <td>${statusBadge}</td>
        </tr>
      `;
    }).join('');

    const advPill = document.getElementById("adv-summary-pill");
    if (advPill && advData.optimal_attacker_tactic) {
      advPill.textContent = `Optimal Counter: ${advData.optimal_attacker_tactic.name}`;
    }
  }
}

// Load Benchmark Data for Single-Page Table
async function loadBenchmarkData() {
  const tableBody = document.querySelector("#benchmark-table tbody");
  const cvDisp = document.getElementById("cv-mean-disp");
  if (!tableBody) return;

  try {
    const res = await fetch("/api/benchmark");
    const data = await res.json();

    tableBody.innerHTML = (data.table || []).map(row => `
      <tr>
        <td style="font-weight: 600;">${row.detector}</td>
        <td style="font-weight: 700; color: var(--blue-primary);">${(row.accuracy * 100).toFixed(1)}%</td>
        <td>${(row.precision * 100).toFixed(1)}%</td>
        <td>${(row.recall * 100).toFixed(1)}%</td>
        <td style="color: ${row.false_positives > 0 ? 'var(--warning-amber)' : 'inherit'}; font-weight: 600;">${row.false_positives}</td>
      </tr>
    `).join('');

    if (cvDisp && data.cross_validation) {
      cvDisp.textContent = `${(data.cross_validation.mean_accuracy * 100).toFixed(1)}% (5-Fold Cross Validation)`;
    }
  } catch (err) {
    console.error("Error loading benchmark:", err);
  }
}

// Toast helper
function showToast(msg) {
  const box = document.getElementById("toast-box");
  if (!box) return;
  const t = document.createElement("div");
  t.className = "toast-msg";
  t.innerHTML = `<span>🛡️</span> <span>${msg}</span>`;
  box.appendChild(t);
  setTimeout(() => {
    t.remove();
  }, 3500);
}
