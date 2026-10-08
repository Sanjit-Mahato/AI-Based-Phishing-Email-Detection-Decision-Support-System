/**
 * Main Application Logic
 * Cyber-Defense Decision Support System Controller
 */

const FEATURE_METADATA = {
  reply_to_mismatch: { name: "Reply-To Mismatch", desc: "Sender domain differs from return path header" },
  ip_in_url: { name: "IP Address in URL", desc: "Direct IP address used instead of valid domain name" },
  suspicious_tld: { name: "Suspicious TLD", desc: "Link points to high-risk top-level domain (.xyz, .club, etc.)" },
  urgency_words: { name: "Urgency Keywords", desc: "Psychological coercion cues detected in body text" },
  executable_attachment: { name: "Dangerous Attachment", desc: "Executable or high-risk file payload (.exe, .scr, etc.)" },
  no_https: { name: "Insecure Protocol (HTTP)", desc: "Hyperlink lacks SSL encryption" },
  long_url: { name: "Abnormally Long URL", desc: "URL length exceeds 75 chars or has excessive parameters" }
};

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  loadPresets();
  loadRules();
  loadBenchmarkData();
  setupForm();
  setupKaggleEval();
});

// Tab Switching
function setupTabs() {
  const tabs = document.querySelectorAll(".nav-tab-btn");
  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = `tab-${btn.dataset.tab}`;
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// Preset Loader
async function loadPresets() {
  const container = document.getElementById("presets-container");
  if (!container) return;

  try {
    const res = await fetch("/api/presets");
    const data = await res.json();
    const presets = data.presets || [];

    container.innerHTML = presets.map((p, idx) => `
      <button type="button" class="btn-preset" data-index="${idx}">
        ${p.name}
      </button>
    `).join('');

    container.querySelectorAll(".btn-preset").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = parseInt(btn.dataset.index, 10);
        const preset = presets[idx];
        const textarea = document.getElementById("email-raw");
        if (textarea && preset) {
          textarea.value = preset.text;
          showToast(`Loaded preset: ${preset.name}`);
          // Auto analyze
          document.getElementById("email-form").dispatchEvent(new Event("submit"));
        }
      });
    });

    // Auto-load first preset on startup
    if (presets.length > 0) {
      document.getElementById("email-raw").value = presets[0].text;
      document.getElementById("email-form").dispatchEvent(new Event("submit"));
    }
  } catch (err) {
    console.error("Error loading presets:", err);
  }
}

// Form Submission & Analysis
function setupForm() {
  const form = document.getElementById("email-form");
  const textarea = document.getElementById("email-raw");
  const submitBtn = document.getElementById("btn-analyze");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawText = textarea.value.trim();
    if (!rawText) {
      showToast("Please enter or paste an email first.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>⏳</span> Analyzing through AI modules...`;

    const startTime = performance.now();

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: rawText, include_adversarial: true })
      });

      const data = await res.json();
      const latency = Math.round(performance.now() - startTime);

      document.getElementById("eval-speed").textContent = `LATENCY: ${latency}ms`;
      renderAnalysisResult(data);
      showToast(`Analysis complete: Verdict is ${data.final_verdict}`);
    } catch (err) {
      console.error("Analysis error:", err);
      showToast("Error communicating with AI engine.");
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<span>⚡</span> Run Multi-Module AI Inference`;
    }
  });
}

// Render Results into UI
function renderAnalysisResult(data) {
  const verdict = data.final_verdict || "Safe";
  const verdictClass = verdict.toLowerCase();

  // 1. Verdict Banner
  const banner = document.getElementById("verdict-banner");
  banner.className = `verdict-card ${verdictClass}`;
  document.getElementById("verdict-title").textContent = verdict;
  document.getElementById("verdict-summary").textContent = data.summary_explanation || "Inference completed.";

  // Metrics
  document.getElementById("val-risk-index").textContent = `${data.risk_index} / 100`;
  document.getElementById("val-confidence").textContent = `${data.confidence_percentage}%`;

  // Multi-Module snapshot
  const u1 = data.modules.unit_1_heuristic;
  document.getElementById("u1-score-disp").textContent = `Score: ${u1.score}/${u1.max_score} (${u1.risk_level})`;

  const u3 = data.modules.unit_3_expert_system;
  document.getElementById("u3-rule-disp").textContent = `Proved: ${u3.backward_chaining.proved_verdict}`;

  const u4 = data.modules.unit_4_statistical;
  document.getElementById("u4-prob-disp").textContent = `${(u4.probability_phishing * 100).toFixed(1)}% (${u4.verdict})`;

  const u2 = data.modules.unit_2_adversarial;
  if (u2) {
    document.getElementById("u2-game-disp").textContent = `Payoff: ${u2.game_payoff} (${u2.optimal_attacker_tactic.name})`;
  }

  // 2. Actionable Advisories
  const advisoryContainer = document.getElementById("advisory-container");
  if (advisoryContainer) {
    advisoryContainer.innerHTML = (data.recommendations || []).map(r => `
      <div class="advisory-item ${r.level}">
        <div>
          <div class="advisory-action">${r.action}</div>
          <div class="advisory-detail">${r.detail}</div>
        </div>
      </div>
    `).join('');
  }

  // 3. Features Grid
  const featuresContainer = document.getElementById("features-grid-container");
  if (featuresContainer && data.features) {
    const evidence = data.evidence || {};
    featuresContainer.innerHTML = Object.keys(FEATURE_METADATA).map(key => {
      const meta = FEATURE_METADATA[key];
      const isActive = data.features[key] === 1;

      let detailSnippet = "";
      if (isActive && evidence[key]) {
        const evVal = evidence[key];
        detailSnippet = Array.isArray(evVal) ? evVal.join(', ') : String(evVal);
        if (detailSnippet.length > 50) detailSnippet = detailSnippet.substring(0, 50) + "...";
      }

      return `
        <div class="feature-pill ${isActive ? 'active' : ''}">
          <div class="feature-pill-header">
            <span class="feature-name">${meta.name}</span>
            <span class="status-dot"></span>
          </div>
          <div class="feature-desc">${meta.desc}</div>
          ${detailSnippet ? `<div style="margin-top: 6px; font-size: 11px; color: var(--cyan-primary); font-family: var(--font-mono);">${detailSnippet}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  // 4. Update Proof Tree in Tab 2
  if (u3.backward_chaining && typeof renderProofTree === 'function') {
    renderProofTree(u3.backward_chaining.proof_tree, "proof-tree-view");
  }

  // Forward Chaining trace
  const fcTrace = document.getElementById("forward-chain-trace");
  if (fcTrace && u3.forward_chaining) {
    const fc = u3.forward_chaining;
    if (fc.fired_rules && fc.fired_rules.length > 0) {
      fcTrace.innerHTML = fc.fired_rules.map(r => `
        <div style="margin-bottom: 8px;">
          <span style="color: var(--cyan-primary);">Step ${r.step}:</span> Rule <strong>${r.rule_id}</strong> fired!
          <br>&nbsp;&nbsp;Premises: <span style="color: var(--warning);">${r.premises.join(' ∧ ')}</span>
          <br>&nbsp;&nbsp;Derived: <span style="color: var(--success);">${r.derived}</span>
        </div>
      `).join('');
    } else {
      fcTrace.innerHTML = "<div>No Horn rules fired (No matching premise facts).</div>";
    }
  }

  // 5. Update Adversarial View in Tab 3
  if (u2 && typeof renderAdversarialView === 'function') {
    renderAdversarialView(u2);
  }
}

// Load Rules Catalog into Tab 2
async function loadRules() {
  const container = document.getElementById("rules-catalog-view");
  if (!container) return;

  try {
    const res = await fetch("/api/rules");
    const data = await res.json();
    const rules = data.rules || [];

    container.innerHTML = rules.map(r => `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px 12px; margin-bottom: 8px; font-size: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <span style="color: var(--cyan-primary); font-family: var(--font-mono); font-weight: 700;">${r.rule_id}: ${r.premises.join(' ∧ ')} ➔ ${r.conclusion}</span>
          <span class="badge-tag" style="padding: 2px 6px; font-size: 10px;">${r.conclusion.toUpperCase()}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 11px;">${r.description}</div>
      </div>
    `).join('');
  } catch (err) {
    console.error("Error loading rules:", err);
  }
}

// Load Benchmark Data in Tab 4
async function loadBenchmarkData() {
  const btn = document.getElementById("btn-run-benchmark");
  if (btn) btn.addEventListener("click", fetchBenchmark);

  fetchBenchmark();
}

async function fetchBenchmark() {
  const tableBody = document.querySelector("#benchmark-table tbody");
  const cvDisp = document.getElementById("cv-scores-disp");
  if (!tableBody) return;

  try {
    tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Evaluating 60 test emails...</td></tr>`;
    const res = await fetch("/api/benchmark");
    const data = await res.json();

    tableBody.innerHTML = (data.table || []).map(row => `
      <tr>
        <td style="font-weight: 600; color: #fff;">${row.detector}</td>
        <td style="color: var(--cyan-primary); font-weight: 700;">${row.accuracy.toFixed(3)}</td>
        <td>${row.precision.toFixed(3)}</td>
        <td>${row.recall.toFixed(3)}</td>
        <td style="color: ${row.false_positives > 0 ? 'var(--warning)' : 'var(--text-muted)'};">${row.false_positives}</td>
        <td>${row.false_negatives}</td>
      </tr>
    `).join('');

    if (cvDisp && data.cross_validation) {
      const cv = data.cross_validation;
      cvDisp.innerHTML = `
        Folds Accuracies: <strong>${cv.fold_accuracies.join(', ')}</strong><br>
        Mean Accuracy: <strong style="color: var(--success);">${(cv.mean_accuracy * 100).toFixed(1)}%</strong> (± ${(cv.std_accuracy * 100).toFixed(2)}%)
      `;
    }
  } catch (err) {
    console.error("Error loading benchmark:", err);
  }
}

// Kaggle Dataset Evaluation
function setupKaggleEval() {
  const btn = document.getElementById("btn-eval-kaggle");
  const select = document.getElementById("kaggle-sample-select");
  const container = document.getElementById("kaggle-results-container");

  if (!btn) return;

  btn.addEventListener("click", async () => {
    const samples = parseInt(select.value, 10);
    btn.disabled = true;
    btn.innerHTML = `<span>⏳</span> Streaming & Training...`;

    try {
      const res = await fetch("/api/kaggle-eval", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ samples: samples })
      });

      const data = await res.json();
      if (data.error) {
        showToast(data.error);
        return;
      }

      container.style.display = "block";
      const m = data.metrics;
      container.innerHTML = `
        <div class="metrics-row" style="margin-top: 14px;">
          <div class="metric-box">
            <div class="metric-label">Kaggle Accuracy</div>
            <div class="metric-value" style="color: var(--success);">${(m.accuracy * 100).toFixed(1)}%</div>
          </div>
          <div class="metric-box">
            <div class="metric-label">Recall / Sensitivity</div>
            <div class="metric-value" style="color: var(--cyan-primary);">${(m.recall * 100).toFixed(1)}%</div>
          </div>
        </div>
        <div style="margin-top: 10px; font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">
          Evaluated: ${data.samples_evaluated} emails (Test set: ${data.test_size}) | TP: ${m.true_positives}, FP: ${m.false_positives}, TN: ${m.true_negatives}, FN: ${m.false_negatives}
        </div>
      `;
      showToast(`Kaggle evaluation completed on ${data.samples_evaluated} samples!`);
    } catch (err) {
      console.error("Kaggle evaluation error:", err);
      showToast("Failed to run Kaggle evaluation.");
    } finally {
      btn.disabled = false;
      btn.innerHTML = `Run Evaluation on Kaggle Dataset`;
    }
  });
}

// Toast helper
function showToast(msg) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `<span>🛡️</span> <span>${msg}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.remove();
  }, 4000);
}
