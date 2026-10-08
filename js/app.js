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
  setupBatchCSVScanner();
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

// ==========================================================================
// Batch CSV Upload & Threat Intelligence Audit Controller
// ==========================================================================
let currentCsvContent = "";
let currentBatchReportData = null;
let currentBatchFilter = "ALL";

function setupBatchCSVScanner() {
  const dropzone = document.getElementById("csv-dropzone");
  const fileInput = document.getElementById("csv-file-input");
  const loadSampleBtn = document.getElementById("btn-load-sample-csv");
  const runBatchBtn = document.getElementById("btn-run-batch");
  const exportBtn = document.getElementById("btn-export-csv-report");
  const statusElem = document.getElementById("csv-selected-status");
  const dropLabel = document.getElementById("dropzone-label");
  const dropSub = document.getElementById("dropzone-sublabel");

  if (!dropzone || !fileInput) return;

  // 1. File Input Change
  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) handleFileSelected(file);
  });

  // 2. Drag & Drop events
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      handleFileSelected(file);
    }
  });

  function handleFileSelected(file) {
    if (!file.name.toLowerCase().endsWith(".csv")) {
      showToast("Please upload a valid .csv file.");
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      currentCsvContent = event.target.result;
      const sizeKb = (file.size / 1024).toFixed(1);
      dropLabel.textContent = `Selected: ${file.name} (${sizeKb} KB)`;
      dropSub.textContent = "Ready to analyze. Click 'Analyze Entire CSV' below.";
      statusElem.textContent = `${file.name} loaded`;
      showToast(`Loaded ${file.name} successfully.`);
    };
    reader.onerror = () => {
      showToast("Failed to read the selected CSV file.");
    };
    reader.readAsText(file);
  }

  // 3. Load Sample CSV Button
  if (loadSampleBtn) {
    loadSampleBtn.addEventListener("click", async () => {
      try {
        loadSampleBtn.disabled = true;
        loadSampleBtn.innerHTML = `<span>⏳</span> Fetching Sample...`;
        const res = await fetch("/api/sample-csv");
        const data = await res.json();

        if (data.csv_text) {
          currentCsvContent = data.csv_text;
          dropLabel.textContent = `Loaded: sample_email_list.csv (15 Emails)`;
          dropSub.textContent = "Multi-threat benchmark batch loaded. Click 'Analyze Entire CSV'.";
          statusElem.textContent = "sample_email_list.csv active";
          showToast("Loaded sample email list CSV.");
        } else {
          showToast("Could not load sample CSV.");
        }
      } catch (err) {
        console.error("Error loading sample CSV:", err);
        showToast("Error loading sample CSV file.");
      } finally {
        loadSampleBtn.disabled = false;
        loadSampleBtn.innerHTML = `<span>📄</span> Load Sample CSV (15 Emails)`;
      }
    });
  }

  // 4. Run Batch Analysis Button
  if (runBatchBtn) {
    runBatchBtn.addEventListener("click", async () => {
      if (!currentCsvContent) {
        showToast("Please select or load a CSV file first.");
        return;
      }

      const maxRows = parseInt(document.getElementById("batch-max-rows")?.value || "250", 10);
      runBatchBtn.disabled = true;
      runBatchBtn.innerHTML = `<span>⏳</span> Analyzing Batch...`;

      const startTime = performance.now();

      try {
        const res = await fetch("/api/batch-analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ csv_content: currentCsvContent, max_rows: maxRows })
        });

        const report = await res.json();
        const latency = Math.round(performance.now() - startTime);

        if (report.error) {
          showToast(report.error);
          return;
        }

        currentBatchReportData = report;
        renderBatchReport(report);
        showToast(`Analyzed ${report.summary.total_scanned} emails in ${latency}ms.`);
      } catch (err) {
        console.error("Batch analyze error:", err);
        showToast("Failed to run batch analysis.");
      } finally {
        runBatchBtn.disabled = false;
        runBatchBtn.innerHTML = `<span>⚡</span> Analyze Entire CSV`;
      }
    });
  }

  // 5. Filter Tabs setup
  const filterTabs = document.querySelectorAll(".filter-tab");
  filterTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      filterTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentBatchFilter = tab.dataset.filter;
      if (currentBatchReportData) {
        renderBatchTableRows(currentBatchReportData.results, currentBatchFilter);
      }
    });
  });

  // 6. Export CSV Button
  if (exportBtn) {
    exportBtn.addEventListener("click", exportBatchCsvReport);
  }
}

// Render the Entire Batch Report Area
function renderBatchReport(report) {
  const reportArea = document.getElementById("batch-report-area");
  if (!reportArea) return;

  reportArea.style.display = "block";
  document.getElementById("batch-timestamp").textContent = `Generated: ${new Date().toLocaleTimeString()} (Scanned ${report.summary.total_scanned} records)`;

  // Summary KPIs
  const s = report.summary;
  document.getElementById("kpi-total").textContent = s.total_scanned;
  document.getElementById("kpi-phishing").textContent = s.phishing_count;
  document.getElementById("kpi-phishing-pct").textContent = `${s.phishing_percentage}% of batch`;
  document.getElementById("kpi-suspicious").textContent = s.suspicious_count;
  document.getElementById("kpi-suspicious-pct").textContent = `${s.suspicious_percentage}% of batch`;
  document.getElementById("kpi-safe").textContent = s.safe_count;
  document.getElementById("kpi-safe-pct").textContent = `${s.safe_percentage}% of batch`;
  document.getElementById("kpi-avg-risk").textContent = `${s.average_risk_score} / 100`;

  // Filter button counts
  document.getElementById("count-all").textContent = s.total_scanned;
  document.getElementById("count-phishing").textContent = s.phishing_count;
  document.getElementById("count-suspicious").textContent = s.suspicious_count;
  document.getElementById("count-safe").textContent = s.safe_count;

  // Prevalence Bars
  const prevContainer = document.getElementById("batch-prevalence-container");
  if (prevContainer && report.indicator_prevalence) {
    const prev = report.indicator_prevalence;
    prevContainer.innerHTML = Object.keys(INDICATOR_DETAILS).map(key => {
      const meta = INDICATOR_DETAILS[key];
      const stats = prev[key] || { count: 0, percentage: 0 };
      const barColor = stats.percentage > 30 ? "var(--danger-red)" : (stats.percentage > 10 ? "var(--warning-amber)" : "var(--blue-primary)");

      return `
        <div class="prev-bar-box">
          <div class="prev-bar-header">
            <span>${meta.title}</span>
            <span style="font-family: var(--font-mono); color: ${barColor};">${stats.percentage}% (${stats.count})</span>
          </div>
          <div class="prev-bar-track">
            <div class="prev-bar-fill" style="width: ${stats.percentage}%; background: ${barColor};"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Table
  renderBatchTableRows(report.results, currentBatchFilter);
  reportArea.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Render Filtered Table Rows
function renderBatchTableRows(items, filter) {
  const tbody = document.querySelector("#batch-results-table tbody");
  if (!tbody || !items) return;

  const filtered = items.filter(item => {
    if (filter === "ALL") return true;
    return item.verdict.toLowerCase() === filter.toLowerCase();
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No emails match the selected filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(row => {
    const verdictClass = row.verdict === "Phishing" ? "badge-flagged" : (row.verdict === "Suspicious" ? "badge-flagged" : "badge-clean");
    const riskColor = row.risk_score >= 60 ? "var(--danger-red)" : (row.risk_score >= 30 ? "var(--warning-amber)" : "var(--success-green)");

    const flagsBadges = row.active_flags.length > 0 
      ? row.active_flags.map(f => `<span class="badge-flagged" style="font-size: 10px; padding: 2px 5px; margin-right: 4px; display: inline-block; margin-bottom: 2px;">${f.replace(/_/g, ' ')}</span>`).join('')
      : `<span style="color: var(--text-muted); font-size: 11px;">None</span>`;

    return `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--text-muted); font-weight: 600;">#${row.row_id}</td>
        <td style="font-weight: 600; font-size: 12px; color: var(--text-dark);">${escapeHtml(row.sender)}</td>
        <td style="font-weight: 600; font-size: 12px; color: var(--blue-primary);">${escapeHtml(row.subject)}</td>
        <td style="font-size: 11px; color: var(--text-muted); max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(row.snippet)}">
          ${escapeHtml(row.snippet)}
        </td>
        <td><span class="${verdictClass}">${row.verdict}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${riskColor};">${row.risk_score}</td>
        <td>${flagsBadges}</td>
        <td style="font-size: 11px; color: var(--text-dark); font-weight: 600;">${escapeHtml(row.action)}</td>
      </tr>
    `;
  }).join('');
}

// Client-Side CSV Report Generator & Downloader
function exportBatchCsvReport() {
  if (!currentBatchReportData || !currentBatchReportData.results) {
    showToast("No analyzed report available to export.");
    return;
  }

  const items = currentBatchReportData.results;
  const headers = [
    "Row ID", "Sender", "Subject", "Email Snippet", "Verdict", 
    "Risk Score", "Confidence %", "Triggered Flags Count", 
    "Triggered Indicators", "Decision Reason", "Recommended Action"
  ];

  const csvRows = [headers.join(",")];

  items.forEach(row => {
    const escapeCsv = (val) => `"${String(val || '').replace(/"/g, '""')}"`;
    csvRows.push([
      row.row_id,
      escapeCsv(row.sender),
      escapeCsv(row.subject),
      escapeCsv(row.snippet),
      escapeCsv(row.verdict),
      row.risk_score,
      row.confidence,
      row.flags_count,
      escapeCsv(row.active_flags.join("; ")),
      escapeCsv(row.primary_reason),
      escapeCsv(row.action)
    ].join(","));
  });

  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishing_threat_audit_report_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast("Audit report CSV downloaded!");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

