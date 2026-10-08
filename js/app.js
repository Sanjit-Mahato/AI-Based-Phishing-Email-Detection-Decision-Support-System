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
  setupBatchCSVScanner();
  setupEmailDetailModal();
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

// Render Filtered Table Rows with Clickable Rows & Read Button
function renderBatchTableRows(items, filter) {
  const tbody = document.querySelector("#batch-results-table tbody");
  if (!tbody || !items) return;

  const filtered = items.filter(item => {
    if (filter === "ALL") return true;
    return item.verdict.toLowerCase() === filter.toLowerCase();
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No emails match the selected filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(row => {
    const verdictClass = row.verdict === "Phishing" ? "badge-flagged" : (row.verdict === "Suspicious" ? "badge-flagged" : "badge-clean");
    const riskColor = row.risk_score >= 60 ? "var(--danger-red)" : (row.risk_score >= 30 ? "var(--warning-amber)" : "var(--success-green)");

    const flagsBadges = row.active_flags.length > 0 
      ? row.active_flags.map(f => `<span class="badge-flagged" style="font-size: 10px; padding: 2px 5px; margin-right: 4px; display: inline-block; margin-bottom: 2px;">${f.replace(/_/g, ' ')}</span>`).join('')
      : `<span style="color: var(--text-muted); font-size: 11px;">None</span>`;

    return `
      <tr class="clickable-row" data-row-id="${row.row_id}" title="Click to view full email content">
        <td style="font-family: var(--font-mono); color: var(--text-muted); font-weight: 600;">#${row.row_id}</td>
        <td style="font-weight: 600; font-size: 12px; color: var(--text-dark);">${escapeHtml(row.sender)}</td>
        <td style="font-weight: 600; font-size: 12px; color: var(--blue-primary);">
          <span style="text-decoration: underline; text-decoration-color: rgba(26, 86, 219, 0.3);">${escapeHtml(row.subject)}</span>
        </td>
        <td style="font-size: 11px; color: var(--text-muted); max-width: 240px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(row.snippet)}">
          ${escapeHtml(row.snippet)}
        </td>
        <td><span class="${verdictClass}">${row.verdict}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${riskColor};">${row.risk_score}</td>
        <td>${flagsBadges}</td>
        <td style="font-size: 11px; color: var(--text-dark); font-weight: 600;">${escapeHtml(row.action)}</td>
        <td style="text-align: center;">
          <button type="button" class="btn-table-view" data-row-id="${row.row_id}">
            <span>👁️</span> Read
          </button>
        </td>
      </tr>
    `;
  }).join('');

  // Attach click listener to table rows and read buttons
  tbody.querySelectorAll(".clickable-row").forEach(tr => {
    tr.addEventListener("click", () => {
      const rowId = parseInt(tr.dataset.rowId, 10);
      openEmailDetailModal(rowId);
    });
  });
}

// ==========================================================================
// Email Detail Inspection Modal Controller
// ==========================================================================
let activeModalEmail = null;

function setupEmailDetailModal() {
  const modal = document.getElementById("email-detail-modal");
  const closeBtn = document.getElementById("btn-close-modal");
  const doneBtn = document.getElementById("btn-modal-done");
  const copyBtn = document.getElementById("btn-copy-email-content");
  const scannerBtn = document.getElementById("btn-load-in-scanner");

  if (!modal) return;

  function closeModal() {
    modal.classList.remove("open");
    activeModalEmail = null;
  }

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (doneBtn) doneBtn.addEventListener("click", closeModal);

  // Close when clicking the backdrop
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });

  // Escape key handler
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("open")) {
      closeModal();
    }
  });

  // Copy email text button
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      if (!activeModalEmail) return;
      const textToCopy = activeModalEmail.full_email || activeModalEmail.body || activeModalEmail.snippet;
      try {
        await navigator.clipboard.writeText(textToCopy);
        showToast("Email text copied to clipboard!");
      } catch (err) {
        const ta = document.createElement("textarea");
        ta.value = textToCopy;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        showToast("Email text copied to clipboard!");
      }
    });
  }

  // Load into single live scanner
  if (scannerBtn) {
    scannerBtn.addEventListener("click", () => {
      if (!activeModalEmail) return;
      const emailInput = document.getElementById("email-content");
      if (emailInput) {
        emailInput.value = activeModalEmail.full_email || activeModalEmail.body || activeModalEmail.snippet;
        closeModal();
        const scannerSec = document.getElementById("single-scanner-section");
        if (scannerSec) {
          scannerSec.scrollIntoView({ behavior: "smooth" });
        }
        const scanBtn = document.getElementById("btn-scan");
        if (scanBtn) {
          setTimeout(() => scanBtn.click(), 300);
        }
        showToast(`Loaded Email #${activeModalEmail.row_id} into Live Scanner.`);
      }
    });
  }
}

function openEmailDetailModal(rowId) {
  if (!currentBatchReportData || !currentBatchReportData.results) return;

  const item = currentBatchReportData.results.find(r => r.row_id === rowId);
  if (!item) return;

  activeModalEmail = item;
  const modal = document.getElementById("email-detail-modal");
  if (!modal) return;

  // Header info
  document.getElementById("modal-email-id").textContent = `#${item.row_id}`;
  document.getElementById("modal-email-subject").textContent = item.subject || "(No Subject)";
  document.getElementById("modal-email-sender").textContent = item.sender || "N/A";

  const replyToWrap = document.getElementById("modal-reply-to-wrap");
  const replyToElem = document.getElementById("modal-email-reply-to");
  if (item.reply_to && item.reply_to !== item.sender) {
    replyToElem.textContent = item.reply_to;
    replyToWrap.style.display = "inline";
  } else {
    replyToWrap.style.display = "none";
  }

  // Verdict & Risk
  const verdictElem = document.getElementById("modal-email-verdict");
  verdictElem.textContent = item.verdict.toUpperCase();
  verdictElem.className = item.verdict === "Phishing" ? "badge-flagged" : (item.verdict === "Suspicious" ? "badge-flagged" : "badge-clean");

  const riskElem = document.getElementById("modal-email-risk");
  riskElem.textContent = `Risk: ${item.risk_score}/100 (${item.confidence}% Conf)`;
  riskElem.style.color = item.risk_score >= 60 ? "var(--danger-red)" : (item.risk_score >= 30 ? "var(--warning-amber)" : "var(--success-green)");

  // Reasoning
  document.getElementById("modal-email-reason").textContent = item.primary_reason || "Evaluation completed with no anomalous indicators.";

  // Active Flags Badges
  const flagsContainer = document.getElementById("modal-email-flags");
  if (item.active_flags && item.active_flags.length > 0) {
    flagsContainer.innerHTML = item.active_flags.map(flag => `
      <span class="badge-flagged" style="font-size: 11px; padding: 4px 8px;">
        ⚠️ ${flag.replace(/_/g, ' ')}
      </span>
    `).join('');
  } else {
    flagsContainer.innerHTML = `<span class="badge-clean" style="font-size: 11px; padding: 4px 8px;">✓ No Threat Indicators Triggered</span>`;
  }

  // Detected URLs
  const urlsBox = document.getElementById("modal-urls-box");
  const urlsList = document.getElementById("modal-urls-list");
  if (item.urls && item.urls.length > 0) {
    urlsBox.style.display = "block";
    urlsList.innerHTML = item.urls.map(u => `<div class="modal-url-pill">🔗 ${escapeHtml(u)}</div>`).join('');
  } else {
    urlsBox.style.display = "none";
  }

  // Detected Attachments
  const attBox = document.getElementById("modal-attachments-box");
  const attList = document.getElementById("modal-attachments-list");
  if (item.attachments && item.attachments.length > 0) {
    attBox.style.display = "block";
    attList.innerHTML = item.attachments.map(a => `<div class="modal-attachment-pill">📎 ${escapeHtml(a)}</div>`).join('');
  } else {
    attBox.style.display = "none";
  }

  // Full Email Content
  const fullContentElem = document.getElementById("modal-email-content");
  fullContentElem.textContent = item.full_email || item.body || item.snippet;

  // Action Recommendation
  document.getElementById("modal-email-action").textContent = item.action || "Standard Verification";

  // Display modal
  modal.classList.add("open");
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

