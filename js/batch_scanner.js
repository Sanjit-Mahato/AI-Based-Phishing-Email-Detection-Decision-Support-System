/**
 * Batch CSV Fleet Threat Intelligence Controller
 * Handles drag-and-drop CSV upload, batch analysis execution, KPI telemetry,
 * indicator prevalence bars, interactive search/pagination, inspection modal, and CSV export.
 */

let currentCsvContent = "";
let currentBatchReportData = null;
let currentBatchFilter = "ALL";
let currentSearchQuery = "";
let currentBatchPage = 1;
const PAGE_SIZE = 15;

function setupBatchCSVScanner() {
  const dropzone = document.getElementById("csv-dropzone");
  const fileInput = document.getElementById("csv-file-input");
  const loadSampleBtn = document.getElementById("btn-load-sample-csv");
  const runBatchBtn = document.getElementById("btn-run-batch");
  const exportBtn = document.getElementById("btn-export-csv-report");
  const searchInput = document.getElementById("batch-search-input");
  const prevPageBtn = document.getElementById("btn-page-prev");
  const nextPageBtn = document.getElementById("btn-page-next");

  if (!dropzone || !fileInput) return;

  // 1. Dropzone click & file change
  dropzone.addEventListener("click", (e) => {
    if (e.target !== fileInput) {
      fileInput.click();
    }
  });

  fileInput.addEventListener("click", (e) => {
    e.stopPropagation();
  });

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) handleFileSelected(file);
    fileInput.value = ""; // Reset so re-uploading the same file works
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
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  function handleFileSelected(file) {
    if (!file.name.toLowerCase().endsWith(".csv")) {
      showToast("Please upload a valid .csv file.");
      return;
    }

    // Limit read chunk to 30 MB (covers datasets up to 30MB entirely)
    const MAX_READ_BYTES = 30 * 1024 * 1024;
    const isLarge = file.size > MAX_READ_BYTES;
    const blobToRead = isLarge ? file.slice(0, MAX_READ_BYTES) : file;

    const sizeKb = (file.size / 1024).toFixed(1);
    const dropLabel = document.getElementById("dropzone-label");
    const dropSub = document.getElementById("dropzone-sublabel");
    const statusBadge = document.getElementById("csv-selected-status");

    if (dropLabel) dropLabel.textContent = `Selected: ${file.name} (${sizeKb} KB)`;
    if (dropSub) dropSub.textContent = "Reading CSV file and checking emails...";
    if (statusBadge) statusBadge.textContent = `${file.name} loading...`;

    const reader = new FileReader();
    reader.onload = (event) => {
      let content = event.target.result;
      if (isLarge) {
        // Cleanly slice at the last complete row to avoid incomplete quotes/rows
        const lastNl = content.lastIndexOf('\n');
        if (lastNl > 0) {
          content = content.substring(0, lastNl);
        }
      }
      currentCsvContent = content;
      if (dropLabel) dropLabel.textContent = `Active: ${file.name} (${sizeKb} KB)`;
      if (dropSub) dropSub.textContent = isLarge
        ? "Large dataset: top chunk loaded for instant scanning."
        : "File loaded. Scanning emails...";
      if (statusBadge) statusBadge.textContent = `${file.name} ready`;
      showToast(`Loaded ${file.name}. Scanning...`);

      // Automatically execute fleet analysis on upload
      triggerBatchAnalysis();
    };
    reader.onerror = () => {
      showToast("Could not read CSV file.");
      if (dropSub) dropSub.textContent = "Error reading file from disk.";
    };
    reader.readAsText(blobToRead);
  }

  // 3. Load Sample CSV
  if (loadSampleBtn) {
    loadSampleBtn.addEventListener("click", async () => {
      try {
        loadSampleBtn.disabled = true;
        loadSampleBtn.innerHTML = `<span class="btn-spinner"></span> Loading Sample...`;

        let sampleCsvText = "";
        try {
          const res = await fetch("/api/sample-csv");
          const data = await res.json();
          if (data && data.csv_text) {
            sampleCsvText = data.csv_text;
          }
        } catch (_) {}

        if (!sampleCsvText && window.PhishRadarEngine && window.PhishRadarEngine.sampleCsv) {
          sampleCsvText = window.PhishRadarEngine.sampleCsv;
        }

        if (sampleCsvText) {
          currentCsvContent = sampleCsvText;
          document.getElementById("dropzone-label").textContent = "Loaded: sample_email_list.csv (15 Emails)";
          document.getElementById("dropzone-sublabel").textContent = "Sample list active. Scanning...";
          document.getElementById("csv-selected-status").textContent = "sample_email_list.csv ready";
          showToast("Loaded sample list. Scanning...");
          triggerBatchAnalysis();
        } else {
          showToast("Could not load sample CSV.");
        }
      } catch (err) {
        console.error("Error loading sample CSV:", err);
        showToast("Error retrieving sample list.");
      } finally {
        loadSampleBtn.disabled = false;
        loadSampleBtn.innerHTML = `
          <svg class="ui-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          <span>Load Sample List (15 Emails)</span>
        `;
      }
    });
  }

  // 4. Batch Analysis Trigger Logic
  async function triggerBatchAnalysis() {
    if (!currentCsvContent) {
      showToast("Please select or load a CSV file first.");
      return;
    }

    const maxRows = parseInt(document.getElementById("batch-max-rows")?.value || "250", 10);
    const runBtn = document.getElementById("btn-run-batch");
    if (runBtn) {
      runBtn.disabled = true;
      runBtn.innerHTML = `<span class="btn-spinner"></span> Scanning emails...`;
    }

    const dropSub = document.getElementById("dropzone-sublabel");
    if (dropSub) dropSub.textContent = "Checking emails for scams and fake links...";

    const startTime = performance.now();

    try {
      const res = await fetch("/api/batch-analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csv_content: currentCsvContent, max_rows: maxRows })
      });

      if (!res.ok) {
        let errMsg = `Server returned HTTP ${res.status}`;
        try {
          const errData = await res.json();
          if (errData && errData.error) errMsg = errData.error;
        } catch (_) {}
        showToast(`Scan failed: ${errMsg}`);
        if (dropSub) dropSub.textContent = "Error scanning file. Please check CSV format.";
        return;
      }

      const report = await res.json();
      const latency = Math.round(performance.now() - startTime);

      if (report.error) {
        showToast(report.error);
        if (dropSub) dropSub.textContent = report.error;
        return;
      }

      currentBatchReportData = report;
      currentBatchPage = 1;
      renderBatchReport(report);

      const totalCount = (report.summary && report.summary.total_scanned !== undefined)
        ? report.summary.total_scanned
        : (report.results ? report.results.length : (report.rows ? report.rows.length : 0));

      if (dropSub) dropSub.textContent = `Completed scan of ${totalCount} emails in ${latency}ms.`;
      showToast(`Checked ${totalCount} emails in ${latency}ms.`);
    } catch (err) {
      console.error("Batch analyze error:", err);
      showToast("Failed to run email scan. Check connection.");
      if (dropSub) dropSub.textContent = "Scan failed. Please try again.";
    } finally {
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.innerHTML = `
          <svg class="ui-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg>
          <span>Scan All Emails</span>
        `;
      }
    }
  }

  // Bind Run Batch Button
  if (runBatchBtn) {
    runBatchBtn.addEventListener("click", () => {
      triggerBatchAnalysis();
    });
  }

  // Bind Max Rows Dropdown Change
  const maxRowsSelect = document.getElementById("batch-max-rows");
  if (maxRowsSelect) {
    maxRowsSelect.addEventListener("change", () => {
      if (currentCsvContent) {
        triggerBatchAnalysis();
      }
    });
  }

  // 5. Filter Tabs
  document.querySelectorAll(".filter-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentBatchFilter = tab.dataset.filter;
      currentBatchPage = 1;
      if (currentBatchReportData) {
        renderFilteredTable();
      }
    });
  });

  // 6. Search input
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentSearchQuery = e.target.value.toLowerCase().trim();
      currentBatchPage = 1;
      if (currentBatchReportData) {
        renderFilteredTable();
      }
    });
  }

  // 7. Pagination buttons
  if (prevPageBtn) {
    prevPageBtn.addEventListener("click", () => {
      if (currentBatchPage > 1) {
        currentBatchPage--;
        renderFilteredTable();
      }
    });
  }

  if (nextPageBtn) {
    nextPageBtn.addEventListener("click", () => {
      currentBatchPage++;
      renderFilteredTable();
    });
  }

  // 8. Export CSV
  if (exportBtn) {
    exportBtn.addEventListener("click", exportBatchCsvReport);
  }

  // Setup Email Inspection Modal Listeners
  setupEmailDetailModal();
}

// Render Batch Report Visuals
function renderBatchReport(report) {
  const reportArea = document.getElementById("batch-report-area");
  if (!reportArea) return;

  reportArea.style.display = "block";

  const allItems = report.results || report.rows || [];

  // Summary KPIs with safe fallbacks
  const s = report.summary || {};
  const total = (s.total_scanned !== undefined && s.total_scanned !== 0) ? s.total_scanned : allItems.length;
  const phish = (s.phishing_count !== undefined) ? s.phishing_count : allItems.filter(r => r.verdict === 'Phishing').length;
  const susp = (s.suspicious_count !== undefined) ? s.suspicious_count : allItems.filter(r => r.verdict === 'Suspicious').length;
  const safe = (s.safe_count !== undefined) ? s.safe_count : allItems.filter(r => r.verdict === 'Safe').length;

  const phishPct = total > 0 ? (s.phishing_percentage !== undefined ? s.phishing_percentage : Math.round((phish / total) * 100)) : 0;
  const suspPct = total > 0 ? (s.suspicious_percentage !== undefined ? s.suspicious_percentage : Math.round((susp / total) * 100)) : 0;
  const safePct = total > 0 ? (s.safe_percentage !== undefined ? s.safe_percentage : Math.round((safe / total) * 100)) : 0;
  const avgRisk = s.average_risk_score !== undefined
    ? s.average_risk_score
    : (total > 0 ? Math.round(allItems.reduce((a, b) => a + (b.risk_score || 0), 0) / total) : 0);

  document.getElementById("kpi-total").textContent = total;
  document.getElementById("kpi-phishing").textContent = phish;
  document.getElementById("kpi-phishing-pct").textContent = `${phishPct}% of batch`;
  document.getElementById("kpi-suspicious").textContent = susp;
  document.getElementById("kpi-suspicious-pct").textContent = `${suspPct}% of batch`;
  document.getElementById("kpi-safe").textContent = safe;
  document.getElementById("kpi-safe-pct").textContent = `${safePct}% of batch`;
  document.getElementById("kpi-avg-risk").textContent = `${avgRisk} / 100`;

  // Filter button counts
  document.getElementById("count-all").textContent = total;
  document.getElementById("count-phishing").textContent = phish;
  document.getElementById("count-suspicious").textContent = susp;
  document.getElementById("count-safe").textContent = safe;

  // Prevalence Bars
  const prevContainer = document.getElementById("batch-prevalence-container");
  if (prevContainer) {
    const prev = report.indicator_prevalence || {};
    const metaDict = (typeof CORE_INDICATOR_METADATA !== "undefined") ? CORE_INDICATOR_METADATA : {
      reply_to_mismatch: { title: "Fake Sender Address" },
      ip_in_url: { title: "IP Number Link" },
      suspicious_tld: { title: "Risky Website Ending" },
      urgency_words: { title: "Urgent Pressure Words" },
      executable_attachment: { title: "Dangerous File" },
      no_https: { title: "Insecure Link (HTTP)" },
      long_url: { title: "Suspicious Long Link" }
    };
    prevContainer.innerHTML = Object.keys(metaDict).map(key => {
      const meta = metaDict[key] || { title: key.replace(/_/g, ' ') };
      const rawStat = prev[key];
      const count = typeof rawStat === "object" && rawStat !== null ? (rawStat.count || 0) : (Number(rawStat) || 0);
      const percentage = typeof rawStat === "object" && rawStat !== null && rawStat.percentage !== undefined
        ? rawStat.percentage
        : (total > 0 ? Math.round((count / total) * 100) : 0);
      const barColor = percentage > 35 ? "var(--threat-phish)" : (percentage > 15 ? "var(--threat-suspicious)" : "var(--accent-cyan)");

      return `
        <div class="prev-bar-box">
          <div class="prev-bar-header">
            <span>${escapeHtmlBatch(meta.title)}</span>
            <span style="font-family: var(--font-mono); color: ${barColor};">${percentage}% (${count})</span>
          </div>
          <div class="prev-bar-track">
            <div class="prev-bar-fill" style="width: ${percentage}%; background: ${barColor};"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  renderFilteredTable();
  reportArea.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Render Filtered Table with Pagination
function renderFilteredTable() {
  if (!currentBatchReportData) return;

  const items = currentBatchReportData.results || currentBatchReportData.rows || [];
  if (!items || items.length === 0) return;

  const tbody = document.querySelector("#batch-results-table tbody");
  if (!tbody) return;

  // Filter by Verdict Tab
  let filtered = items.filter(item => {
    if (currentBatchFilter === "ALL") return true;
    return (item.verdict || "").toLowerCase() === currentBatchFilter.toLowerCase();
  });

  // Filter by Search Query
  if (currentSearchQuery) {
    filtered = filtered.filter(item => {
      const s = (item.sender || "").toLowerCase();
      const sub = (item.subject || "").toLowerCase();
      const snip = (item.snippet || "").toLowerCase();
      const raw = (item.raw_content || "").toLowerCase();
      return s.includes(currentSearchQuery) || sub.includes(currentSearchQuery) || snip.includes(currentSearchQuery) || raw.includes(currentSearchQuery);
    });
  }

  const totalFiltered = filtered.length;
  const totalPages = Math.max(1, Math.ceil(totalFiltered / PAGE_SIZE));
  if (currentBatchPage > totalPages) currentBatchPage = totalPages;

  const startIndex = (currentBatchPage - 1) * PAGE_SIZE;
  const pageItems = filtered.slice(startIndex, startIndex + PAGE_SIZE);

  // Update pagination info
  const pageInfo = document.getElementById("batch-pagination-info");
  if (pageInfo) {
    const endCount = Math.min(startIndex + pageItems.length, totalFiltered);
    pageInfo.textContent = totalFiltered > 0
      ? `Showing ${startIndex + 1} - ${endCount} of ${totalFiltered} emails`
      : `Showing 0 of 0 emails`;
  }

  const currentPageDisp = document.getElementById("batch-current-page");
  if (currentPageDisp) currentPageDisp.textContent = `Page ${currentBatchPage} of ${totalPages}`;

  const prevBtn = document.getElementById("btn-page-prev");
  const nextBtn = document.getElementById("btn-page-next");
  if (prevBtn) prevBtn.disabled = currentBatchPage <= 1;
  if (nextBtn) nextBtn.disabled = currentBatchPage >= totalPages;

  if (pageItems.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No emails match the selected criteria.</td></tr>`;
    return;
  }

  const flagNames = {
    reply_to_mismatch: "Fake Sender",
    ip_in_url: "IP Link",
    suspicious_tld: "Risky Ending",
    urgency_words: "Urgent Words",
    executable_attachment: "Dangerous File",
    no_https: "Insecure Link",
    long_url: "Long Link"
  };

  tbody.innerHTML = pageItems.map(row => {
    const v = row.verdict || "Safe";
    const verdictClass = v === "Phishing" ? "phish" : (v === "Suspicious" ? "suspicious" : "safe");
    const riskColor = row.risk_score >= 60 ? "var(--threat-phish)" : (row.risk_score >= 30 ? "var(--threat-suspicious)" : "var(--threat-safe)");

    const flagsBadges = (row.active_flags && row.active_flags.length > 0)
      ? row.active_flags.map(f => `<span class="badge-threat phish" style="font-size: 9.5px; padding: 1px 6px; margin: 1px;">${flagNames[f] || f.replace(/_/g, ' ')}</span>`).join('')
      : `<span style="color: var(--text-muted); font-size: 11px;">None</span>`;

    const cleanSender = (row.sender && row.sender !== "N/A" && row.sender !== "Unknown") ? row.sender : `Inbound Email #${row.row_id}`;
    const cleanSubject = (row.subject && row.subject !== "(No Subject)" && row.subject !== "No Subject") ? row.subject : `(No subject)`;

    return `
      <tr class="clickable-row" data-row-id="${row.row_id}" title="Click to view details">
        <td style="font-family: var(--font-mono); color: var(--text-muted); font-weight: 700;">#${row.row_id}</td>
        <td style="font-weight: 600; color: var(--text-white);">${escapeHtmlBatch(cleanSender)}</td>
        <td style="font-weight: 600; color: var(--accent-cyan);">${escapeHtmlBatch(cleanSubject)}</td>
        <td style="font-size: 11.5px; color: var(--text-muted); max-width: 260px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtmlBatch(row.snippet || '')}">
          ${escapeHtmlBatch(row.snippet || '')}
        </td>
        <td><span class="badge-threat ${verdictClass}">${v}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${riskColor};">${row.risk_score}</td>
        <td>${flagsBadges}</td>
        <td style="font-size: 11.5px; color: var(--text-title); font-weight: 600;">${escapeHtmlBatch(row.action || '')}</td>
        <td style="text-align: center;">
          <button type="button" class="btn-table-inspect" data-row-id="${row.row_id}">
            View
          </button>
        </td>
      </tr>
    `;
  }).join('');

  // Row click bindings
  tbody.querySelectorAll(".clickable-row").forEach(tr => {
    tr.addEventListener("click", () => {
      const rowId = parseInt(tr.dataset.rowId, 10);
      openEmailDetailModal(rowId);
    });
  });

  tbody.querySelectorAll(".btn-table-inspect").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const rowId = parseInt(btn.dataset.rowId, 10);
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

  // Close on backdrop click
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });

  // Close on Escape key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("open")) {
      closeModal();
    }
  });

  // Modal Tab Switching
  document.querySelectorAll(".modal-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".modal-tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".modal-tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.dataset.tab;
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  // Copy raw content
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      if (!activeModalEmail) return;
      const content = activeModalEmail.raw_content || "";
      navigator.clipboard.writeText(content).then(() => {
        showToast("Email text copied to clipboard.");
      }).catch(() => {
        showToast("Failed to copy text.");
      });
    });
  }

  // Pivot to Live Scanner
  if (scannerBtn) {
    scannerBtn.addEventListener("click", () => {
      if (!activeModalEmail) return;
      closeModal();

      // Switch workspace to Live Scanner
      if (typeof switchWorkspace === "function") {
        switchWorkspace("workspace-analyzer");
      } else {
        const analyzerNavBtn = document.querySelector('.nav-item[data-workspace="workspace-analyzer"]');
        if (analyzerNavBtn) analyzerNavBtn.click();
      }

      const textarea = document.getElementById("email-content");
      if (textarea) {
        textarea.value = activeModalEmail.raw_content || activeModalEmail.full_email || activeModalEmail.body || "";
        if (typeof updateTextareaCounters === "function") updateTextareaCounters();
        showToast(`Loaded email #${activeModalEmail.row_id} into Live Scanner.`);
        document.getElementById("scanner-form").dispatchEvent(new Event("submit"));
      }
    });
  }
}

function openEmailDetailModal(rowId) {
  if (!currentBatchReportData) return;

  const items = currentBatchReportData.results || currentBatchReportData.rows || [];
  const email = items.find(r => r.row_id === rowId);
  if (!email) return;

  activeModalEmail = email;
  const modal = document.getElementById("email-detail-modal");
  if (!modal) return;

  // Header meta
  const modalSender = (email.sender && email.sender !== "N/A" && email.sender !== "Unknown") ? email.sender : `External Inbound #${email.row_id}`;
  const modalSubject = (email.subject && email.subject !== "(No Subject)" && email.subject !== "No Subject") ? email.subject : `Security Event #${email.row_id}`;

  document.getElementById("modal-email-id").textContent = `#${email.row_id}`;
  document.getElementById("modal-email-subject").textContent = modalSubject;
  document.getElementById("modal-email-sender").textContent = modalSender;

  const replyWrap = document.getElementById("modal-reply-to-wrap");
  const replyElem = document.getElementById("modal-email-reply-to");
  if (email.reply_to && email.reply_to !== email.sender) {
    replyWrap.style.display = "inline";
    replyElem.textContent = email.reply_to;
  } else {
    replyWrap.style.display = "none";
  }

  const v = email.verdict || "Safe";
  const vClass = v === "Phishing" ? "phish" : (v === "Suspicious" ? "suspicious" : "safe");
  const verdictBadge = document.getElementById("modal-email-verdict");
  verdictBadge.className = `badge-threat ${vClass}`;
  verdictBadge.textContent = v.toUpperCase();

  const riskBadge = document.getElementById("modal-email-risk");
  riskBadge.textContent = `Risk: ${email.risk_score}/100`;

  // Tab 1: Threat Triage
  document.getElementById("modal-email-reason").textContent = email.reason || email.primary_reason || "Scan complete.";

  const flagsContainer = document.getElementById("modal-email-flags");
  if (flagsContainer) {
    const flagNames = {
      reply_to_mismatch: "Fake Sender Address",
      ip_in_url: "IP Number Link",
      suspicious_tld: "Risky Website Ending",
      urgency_words: "Urgent Pressure Words",
      executable_attachment: "Dangerous File Attached",
      no_https: "Insecure Link (HTTP)",
      long_url: "Suspicious Long Link"
    };
    flagsContainer.innerHTML = (email.active_flags && email.active_flags.length > 0)
      ? email.active_flags.map(f => `<span class="badge-threat phish">${flagNames[f] || f.replace(/_/g, ' ')}</span>`).join('')
      : `<span class="badge-threat safe">Safe (No warning signs)</span>`;
  }

  // Detected URLs
  const urlsBox = document.getElementById("modal-urls-box");
  const urlsList = document.getElementById("modal-urls-list");
  const detectedUrls = email.detected_urls || email.urls || [];
  if (detectedUrls.length > 0) {
    urlsBox.style.display = "block";
    urlsList.innerHTML = detectedUrls.map(u => `
      <code style="background: rgba(0,0,0,0.4); padding: 4px 8px; border-radius: 4px; color: var(--accent-cyan); font-size: 11px; word-break: break-all;">
        ${escapeHtmlBatch(u)}
      </code>
    `).join('');
  } else {
    urlsBox.style.display = "none";
  }

  // Attachments
  const attachBox = document.getElementById("modal-attachments-box");
  const attachList = document.getElementById("modal-attachments-list");
  const detectedAttachments = email.detected_attachments || email.attachments || [];
  if (detectedAttachments.length > 0) {
    attachBox.style.display = "block";
    attachList.innerHTML = detectedAttachments.map(a => `
      <span class="badge-threat phish" style="font-size: 11px;">
        <svg class="ui-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
          <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
        </svg>
        ${escapeHtmlBatch(a)}
      </span>
    `).join('');
  } else {
    attachBox.style.display = "none";
  }

  // Tab 2: Raw Content
  document.getElementById("modal-email-content").textContent = email.raw_content || email.full_email || email.body || "(No message body content available)";

  // Tab 3: Advisory
  const defaultAction = email.verdict === "Phishing" ? "Delete this email" : (email.verdict === "Suspicious" ? "Be careful" : "Email looks safe");
  document.getElementById("modal-email-action").textContent = email.action || defaultAction;
  const recList = document.getElementById("modal-recommendations-list");
  if (recList) {
    const recLevel = email.verdict === "Phishing" ? "CRITICAL" : (email.verdict === "Suspicious" ? "WARNING" : "SUCCESS");
    recList.innerHTML = `
      <div class="rec-item ${recLevel}">
        <div>
          <div class="rec-title">${escapeHtmlBatch(email.action || defaultAction)}</div>
          <div class="rec-detail">${escapeHtmlBatch(email.reason || (email.verdict === "Safe" ? "No scam signs found." : "Double-check before clicking."))}</div>
        </div>
      </div>
      <div class="rec-item HIGH">
        <div>
          <div class="rec-title">Check Sender</div>
          <div class="rec-detail">Make sure the sender's real address matches who they claim to be.</div>
        </div>
      </div>
      <div class="rec-item INFO">
        <div>
          <div class="rec-title">Stay Safe</div>
          <div class="rec-detail">Never share passwords or personal details through email links.</div>
        </div>
      </div>
    `;
  }

  // Reset to first tab
  document.querySelectorAll(".modal-tab-btn").forEach((b, i) => b.classList.toggle("active", i === 0));
  document.querySelectorAll(".modal-tab-content").forEach((c, i) => c.classList.toggle("active", i === 0));

  modal.classList.add("open");
}

// Export Batch CSV Audit Report
function exportBatchCsvReport() {
  if (!currentBatchReportData) {
    showToast("No report data available to export.");
    return;
  }

  const items = currentBatchReportData.results || currentBatchReportData.rows || [];
  if (!items || items.length === 0) {
    showToast("No report data available to export.");
    return;
  }
  const headers = ["Row_ID", "Sender", "Reply_To", "Subject", "Verdict", "Risk_Score", "Triggered_Indicators", "Recommended_Action", "Deduction_Reason"];

  const csvRows = [headers.join(",")];

  items.forEach(r => {
    const row = [
      r.row_id,
      `"${(r.sender || "").replace(/"/g, '""')}"`,
      `"${(r.reply_to || "").replace(/"/g, '""')}"`,
      `"${(r.subject || "").replace(/"/g, '""')}"`,
      `"${r.verdict || ""}"`,
      r.risk_score || 0,
      `"${(r.active_flags || []).join('; ')}"`,
      `"${(r.action || "").replace(/"/g, '""')}"`,
      `"${(r.reason || "").replace(/"/g, '""')}"`
    ];
    csvRows.push(row.join(","));
  });

  const blob = new Blob([csvRows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `phishradar_fleet_audit_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Exported fleet threat audit report CSV.");
}

function escapeHtmlBatch(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
