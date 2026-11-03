/**
 * Benchmark & Evaluation Studio Module
 * Renders the 5-detector benchmark comparative table, 5-fold cross validation,
 * and large-scale Kaggle dataset streaming tests.
 */

function setupBenchmarkStudio() {
  const runBtn = document.getElementById("btn-run-benchmark");
  const kaggleBtn = document.getElementById("btn-eval-kaggle");

  if (runBtn) {
    runBtn.addEventListener("click", loadBenchmarkData);
  }

  if (kaggleBtn) {
    kaggleBtn.addEventListener("click", runKaggleEvaluation);
  }
}

async function loadBenchmarkData() {
  const btn = document.getElementById("btn-run-benchmark");
  const tbody = document.querySelector("#benchmark-table tbody");
  if (!tbody) return;

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-spinner"></span> Evaluating Models...`;
  }

  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--blue-primary); padding: 24px;">Running verification suite across 60 benchmark emails...</td></tr>`;

  try {
    const res = await fetch("/api/benchmark");
    const data = await res.json();

    // 1. Render Table
    if (data.table && data.table.length > 0) {
      tbody.innerHTML = data.table.map(row => {
        const accPct = (row.accuracy * 100).toFixed(1);
        const precPct = (row.precision * 100).toFixed(1);
        const recPct = (row.recall * 100).toFixed(1);
        const f1Pct = (row.f1 * 100).toFixed(1);

        const isCombined = row.detector.toLowerCase().includes("combined");
        const highlightStyle = isCombined ? "background: var(--blue-light); font-weight: 700;" : "";

        return `
          <tr style="${highlightStyle}">
            <td style="font-weight: 700; color: ${isCombined ? 'var(--blue-primary)' : 'var(--text-dark)'};">
              ${isCombined ? '<span class="status-badge-similox live" style="font-size: 10px; margin-right: 6px;">CONSENSUS</span>' : ''}${escapeHtmlBench(row.detector)}
            </td>
            <td style="font-family: var(--font-mono); font-weight: 700; color: ${row.accuracy >= 0.88 ? 'var(--threat-safe)' : 'var(--text-title)'};">${accPct}%</td>
            <td style="font-family: var(--font-mono);">${precPct}%</td>
            <td style="font-family: var(--font-mono);">${recPct}%</td>
            <td style="font-family: var(--font-mono);">${f1Pct}%</td>
            <td style="font-family: var(--font-mono); color: ${row.false_positives > 5 ? 'var(--threat-suspicious)' : 'var(--text-muted)'};">${row.false_positives}</td>
            <td style="font-family: var(--font-mono); color: ${row.false_negatives > 0 ? 'var(--threat-phish)' : 'var(--threat-safe)'};">${row.false_negatives}</td>
          </tr>
        `;
      }).join('');
    }

    // 2. Render 5-Fold Cross-Validation
    if (data.cross_validation) {
      const cv = data.cross_validation;
      const cvContainer = document.getElementById("cv-scores-disp");
      const cvMean = document.getElementById("cv-mean-score");

      if (cvContainer && cv.fold_scores) {
        cvContainer.innerHTML = cv.fold_scores.map((score, idx) => `
          <div style="background: var(--bg-card-subtle); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 8px 12px; font-size: 11.5px;">
            <div style="color: var(--text-muted); font-size: 10px;">FOLD ${idx + 1}</div>
            <div style="font-family: var(--font-mono); font-weight: 700; color: var(--blue-primary); font-size: 13px;">${(score * 100).toFixed(1)}%</div>
          </div>
        `).join('');
      }

      if (cvMean && cv.mean_score !== undefined) {
        cvMean.textContent = `${(cv.mean_score * 100).toFixed(1)}%`;
      }
    }

    showToast("Benchmark evaluation completed successfully.");

  } catch (err) {
    console.error("Benchmark error:", err);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--threat-phish); padding: 24px;">Failed to load benchmark evaluation.</td></tr>`;
    showToast("Error executing benchmark evaluation.");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `
        <svg class="ui-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
        </svg>
        <span>Run Full Verification</span>
      `;
    }
  }
}

async function runKaggleEvaluation() {
  const btn = document.getElementById("btn-eval-kaggle");
  const select = document.getElementById("kaggle-sample-select");
  const container = document.getElementById("kaggle-results-container");
  const disp = document.getElementById("kaggle-metrics-disp");

  if (!btn || !select || !container || !disp) return;

  const sampleCount = parseInt(select.value, 10) || 500;
  btn.disabled = true;
  btn.innerHTML = `<span class="btn-spinner"></span> Streaming ${sampleCount} records...`;

  try {
    const res = await fetch("/api/kaggle-eval", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ samples: sampleCount })
    });
    const data = await res.json();

    if (data.error) {
      showToast(data.error);
      return;
    }

    container.style.display = "block";
    const m = data.metrics || {};
    disp.innerHTML = `
      <div><strong>Evaluated Samples:</strong> ${data.samples_evaluated} (Test Split: ${data.test_size})</div>
      <div style="margin-top: 6px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px;">
        <div>Accuracy: <strong>${(m.accuracy * 100).toFixed(1)}%</strong></div>
        <div>Precision: <strong>${(m.precision * 100).toFixed(1)}%</strong></div>
        <div>Recall: <strong>${(m.recall * 100).toFixed(1)}%</strong></div>
        <div>F1-Score: <strong>${(m.f1 * 100).toFixed(1)}%</strong></div>
      </div>
      <div style="margin-top: 6px; font-size: 11px; color: var(--text-muted);">
        False Positives: ${m.false_positives} | False Negatives: ${m.false_negatives}
      </div>
    `;

    showToast(`Kaggle evaluation completed for ${data.samples_evaluated} samples.`);
  } catch (err) {
    console.error("Kaggle eval error:", err);
    showToast("Failed to run Kaggle dataset evaluation.");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg class="ui-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
      </svg>
      <span>Stream &amp; Evaluate</span>
    `;
  }
}

function escapeHtmlBench(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
