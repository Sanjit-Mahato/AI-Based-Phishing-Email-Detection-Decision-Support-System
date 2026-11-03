/**
 * Rules Catalog Module
 * Renders the 13 Horn-Clause Knowledge Base and handles live searching.
 */

let allRulesData = [];

async function loadRulesCatalog() {
  const container = document.getElementById("rules-catalog-container");
  if (!container) return;

  try {
    const res = await fetch("/api/rules");
    const data = await res.json();
    allRulesData = data.rules || [];
    renderRules(allRulesData);
    setupRulesSearch();
  } catch (err) {
    console.error("Failed to load rules catalog:", err);
    container.innerHTML = `<div style="color: var(--threat-phish); padding: 20px;">Failed to load rules catalog from server.</div>`;
  }
}

function renderRules(rules) {
  const container = document.getElementById("rules-catalog-container");
  if (!container) return;

  if (rules.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted); padding: 30px; text-align: center; grid-column: 1 / -1;">No matching rules found in knowledge base.</div>`;
    return;
  }

  container.innerHTML = rules.map(rule => {
    const premisesList = rule.premises && rule.premises.length > 0
      ? rule.premises.map(p => `<li><code>${escapeHtmlRules(p)}</code></li>`).join("")
      : "<li><em>Direct fact assertion</em></li>";

    return `
      <div class="rule-card">
        <div class="rule-header">
          <span class="rule-id">${escapeHtmlRules(rule.id || "RULE")}</span>
          <span class="rule-cf">CF: <strong>${rule.confidence_factor !== undefined ? rule.confidence_factor : 1.0}</strong></span>
        </div>
        <div class="rule-title">${escapeHtmlRules(rule.conclusion ? rule.conclusion.replace(/_/g, ' ').toUpperCase() : rule.name)}</div>
        <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Antecedent Premises:</div>
        <ul class="rule-premises">
          ${premisesList}
        </ul>
        <div class="rule-rationale">
          "${escapeHtmlRules(rule.description || rule.rationale || 'Rule for inference and threat classification.')}"
        </div>
      </div>
    `;
  }).join("");
}

function setupRulesSearch() {
  const searchInput = document.getElementById("rules-search-input");
  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
      renderRules(allRulesData);
      return;
    }

    const filtered = allRulesData.filter(r => {
      const idMatch = (r.id || "").toLowerCase().includes(q);
      const concMatch = (r.conclusion || "").toLowerCase().includes(q);
      const descMatch = (r.description || "").toLowerCase().includes(q);
      const premMatch = (r.premises || []).some(p => p.toLowerCase().includes(q));
      return idMatch || concMatch || descMatch || premMatch;
    });

    renderRules(filtered);
  });
}

function escapeHtmlRules(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
