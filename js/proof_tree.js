/**
 * Proof Tree Visualizer
 * Renders the Backward Chaining Proof Tree recursively as interactive HTML nodes
 * and displays the Forward Chaining inference trace.
 */

function renderProofTree(proofTree, containerId) {
  const container = document.getElementById(containerId || "proof-tree-view");
  if (!container) return;

  if (!proofTree) {
    container.innerHTML = `
      <div style="color: var(--text-muted); text-align: center; padding: 30px;">
        No proof tree generated for this email. (Email proved Safe or No Horn clauses triggered).
      </div>
    `;
    return;
  }

  function buildNodeHtml(node) {
    const isFact = node.is_fact;
    const goalTitle = (node.goal || "").replace(/_/g, ' ').toUpperCase();
    const ruleInfo = node.rule_id ? `<span class="tree-rule-badge">${escapeHtmlProof(node.rule_id)}</span>` : '';
    const desc = node.rule_desc ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${escapeHtmlProof(node.rule_desc)}</div>` : '';

    let childrenHtml = '';
    if (node.children && node.children.length > 0) {
      childrenHtml = `
        <div style="display: flex; gap: 14px; margin-top: 14px; padding-left: 18px; border-left: 2px dashed rgba(0, 240, 255, 0.3);">
          ${node.children.map(child => buildNodeHtml(child)).join('')}
        </div>
      `;
    }

    return `
      <div style="display: flex; flex-direction: column; align-items: flex-start; margin-bottom: 10px;">
        <div class="tree-node ${isFact ? 'fact' : ''}">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px;">
            <span class="tree-node-title"><span class="proof-tag ${isFact ? 'fact' : 'goal'}">${isFact ? 'FACT' : 'GOAL'}</span> ${escapeHtmlProof(goalTitle)}</span>
            ${ruleInfo}
          </div>
          ${desc}
        </div>
        ${childrenHtml}
      </div>
    `;
  }

  container.innerHTML = `
    <div style="padding: 6px;">
      <div style="margin-bottom: 12px; font-size: 11.5px; color: var(--accent-cyan); font-family: var(--font-mono);">
        [PROVING ROOT HYPOTHESIS: ${(proofTree.goal || "").toUpperCase()}]
      </div>
      ${buildNodeHtml(proofTree)}
    </div>
  `;
}

function renderForwardChainTrace(fcData) {
  const elem = document.getElementById("forward-chain-trace");
  if (!elem) return;

  if (!fcData) {
    elem.textContent = "No forward chaining inference run.";
    return;
  }

  const derived = fcData.derived_facts || [];
  const rules = fcData.rules_fired || [];

  if (derived.length === 0) {
    elem.textContent = "No higher-level threat facts derived. (Ground features insufficient to fire rules).";
    return;
  }

  elem.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 6px;">
      <div><strong>Verdict:</strong> <span style="color: ${fcData.verdict === 'Phishing' ? 'var(--threat-phish)' : 'var(--threat-safe)'};">${fcData.verdict}</span></div>
      <div><strong>Rules Fired (${rules.length}):</strong> ${rules.map(r => `<span class="status-pill" style="font-size: 9.5px; padding: 2px 6px; margin-right: 4px;">${escapeHtmlProof(r)}</span>`).join('')}</div>
      <div><strong>Derived Facts:</strong> <span style="color: var(--accent-cyan);">${derived.map(f => f.replace(/_/g, ' ')).join(', ')}</span></div>
    </div>
  `;
}

function escapeHtmlProof(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
