/**
 * Proof Tree Visualizer
 * Renders the Backward Chaining Proof Tree recursively as interactive HTML nodes.
 */

function renderProofTree(proofTree, containerId) {
  const container = document.getElementById(containerId);
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
    const goalTitle = node.goal.replace(/_/g, ' ').toUpperCase();
    const ruleInfo = node.rule_id ? `<span class="tree-rule-badge">${node.rule_id}</span>` : '';
    const desc = node.rule_desc ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${node.rule_desc}</div>` : '';

    let childrenHtml = '';
    if (node.children && node.children.length > 0) {
      childrenHtml = `
        <div style="display: flex; gap: 16px; margin-top: 16px; padding-left: 20px; border-left: 2px dashed rgba(6, 182, 212, 0.3);">
          ${node.children.map(child => buildNodeHtml(child)).join('')}
        </div>
      `;
    }

    return `
      <div style="display: flex; flex-direction: column; align-items: flex-start; margin-bottom: 12px;">
        <div class="tree-node ${isFact ? 'fact' : ''}">
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <span class="tree-node-title">${isFact ? '📌 FACT: ' : '🎯 GOAL: '}${goalTitle}</span>
            ${ruleInfo}
          </div>
          ${desc}
        </div>
        ${childrenHtml}
      </div>
    `;
  }

  container.innerHTML = `
    <div style="padding: 10px;">
      <div style="margin-bottom: 14px; font-size: 12px; color: var(--cyan-primary); font-family: var(--font-mono);">
        [PROVING ROOT GOAL: ${proofTree.goal.toUpperCase()}]
      </div>
      ${buildNodeHtml(proofTree)}
    </div>
  `;
}
