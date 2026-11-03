/**
 * Adversarial Minimax View & Game Tree Visualizer
 * Renders the two-player game search tree and tactics sensitivity matrix.
 */

function renderAdversarialView(advData) {
  if (!advData) return;

  // 1. Update stats
  const optimalElem = document.getElementById("adv-optimal-tactic");
  const pruningElem = document.getElementById("adv-pruning-stats");

  if (optimalElem) {
    if (advData.optimal_attacker_tactic) {
      optimalElem.textContent = advData.optimal_attacker_tactic.name || "None (Attacker Caught)";
    } else {
      optimalElem.textContent = "None (Attacker Caught)";
    }
  }

  if (pruningElem) {
    const s = advData.search_statistics || {};
    const nodes = s.nodes_evaluated !== undefined ? s.nodes_evaluated : 0;
    const cuts = s.pruning_cutoffs !== undefined ? s.pruning_cutoffs : 0;
    const payoff = advData.game_payoff !== undefined ? advData.game_payoff : 0;
    pruningElem.textContent = `${payoff > 0 ? '+' : ''}${payoff} Payoff | ${nodes} Nodes, ${cuts} Cutoffs`;
  }

  // 2. Tactics Matrix Table
  const tableBody = document.querySelector("#tactics-matrix-table tbody");
  if (tableBody && advData.tactics_matrix) {
    tableBody.innerHTML = advData.tactics_matrix.map(row => {
      const isEvaded = row.evades_baseline;
      const evasionBadge = isEvaded
        ? `<span class="badge-threat phish" style="font-size: 10px;">EVADES</span>`
        : `<span class="badge-threat safe" style="font-size: 10px;">BLOCKED (${escapeHtmlAdv(row.baseline_verdict)})</span>`;

      return `
        <tr>
          <td style="font-weight: 700; color: var(--text-dark);">${escapeHtmlAdv(row.name)}</td>
          <td><code style="color: var(--blue-primary); font-size: 11px;">${row.suppressed_features ? row.suppressed_features.join(', ') : 'None'}</code></td>
          <td style="font-family: var(--font-mono);">${row.cost}</td>
          <td style="font-family: var(--font-mono);">${row.baseline_score}</td>
          <td style="font-family: var(--font-mono);">${row.defended_score}</td>
          <td>${evasionBadge}</td>
        </tr>
      `;
    }).join('');
  }

  // 3. Game Tree Rendering
  const treeContainer = document.getElementById("adversarial-tree-view");
  if (treeContainer && advData.search_tree) {
    const root = advData.search_tree;

    let html = `
      <div style="padding: 6px; font-family: var(--font-mono); font-size: 12px;">
        <div style="background: var(--threat-phish-bg); border: 1px solid var(--threat-phish-border); padding: 10px 14px; border-radius: var(--radius-sm); margin-bottom: 14px; display: inline-block;">
          <strong style="color: var(--threat-phish);">[MAX ROOT: Attacker]</strong> | Best Action: <strong style="color: var(--text-dark);">${escapeHtmlAdv(root.best_action || 'N/A')}</strong> | Payoff: <strong>${root.value}</strong>
        </div>

        <div style="display: flex; flex-direction: column; gap: 10px; margin-left: 16px; border-left: 2px dashed var(--border-hover); padding-left: 16px;">
    `;

    if (root.children && root.children.length > 0) {
      root.children.forEach(child => {
        const isOptimal = child.action === root.best_action;
        html += `
          <div style="background: ${isOptimal ? 'var(--blue-light)' : 'var(--bg-page)'}; border: 1px solid ${isOptimal ? 'var(--blue-border)' : 'var(--border-card)'}; border-radius: var(--radius-sm); padding: 10px 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <span style="color: ${isOptimal ? 'var(--blue-primary)' : 'var(--text-dark)'}; font-weight: 700;">Move: ${escapeHtmlAdv(child.action)}</span>
                ${isOptimal ? ' <span class="status-badge-similox live" style="padding: 2px 6px; font-size: 9px; margin-left: 6px;">OPTIMAL MOVE</span>' : ''}
              </div>
              <span style="color: var(--text-muted); font-size: 11.5px;">Payoff: <strong>${child.value}</strong></span>
            </div>

            <div style="margin-top: 6px; font-size: 11px; color: var(--text-muted); padding-left: 10px; border-left: 2px solid var(--border-hover);">
              Defender MIN responses evaluated: ${child.children ? child.children.length : 0} countermeasure(s)
              ${child.pruned_at_alpha !== undefined ? `<br><span style="color: var(--threat-suspicious); font-weight: 600;">[PRUNED] Alpha-Beta cutoff at alpha=${child.pruned_at_alpha}</span>` : ''}
            </div>
          </div>
        `;
      });
    } else {
      html += `<div style="color: var(--text-muted);">No child branch moves generated.</div>`;
    }

    html += `
        </div>
      </div>
    `;

    treeContainer.innerHTML = html;
  }
}

async function triggerAdversarialSimulation(features) {
  try {
    const res = await fetch("/api/adversarial", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features: features || {} })
    });
    const data = await res.json();
    renderAdversarialView(data);
  } catch (err) {
    console.error("Adversarial simulation error:", err);
  }
}

function escapeHtmlAdv(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
