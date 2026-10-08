/**
 * Adversarial Minimax View & Game Tree Visualizer
 * Renders the two-player game search tree and tactics sensitivity matrix.
 */

function renderAdversarialView(advData) {
  if (!advData) return;

  // 1. Update stats
  const optimalElem = document.getElementById("adv-optimal-tactic");
  const payoffElem = document.getElementById("adv-game-payoff");
  const pruningElem = document.getElementById("adv-pruning-stats");

  if (optimalElem && advData.optimal_attacker_tactic) {
    optimalElem.textContent = advData.optimal_attacker_tactic.name || "None";
  }
  if (payoffElem && advData.game_payoff !== undefined) {
    payoffElem.textContent = `${advData.game_payoff > 0 ? '+' : ''}${advData.game_payoff}`;
    payoffElem.style.color = advData.game_payoff > 0 ? "var(--danger)" : "var(--success)";
  }
  if (pruningElem && advData.search_statistics) {
    const s = advData.search_statistics;
    pruningElem.textContent = `${s.nodes_evaluated} Nodes / ${s.pruning_cutoffs} Cuts (Alpha-Beta)`;
  }

  // 2. Tactics Matrix Table
  const tableBody = document.querySelector("#tactics-matrix-table tbody");
  if (tableBody && advData.tactics_matrix) {
    tableBody.innerHTML = advData.tactics_matrix.map(row => {
      const isEvaded = row.evades_baseline;
      const evasionBadge = isEvaded
        ? `<span style="color: var(--danger); font-weight: 700;">🚨 EVADES (Safe)</span>`
        : `<span style="color: var(--success); font-weight: 700;">🛡️ CAUGHT (${row.baseline_verdict})</span>`;

      return `
        <tr>
          <td style="font-weight: 600; color: #fff;">${row.name}</td>
          <td><code style="color: var(--cyan-primary);">${row.suppressed_features.join(', ')}</code></td>
          <td>${row.cost}</td>
          <td>Score: ${row.baseline_score}</td>
          <td><span style="color: ${row.baseline_verdict === 'Phishing' ? 'var(--danger)' : (row.baseline_verdict === 'Suspicious' ? 'var(--warning)' : 'var(--success)')};">${row.baseline_verdict}</span></td>
          <td>Score: ${row.defended_score} (${row.defended_verdict})</td>
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
      <div style="padding: 10px; font-family: var(--font-mono); font-size: 13px;">
        <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); padding: 12px 16px; border-radius: var(--radius-md); display: inline-block; margin-bottom: 16px;">
          <strong style="color: var(--danger);">[MAX NODE: Attacker Root]</strong> | Best Action: <strong>${root.best_action || 'N/A'}</strong> | Value: <strong>${root.value}</strong>
        </div>

        <div style="display: flex; flex-direction: column; gap: 14px; margin-left: 20px; border-left: 2px dashed rgba(255, 255, 255, 0.15); padding-left: 20px;">
    `;

    if (root.children) {
      root.children.forEach(child => {
        const isOptimal = child.action === root.best_action;
        html += `
          <div style="background: ${isOptimal ? 'rgba(6, 182, 212, 0.12)' : 'rgba(255, 255, 255, 0.02)'}; border: 1px solid ${isOptimal ? 'var(--cyan-primary)' : 'rgba(255, 255, 255, 0.08)'}; border-radius: var(--radius-md); padding: 10px 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div>
                <span style="color: ${isOptimal ? 'var(--cyan-primary)' : 'var(--text-main)'}; font-weight: 700;">⚔️ Tactic: ${child.action}</span>
                ${isOptimal ? ' <span class="badge-tag" style="padding: 2px 6px; font-size: 10px;">OPTIMAL MOVE</span>' : ''}
              </div>
              <span style="color: var(--text-muted); font-size: 12px;">Payoff: <strong>${child.value}</strong></span>
            </div>

            <div style="margin-top: 8px; font-size: 11px; color: var(--text-muted); padding-left: 12px; border-left: 2px solid rgba(255,255,255,0.06);">
              Defender MIN responses evaluated: ${child.children ? child.children.length : 0} countermeasure(s)
              ${child.pruned_at_alpha !== undefined ? `<br><span style="color: var(--warning);">⚡ Alpha-Beta Pruned remaining branches at alpha=${child.pruned_at_alpha}</span>` : ''}
            </div>
          </div>
        `;
      });
    }

    html += `
        </div>
      </div>
    `;

    treeContainer.innerHTML = html;
  }
}
