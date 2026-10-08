"""
Minimax & Alpha-Beta Adversarial Search Engine (Unit/Module 2: Adversarial Search)
Simulates attacker evasion vs detector countermeasures as a two-player zero-sum game.
"""

import math
from typing import Dict, List, Any, Tuple, Optional
from .evasion_tactics import EvasionTacticsRegistry, AdversarialTactic
from ..heuristics.baseline_scorer import BaselineHeuristicScorer


class DetectorCountermeasure:
    """Represents a defensive countermeasure deployed by the detector."""

    def __init__(self, action_id: str, name: str, cost: float, restores: List[str], threshold_offset: int = 0, description: str = ""):
        self.action_id = action_id
        self.name = name
        self.cost = cost
        self.restores = restores  # features restored/unveiled if masked
        self.threshold_offset = threshold_offset
        self.description = description


class AdversarialSearchEngine:
    """
    Minimax game-theoretic search with Alpha-Beta pruning.
    Player 1 (MAX): Attacker mutating email to evade detection.
    Player 2 (MIN): Detector applying inspection countermeasures to neutralize evasion.
    """

    COUNTERMEASURES = [
        DetectorCountermeasure(
            action_id="D0_BASELINE",
            name="Standard Heuristic Inspection",
            cost=0.0,
            restores=[],
            threshold_offset=0,
            description="Default feature inspection without additional deep analysis."
        ),
        DetectorCountermeasure(
            action_id="D1_DEEP_URL",
            name="Deep URL Unshortening & DNS Whois",
            cost=0.5,
            restores=["ip_in_url", "suspicious_tld", "long_url"],
            threshold_offset=0,
            description="Recursively expands redirect chains and checks real target IP and domain registration."
        ),
        DetectorCountermeasure(
            action_id="D2_SANDBOX_ATTACHMENT",
            name="Dynamic Attachment Emulation Sandbox",
            cost=0.8,
            restores=["executable_attachment"],
            threshold_offset=0,
            description="Detonates attachments in an isolated VM to discover hidden binaries or scripts."
        ),
        DetectorCountermeasure(
            action_id="D3_NLP_SEMANTICS",
            name="Contextual NLP Intent Analysis",
            cost=0.4,
            restores=["urgency_words"],
            threshold_offset=0,
            description="Uses semantic similarity to catch implicit coercion even when crude panic keywords are omitted."
        ),
        DetectorCountermeasure(
            action_id="D4_ZERO_TRUST",
            name="Zero-Trust Sensitivity Threshold",
            cost=1.0,
            restores=[],
            threshold_offset=-1,
            description="Lowers detection threshold (Suspicious at >= 2, Phishing at >= 4) with higher alert sensitivity."
        )
    ]

    def __init__(self):
        self.tactics = EvasionTacticsRegistry.get_all_tactics()
        self.scorer = BaselineHeuristicScorer()
        self.nodes_evaluated = 0
        self.pruning_count = 0

    def evaluate_payoff(
        self,
        features: Dict[str, int],
        attacker_cost: float,
        countermeasure: DetectorCountermeasure
    ) -> float:
        """
        Payoff function from the Attacker's perspective (MAX player):
          +10.0 if email successfully evades (Safe)
          +2.0  if flagged as Suspicious (partial evasion)
          -8.0  if caught as Phishing (attack thwarted)
          minus attacker modification cost
          plus detector inspection cost (since detector pays computation overhead)
        """
        # Apply detector threshold offset
        eff_susp = max(1, self.scorer.suspicious_threshold + countermeasure.threshold_offset)
        eff_phish = max(2, self.scorer.phishing_threshold + countermeasure.threshold_offset)

        scorer = BaselineHeuristicScorer(suspicious_threshold=eff_susp, phishing_threshold=eff_phish)
        result = scorer.evaluate(features)
        verdict = result["verdict"]

        if verdict == "Safe":
            base_reward = 10.0
        elif verdict == "Suspicious":
            base_reward = 2.0
        else:  # Phishing
            base_reward = -8.0

        attacker_penalty = attacker_cost * 4.0
        detector_overhead = countermeasure.cost * 1.5

        # Utility to attacker (MAX)
        payoff = base_reward - attacker_penalty + detector_overhead
        return round(payoff, 3)

    def minimax_alpha_beta(
        self,
        features: Dict[str, int],
        depth: int,
        alpha: float,
        beta: float,
        is_maximizing: bool,
        attacker_tactic: Optional[AdversarialTactic] = None,
        tree_log: List[Dict[str, Any]] = None
    ) -> Tuple[float, Any, Dict[str, Any]]:
        """
        Minimax algorithm with Alpha-Beta pruning.
        Returns: (best_payoff, best_action, tree_node_dict)
        """
        self.nodes_evaluated += 1

        node_dict = {
            "depth": depth,
            "type": "MAX (Attacker)" if is_maximizing else "MIN (Detector)",
            "children": [],
            "alpha": None if math.isinf(alpha) else alpha,
            "beta": None if math.isinf(beta) else beta
        }

        # Terminal state: depth limit reached
        if depth == 0:
            dummy_defense = self.COUNTERMEASURES[0]
            val = self.evaluate_payoff(features, attacker_tactic.cost if attacker_tactic else 0.0, dummy_defense)
            node_dict["value"] = val
            return val, None, node_dict

        if is_maximizing:
            # Attacker's turn (MAX)
            max_eval = float("-inf")
            best_tactic = None

            for tactic in self.tactics:
                mutated_features = tactic.apply(features)
                val, _, child_node = self.minimax_alpha_beta(
                    mutated_features,
                    depth - 1,
                    alpha,
                    beta,
                    is_maximizing=False,
                    attacker_tactic=tactic
                )
                child_node["action"] = tactic.name
                child_node["tactic_id"] = tactic.tactic_id
                node_dict["children"].append(child_node)

                if val > max_eval:
                    max_eval = val
                    best_tactic = tactic

                alpha = max(alpha, eval_val := max_eval)
                if beta <= alpha:
                    self.pruning_count += 1
                    node_dict["pruned_at_alpha"] = None if math.isinf(alpha) else alpha
                    node_dict["pruned_at_beta"] = None if math.isinf(beta) else beta
                    break  # Beta cutoff / Alpha-Beta Pruning!

            node_dict["value"] = max_eval
            node_dict["best_action"] = best_tactic.name if best_tactic else "None"
            return max_eval, best_tactic, node_dict

        else:
            # Detector's turn (MIN)
            min_eval = float("inf")
            best_defense = None

            for defense in self.COUNTERMEASURES:
                # Detector applies countermeasures to restore features
                defended_features = features.copy()
                for restored_feat in defense.restores:
                    # If the underlying attack had this feature, detector unmasks it
                    defended_features[restored_feat] = 1

                val = self.evaluate_payoff(
                    defended_features,
                    attacker_tactic.cost if attacker_tactic else 0.0,
                    defense
                )

                child_node = {
                    "depth": depth - 1,
                    "type": "EVAL_LEAF",
                    "action": defense.name,
                    "action_id": defense.action_id,
                    "value": val,
                    "restored": defense.restores,
                    "cost": defense.cost
                }
                node_dict["children"].append(child_node)

                if val < min_eval:
                    min_eval = val
                    best_defense = defense

                beta = min(beta, min_eval)
                if beta <= alpha:
                    self.pruning_count += 1
                    node_dict["pruned_at_alpha"] = None if math.isinf(alpha) else alpha
                    node_dict["pruned_at_beta"] = None if math.isinf(beta) else beta
                    break  # Alpha cutoff / Alpha-Beta Pruning!

            node_dict["value"] = min_eval
            node_dict["best_action"] = best_defense.name if best_defense else "None"
            return min_eval, best_defense, node_dict

    def run_adversarial_simulation(self, original_features: Dict[str, int]) -> Dict[str, Any]:
        """
        Runs full adversarial search analysis:
        1. Base detection on unmutated email.
        2. Minimax search with Alpha-Beta pruning to find optimal evasion move and optimal defense.
        3. Generates comparative matrix of all attacker tactics vs baseline and optimal defense.
        """
        self.nodes_evaluated = 0
        self.pruning_count = 0

        # Run Alpha-Beta search at depth 2 (Attacker move -> Detector countermeasure)
        alpha = float("-inf")
        beta = float("inf")

        optimal_payoff, best_tactic, search_tree = self.minimax_alpha_beta(
            original_features,
            depth=2,
            alpha=alpha,
            beta=beta,
            is_maximizing=True
        )

        # Baseline evaluation
        baseline_res = self.scorer.evaluate(original_features)

        # Matrix of all tactics vs Baseline vs Deep Defense
        tactics_matrix = []
        for tactic in self.tactics:
            mutated = tactic.apply(original_features)
            score_baseline = self.scorer.evaluate(mutated)
            
            # Against optimal defense
            optimal_defense = self.COUNTERMEASURES[1]  # Deep URL
            defended = mutated.copy()
            for r in optimal_defense.restores:
                if original_features.get(r, 0) == 1:
                    defended[r] = 1
            score_defended = self.scorer.evaluate(defended)

            tactics_matrix.append({
                "tactic_id": tactic.tactic_id,
                "name": tactic.name,
                "description": tactic.description,
                "suppressed_features": tactic.targets,
                "cost": tactic.cost,
                "baseline_score": score_baseline["score"],
                "baseline_verdict": score_baseline["verdict"],
                "evades_baseline": score_baseline["verdict"] == "Safe",
                "defended_score": score_defended["score"],
                "defended_verdict": score_defended["verdict"],
                "evades_defended": score_defended["verdict"] == "Safe"
            })

        return {
            "original_features": original_features,
            "baseline_result": baseline_res,
            "optimal_attacker_tactic": {
                "tactic_id": best_tactic.tactic_id if best_tactic else "NONE",
                "name": best_tactic.name if best_tactic else "None",
                "description": best_tactic.description if best_tactic else ""
            },
            "game_payoff": optimal_payoff,
            "search_statistics": {
                "nodes_evaluated": self.nodes_evaluated,
                "pruning_cutoffs": self.pruning_count,
                "algorithm": "Minimax with Alpha-Beta Pruning"
            },
            "tactics_matrix": tactics_matrix,
            "search_tree": search_tree
        }
