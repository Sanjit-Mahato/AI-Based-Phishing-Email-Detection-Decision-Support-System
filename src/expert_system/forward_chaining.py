"""
Forward Chaining Inference Engine (Unit/Module 3: Knowledge Representation & Reasoning)
Applies Horn clause rules repeatedly from known indicator facts to derive conclusions.
"""

from typing import Dict, Set, List, Any
from .knowledge_base import HornRule, KnowledgeBase


class ForwardChainingEngine:
    """Data-driven forward chaining inference engine."""

    def __init__(self, rules: List[HornRule] = None):
        self.rules = rules or KnowledgeBase.get_default_rules()

    def infer(self, features: Dict[str, int]) -> Dict[str, Any]:
        """
        Runs forward chaining starting from active base indicator facts.
        Returns all derived facts, rule firing timeline, and final verdict.
        """
        # 1. Base facts asserted directly from features
        facts: Set[str] = {f for f, val in features.items() if val == 1}
        initial_facts = sorted(list(facts))

        fired_rules: List[Dict[str, Any]] = []
        derived_facts: Set[str] = set()

        iteration = 0
        changed = True

        while changed:
            changed = False
            iteration += 1
            for rule in self.rules:
                # If conclusion already known, skip
                if rule.conclusion in facts:
                    continue
                # If all premises satisfied, fire rule
                if rule.is_satisfied(facts):
                    facts.add(rule.conclusion)
                    derived_facts.add(rule.conclusion)
                    fired_rules.append({
                        "step": len(fired_rules) + 1,
                        "iteration": iteration,
                        "rule_id": rule.rule_id,
                        "premises": list(rule.premises),
                        "derived": rule.conclusion,
                        "description": rule.description
                    })
                    changed = True

        # Determine verdict
        if "phishing" in facts:
            verdict = "Phishing"
        elif "suspicious" in facts:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return {
            "initial_facts": initial_facts,
            "all_facts": sorted(list(facts)),
            "derived_facts": sorted(list(derived_facts)),
            "fired_rules": fired_rules,
            "verdict": verdict,
            "is_flagged": verdict in ["Suspicious", "Phishing"],
            "iterations": iteration
        }
