"""
Backward Chaining Inference Engine (Unit/Module 3: Knowledge Representation & Reasoning)
Goal-driven reasoning that proves "phishing" or "suspicious" from rules,
generating an explainable Proof Tree and readable explanation text.
"""

from typing import Dict, Set, List, Any, Optional
from .knowledge_base import HornRule, KnowledgeBase


class ProofNode:
    """A node in the backward chaining proof tree."""

    def __init__(self, goal: str, is_fact: bool = False, rule: Optional[HornRule] = None):
        self.goal = goal
        self.is_fact = is_fact
        self.rule = rule
        self.children: List['ProofNode'] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "is_fact": self.is_fact,
            "rule_id": self.rule.rule_id if self.rule else None,
            "rule_desc": self.rule.description if self.rule else None,
            "children": [child.to_dict() for child in self.children]
        }


class BackwardChainingEngine:
    """Goal-directed backward chaining proof engine."""

    def __init__(self, rules: List[HornRule] = None):
        self.rules = rules or KnowledgeBase.get_default_rules()

    def prove_goal(self, goal: str, facts: Set[str], visited: Set[str] = None) -> Optional[ProofNode]:
        """
        Recursively proves a goal from facts and rules.
        Returns a ProofNode if provable, or None if not provable.
        """
        if visited is None:
            visited = set()

        # Base case: goal is directly asserted in facts
        if goal in facts:
            return ProofNode(goal, is_fact=True)

        if goal in visited:
            return None  # Cycle prevention

        visited.add(goal)

        # Look for rules concluding this goal
        for rule in self.rules:
            if rule.conclusion == goal:
                all_premises_proved = True
                child_nodes: List[ProofNode] = []
                
                for premise in rule.premises:
                    child_node = self.prove_goal(premise, facts, visited.copy())
                    if child_node is None:
                        all_premises_proved = False
                        break
                    child_nodes.append(child_node)

                if all_premises_proved:
                    node = ProofNode(goal, is_fact=False, rule=rule)
                    node.children = child_nodes
                    return node

        return None

    def explain(self, features: Dict[str, int]) -> Dict[str, Any]:
        """
        Attempts to prove 'phishing', then 'suspicious'.
        Constructs proof tree and formatted explanation string.
        """
        facts: Set[str] = {f for f, val in features.items() if val == 1}

        # 1. Try proving 'phishing'
        phishing_proof = self.prove_goal("phishing", facts)
        if phishing_proof:
            explanation_text = self._format_proof_text(phishing_proof)
            return {
                "proved_verdict": "Phishing",
                "is_proved": True,
                "proof_tree": phishing_proof.to_dict(),
                "explanation": explanation_text,
                "summary": f"Proved Phishing: {explanation_text}"
            }

        # 2. Try proving 'suspicious'
        suspicious_proof = self.prove_goal("suspicious", facts)
        if suspicious_proof:
            explanation_text = self._format_proof_text(suspicious_proof)
            return {
                "proved_verdict": "Suspicious",
                "is_proved": True,
                "proof_tree": suspicious_proof.to_dict(),
                "explanation": explanation_text,
                "summary": f"Proved Suspicious: {explanation_text}"
            }

        return {
            "proved_verdict": "Safe",
            "is_proved": False,
            "proof_tree": None,
            "explanation": "No phishing or suspicious Horn clauses were triggered by the email indicators.",
            "summary": "Proved Safe: No risk indicators met threshold rules."
        }

    def _format_proof_text(self, node: ProofNode) -> str:
        """
        Formats node into readable explanation like:
        'phishing by spoofed sender (reply-to mismatch) and bad link (suspicious TLD)'
        """
        if node.is_fact:
            return node.goal.replace('_', ' ')

        if not node.children:
            return node.goal

        child_descriptions = []
        for child in node.children:
            child_text = self._format_proof_text(child)
            if not child.is_fact:
                child_descriptions.append(f"{child.goal.replace('_', ' ')} ({child_text})")
            else:
                child_descriptions.append(child.goal.replace('_', ' '))

        joined_reasons = " and ".join(child_descriptions)
        return f"{node.goal} by {joined_reasons}"
