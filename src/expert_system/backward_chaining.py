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
                "explanation": f"phishing risk: {explanation_text}",
                "summary": f"Phishing risk: {explanation_text}"
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
                "summary": f"Warning: {explanation_text}"
            }

        return {
            "proved_verdict": "Safe",
            "is_proved": False,
            "proof_tree": None,
            "explanation": "No scam signs or risk triggers found.",
            "summary": "Safe: No risks or scam signs found."
        }

    def _collect_leaf_facts(self, node: ProofNode) -> List[str]:
        """Extracts unique underlying facts that triggered the proof."""
        if node.is_fact:
            return [node.goal]
        leafs = []
        for child in node.children:
            leafs.extend(self._collect_leaf_facts(child))
        return list(dict.fromkeys(leafs))

    def _format_proof_text(self, node: ProofNode) -> str:
        """Formats proof into simple, short, plain-English summary."""
        fact_labels = {
            "reply_to_mismatch": "fake sender address",
            "ip_in_url": "unsafe numeric web link",
            "suspicious_tld": "risky website ending",
            "long_url": "suspiciously long link",
            "no_https": "insecure link (no HTTPS)",
            "executable_attachment": "dangerous file attached",
            "urgency_words": "urgent pressure words",
            "spoofed_sender": "fake sender",
            "bad_link": "unsafe link",
            "deceptive_link": "misleading link",
            "dangerous_file": "dangerous file",
        }

        leafs = self._collect_leaf_facts(node)
        readable = [fact_labels.get(f, f.replace('_', ' ')) for f in leafs]

        if not readable:
            return "risk patterns matched"
        if len(readable) == 1:
            return readable[0]
        if len(readable) == 2:
            return f"{readable[0]} and {readable[1]}"
        return ", ".join(readable[:-1]) + f", and {readable[-1]}"
