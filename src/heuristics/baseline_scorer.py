"""
Heuristic Baseline Scorer (Unit/Module 1: Problem Solving & Heuristic Search)
Implements weighted feature scoring and search-based risk prioritization.
"""

from typing import Dict, Any, List, Tuple


class BaselineHeuristicScorer:
    """
    Heuristic scoring engine as specified in Month 2 Progress Report.
    Weights:
      - 3: reply_to_mismatch, ip_in_url, executable_attachment
      - 2: urgency_words, suspicious_tld
      - 1: no_https, long_url
    Thresholds:
      - Score >= 5 -> Phishing
      - Score >= 3 -> Suspicious
      - Score < 3  -> Safe
    """

    DEFAULT_WEIGHTS = {
        "reply_to_mismatch": 3,
        "ip_in_url": 3,
        "executable_attachment": 3,
        "urgency_words": 2,
        "suspicious_tld": 2,
        "no_https": 1,
        "long_url": 1
    }

    MAX_POSSIBLE_SCORE = sum(DEFAULT_WEIGHTS.values())  # 15

    def __init__(self, weights: Dict[str, int] = None, suspicious_threshold: int = 3, phishing_threshold: int = 5):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self.suspicious_threshold = suspicious_threshold
        self.phishing_threshold = phishing_threshold

    def evaluate(self, features: Dict[str, int]) -> Dict[str, Any]:
        """
        Computes the weighted heuristic score, verdict, and breakdown.
        """
        score = 0
        active_factors = []

        for feature_name, weight in self.weights.items():
            if features.get(feature_name, 0) == 1:
                score += weight
                active_factors.append({
                    "feature": feature_name,
                    "weight": weight,
                    "contribution": weight
                })

        # Sort factors by weight descending (Greedy prioritization / informed search)
        active_factors.sort(key=lambda x: x["weight"], reverse=True)

        if score >= self.phishing_threshold:
            verdict = "Phishing"
            risk_level = "HIGH"
        elif score >= self.suspicious_threshold:
            verdict = "Suspicious"
            risk_level = "MEDIUM"
        else:
            verdict = "Safe"
            risk_level = "LOW"

        normalized_risk = min(1.0, score / self.phishing_threshold)

        return {
            "score": score,
            "max_score": self.MAX_POSSIBLE_SCORE,
            "verdict": verdict,
            "risk_level": risk_level,
            "normalized_risk": round(normalized_risk, 3),
            "is_flagged": verdict in ["Suspicious", "Phishing"],
            "active_factors": active_factors,
            "thresholds": {
                "suspicious": self.suspicious_threshold,
                "phishing": self.phishing_threshold
            }
        }

    def search_minimal_evasion(self, features: Dict[str, int]) -> List[Tuple[str, int]]:
        """
        Module 1 Informed Search: Find the minimum feature set an attacker would need
        to suppress to lower a Phishing or Suspicious email to Safe (< 3).
        """
        current_res = self.evaluate(features)
        target = self.suspicious_threshold - 1
        needed_reduction = current_res["score"] - target

        if needed_reduction <= 0:
            return []

        # Greedy best-first selection of highest weight active features
        active = sorted(
            [f for f in current_res["active_factors"]],
            key=lambda x: x["weight"],
            reverse=True
        )

        suppressed = []
        reduction = 0
        for item in active:
            suppressed.append((item["feature"], item["weight"]))
            reduction += item["weight"]
            if reduction >= needed_reduction:
                break

        return suppressed
