"""
Integrated Decision Support System (DSS)
Synthesizes Module 1 (Heuristic Scoring), Module 2 (Adversarial Robustness),
Module 3 (Expert System Horn Clauses & Proof Tree), and Module 4 (Naive Bayes Probability)
into an authoritative, explainable security verdict with actionable recommendations.
"""

from typing import Dict, Any, List
from ..preprocessing.email_parser import EmailParser
from ..preprocessing.feature_extractor import FeatureExtractor
from ..heuristics.baseline_scorer import BaselineHeuristicScorer
from ..expert_system.knowledge_base import KnowledgeBase
from ..expert_system.forward_chaining import ForwardChainingEngine
from ..expert_system.backward_chaining import BackwardChainingEngine
from ..statistical.naive_bayes import NaiveBayesClassifier
from ..adversarial.minimax_engine import AdversarialSearchEngine


class DecisionSupportSystem:
    """
    Central AI Decision Support System for Phishing Email Detection.
    Fulfills academic syllabus requirements:
      - Module 1: Informed Heuristic Search
      - Module 2: Minimax Adversarial Game Search
      - Module 3: Horn Clause Knowledge Base & Backward Chaining Proof Tree
      - Module 4: Bayes' Theorem & Posterior Probability
    """

    def __init__(self, classifier: NaiveBayesClassifier = None):
        self.parser = EmailParser()
        self.feature_extractor = FeatureExtractor()
        self.heuristic_scorer = BaselineHeuristicScorer()
        self.forward_engine = ForwardChainingEngine()
        self.backward_engine = BackwardChainingEngine()
        self.adversarial_engine = AdversarialSearchEngine()
        self.classifier = classifier or NaiveBayesClassifier()

    def set_classifier(self, classifier: NaiveBayesClassifier) -> None:
        self.classifier = classifier

    def analyze_email(self, email_input: Any, include_adversarial: bool = True) -> Dict[str, Any]:
        """
        Runs the complete multi-module AI decision pipeline on raw or structured email input.
        """
        # 1. Parsing
        if isinstance(email_input, str):
            parsed = self.parser.parse_raw_text(email_input)
        elif isinstance(email_input, dict):
            parsed = email_input
        else:
            raise ValueError("Input must be a string or dictionary")

        # 2. Preprocessing & Feature Extraction
        features, evidence = self.feature_extractor.extract_features(parsed)

        # 3. Unit 1: Heuristic Scoring Baseline
        heuristic_res = self.heuristic_scorer.evaluate(features)

        # 4. Unit 3: Knowledge Representation & Expert System
        frame_rep = KnowledgeBase.create_email_frame(parsed, features)
        forward_res = self.forward_engine.infer(features)
        backward_res = self.backward_engine.explain(features)

        # 5. Unit 4: Statistical Reasoning & Naive Bayes Probability
        bayes_res = self.classifier.predict(features)
        p_phishing = bayes_res["probability_phishing"]

        # 6. Combined Decision Support Logic (Month 2 Progress Report Specification)
        # Rules give the primary reason, posterior probability adjusts/calibrates it:
        # - Phishing requires p_phishing >= 0.5
        # - Suspicious is elevated to Phishing if p_phishing >= 0.9
        # - Suspicious is downgraded to Safe if p_phishing < 0.2
        rule_verdict = backward_res["proved_verdict"]

        if rule_verdict == "Phishing":
            if p_phishing >= 0.5:
                final_verdict = "Phishing"
                confidence = max(p_phishing * 100, 75.0)
            else:
                final_verdict = "Suspicious"
                confidence = 65.0
        elif rule_verdict == "Suspicious":
            if p_phishing >= 0.90:
                final_verdict = "Phishing"
                confidence = p_phishing * 100
            elif p_phishing < 0.20:
                final_verdict = "Safe"
                confidence = (1.0 - p_phishing) * 100
            else:
                final_verdict = "Suspicious"
                confidence = max(p_phishing, 1.0 - p_phishing) * 100
        else:  # Rule verdict Safe
            if p_phishing >= 0.85:
                final_verdict = "Suspicious"
                confidence = p_phishing * 100
            else:
                final_verdict = "Safe"
                confidence = (1.0 - p_phishing) * 100

        # Risk Score Index (0 to 100)
        risk_index = round(
            (0.40 * (heuristic_res["score"] / self.heuristic_scorer.phishing_threshold * 100)) +
            (0.40 * (p_phishing * 100)) +
            (0.20 * (100.0 if final_verdict == "Phishing" else (50.0 if final_verdict == "Suspicious" else 0.0))),
            1
        )
        risk_index = min(100.0, max(0.0, risk_index))

        # 7. Actionable Decision Support Recommendations
        recommendations = self._generate_recommendations(final_verdict, features, evidence, backward_res)

        # 8. Unit 2: Adversarial Robustness Search (optional per request for speed)
        adversarial_res = None
        if include_adversarial:
            adversarial_res = self.adversarial_engine.run_adversarial_simulation(features)

        return {
            "final_verdict": final_verdict,
            "risk_index": risk_index,
            "confidence_percentage": round(confidence, 1),
            "is_flagged": final_verdict in ["Suspicious", "Phishing"],
            "summary_explanation": backward_res["summary"],
            "recommendations": recommendations,
            "modules": {
                "unit_1_heuristic": heuristic_res,
                "unit_2_adversarial": adversarial_res,
                "unit_3_expert_system": {
                    "forward_chaining": forward_res,
                    "backward_chaining": backward_res,
                    "frame_representation": frame_rep
                },
                "unit_4_statistical": bayes_res
            },
            "features": features,
            "evidence": evidence,
            "parsed_email": parsed
        }

    def _generate_recommendations(
        self,
        verdict: str,
        features: Dict[str, int],
        evidence: Dict[str, Any],
        backward_res: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generates role-specific, explainable cybersecurity advisory steps."""
        recs = []

        if verdict == "Phishing":
            recs.append({
                "level": "CRITICAL",
                "action": "Quarantine / Delete Immediately",
                "detail": "Do not interact with this email, click any hyperlinks, or reply to the sender."
            })
            if features.get("executable_attachment"):
                recs.append({
                    "level": "CRITICAL",
                    "action": "Do Not Execute Attachments",
                    "detail": f"Contains dangerous file payloads ({', '.join(evidence.get('executable_attachment', []))}). Sandbox inspection required."
                })
            if features.get("reply_to_mismatch"):
                recs.append({
                    "level": "HIGH",
                    "action": "Sender Identity Spoofing Detected",
                    "detail": f"Sender domain does not match return path: {evidence.get('reply_to_mismatch', '')}."
                })
            if features.get("ip_in_url") or features.get("suspicious_tld"):
                recs.append({
                    "level": "HIGH",
                    "action": "Block Malicious Host & URLs",
                    "detail": "Add observed IP address/suspicious domains to enterprise firewall and mail gateway blocklists."
                })
            recs.append({
                "level": "INFO",
                "action": "Notify Security Operations Center (SOC)",
                "detail": "Forward headers as an attachment to internal security team for threat intelligence logging."
            })

        elif verdict == "Suspicious":
            recs.append({
                "level": "WARNING",
                "action": "Treat With Caution",
                "detail": "This email displays deceptive characteristics but has not yet met full malicious criteria."
            })
            if features.get("urgency_words"):
                recs.append({
                    "level": "WARNING",
                    "action": "Beware of Psychological Coercion",
                    "detail": "Urgency words detected attempting to force hasty user action. Verify independently via official phone/portal."
                })
            if features.get("no_https"):
                recs.append({
                    "level": "WARNING",
                    "action": "Unencrypted Destination Link",
                    "detail": "Links use unencrypted HTTP protocol, exposing credentials to interception."
                })

        else:
            recs.append({
                "level": "SUCCESS",
                "action": "Standard Verification",
                "detail": "No anomalous phishing traits, spoofed headers, or malicious files were identified."
            })
            recs.append({
                "level": "INFO",
                "action": "Maintain Hygiene",
                "detail": "Always practice standard cybersecurity hygiene before inputting sensitive credentials."
            })

        return recs
