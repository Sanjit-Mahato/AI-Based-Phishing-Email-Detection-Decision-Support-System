"""
Integration & Unit Test Suite
Verifies all 4 AI modules, pipeline components, and decision support logic.
"""

import unittest
import os
import sys

# Ensure root in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.email_parser import EmailParser
from src.preprocessing.feature_extractor import FeatureExtractor
from src.heuristics.baseline_scorer import BaselineHeuristicScorer
from src.expert_system.knowledge_base import KnowledgeBase
from src.expert_system.forward_chaining import ForwardChainingEngine
from src.expert_system.backward_chaining import BackwardChainingEngine
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.adversarial.minimax_engine import AdversarialSearchEngine
from src.dss.decision_support import DecisionSupportSystem


class TestPhishingDetectionPipeline(unittest.TestCase):

    def setUp(self):
        self.parser = EmailParser()
        self.extractor = FeatureExtractor()
        self.scorer = BaselineHeuristicScorer()
        self.forward_engine = ForwardChainingEngine()
        self.backward_engine = BackwardChainingEngine()
        self.adv_engine = AdversarialSearchEngine()

        self.sample_phish = (
            "From: Chase Security <security@chase-portal.xyz>\n"
            "Reply-To: catch@attacker-inbox.xyz\n"
            "Subject: Urgent: Your online banking is suspended!\n"
            "Attachment: security_fix.exe\n\n"
            "Please immediately verify your account within 24 hours at:\n"
            "http://192.168.1.100/verify-account/auth\n"
        )

        self.sample_safe = (
            "From: Professor Nazim <mnazim@niet.co.in>\n"
            "Reply-To: mnazim@niet.co.in\n"
            "Subject: AI-PBL Project Review Guidelines\n\n"
            "Dear class, please review the uploaded rubric for Semester 3 AI assignment.\n"
            "Link: https://moodle.niet.co.in/course/view.php?id=301\n"
        )

    def test_email_parser(self):
        parsed = self.parser.parse_raw_text(self.sample_phish)
        self.assertIn("chase-portal.xyz", parsed["sender"])
        self.assertIn("attacker-inbox.xyz", parsed["reply_to"])
        self.assertIn("security_fix.exe", parsed["attachments"])
        self.assertTrue(len(parsed["urls"]) > 0)

    def test_feature_extractor(self):
        feats, ev = self.extractor.extract_features(self.sample_phish)
        self.assertEqual(feats["reply_to_mismatch"], 1)
        self.assertEqual(feats["ip_in_url"], 1)
        self.assertEqual(feats["suspicious_tld"], 1)
        self.assertEqual(feats["urgency_words"], 1)
        self.assertEqual(feats["executable_attachment"], 1)
        self.assertEqual(feats["no_https"], 1)

    def test_unit_1_heuristic_scorer(self):
        feats, _ = self.extractor.extract_features(self.sample_phish)
        res = self.scorer.evaluate(feats)
        self.assertEqual(res["verdict"], "Phishing")
        self.assertGreaterEqual(res["score"], 5)

        safe_feats, _ = self.extractor.extract_features(self.sample_safe)
        safe_res = self.scorer.evaluate(safe_feats)
        self.assertEqual(safe_res["verdict"], "Safe")
        self.assertLess(safe_res["score"], 3)

    def test_unit_3_expert_system(self):
        feats, _ = self.extractor.extract_features(self.sample_phish)
        
        # Forward Chaining
        fc_res = self.forward_engine.infer(feats)
        self.assertEqual(fc_res["verdict"], "Phishing")
        self.assertIn("spoofed_sender", fc_res["derived_facts"])
        self.assertIn("bad_link", fc_res["derived_facts"])

        # Backward Chaining
        bc_res = self.backward_engine.explain(feats)
        self.assertEqual(bc_res["proved_verdict"], "Phishing")
        self.assertTrue(bc_res["is_proved"])
        self.assertIn("phishing", bc_res["explanation"])

    def test_unit_4_naive_bayes(self):
        train_data = [
            {"features": {"ip_in_url": 1, "urgency_words": 1, "no_https": 1}, "label": 1},
            {"features": {"ip_in_url": 0, "urgency_words": 0, "no_https": 0}, "label": 0}
        ]
        clf = NaiveBayesClassifier()
        clf.train(train_data)
        self.assertTrue(clf.is_trained)

        probs = clf.predict_proba({"ip_in_url": 1, "urgency_words": 1})
        self.assertGreater(probs["phishing"], probs["safe"])

    def test_unit_2_adversarial_minimax(self):
        feats, _ = self.extractor.extract_features(self.sample_phish)
        adv_res = self.adv_engine.run_adversarial_simulation(feats)
        self.assertIn("optimal_attacker_tactic", adv_res)
        self.assertGreater(adv_res["search_statistics"]["nodes_evaluated"], 0)
        self.assertIn("tactics_matrix", adv_res)

    def test_integrated_decision_support(self):
        dss = DecisionSupportSystem()
        result = dss.analyze_email(self.sample_phish)
        self.assertEqual(result["final_verdict"], "Phishing")
        self.assertGreater(result["risk_index"], 60.0)
        self.assertTrue(len(result["recommendations"]) > 0)


if __name__ == "__main__":
    unittest.main()
