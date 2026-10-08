"""
Benchmark Verification Test Suite
Tests that the 60 test emails and 5-fold cross-validation run properly.
"""

import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.feature_extractor import FeatureExtractor
from src.heuristics.baseline_scorer import BaselineHeuristicScorer
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.statistical.evaluation import ModelEvaluator
from data.benchmark_dataset import generate_benchmark_emails


class TestBenchmarkReproduction(unittest.TestCase):

    def test_benchmark_metrics(self):
        train_emails, test_emails = generate_benchmark_emails()
        self.assertEqual(len(train_emails), 140)
        self.assertEqual(len(test_emails), 60)

        extractor = FeatureExtractor()
        for s in train_emails:
            s["features"], _ = extractor.extract_features(s["raw"])
        for s in test_emails:
            s["features"], _ = extractor.extract_features(s["raw"])

        # Train Naive Bayes
        clf = NaiveBayesClassifier()
        clf.train(train_emails)

        y_true = [s["label"] for s in test_emails]
        self.assertEqual(sum(y_true), 28)
        self.assertEqual(len(y_true) - sum(y_true), 32)

        # Baseline heuristic
        scorer = BaselineHeuristicScorer()
        y_pred_heur = [1 if scorer.evaluate(s["features"])["is_flagged"] else 0 for s in test_emails]
        m_heur = ModelEvaluator.compute_metrics(y_true, y_pred_heur)

        self.assertAlmostEqual(m_heur["accuracy"], 0.883, places=2)
        self.assertAlmostEqual(m_heur["recall"], 1.000, places=2)

        # 5-fold CV
        cv = ModelEvaluator.cross_validate_naive_bayes(train_emails + test_emails, k_folds=5)
        self.assertEqual(cv["k_folds"], 5)
        self.assertGreater(cv["mean_accuracy"], 0.85)


if __name__ == "__main__":
    unittest.main()
