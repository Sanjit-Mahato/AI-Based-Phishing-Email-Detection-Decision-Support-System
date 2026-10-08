"""
Interactive Experiment & EDA Runner
Performs feature distribution analysis, correlation inspection, and multi-detector evaluation.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.feature_extractor import FeatureExtractor
from src.heuristics.baseline_scorer import BaselineHeuristicScorer
from src.expert_system.backward_chaining import BackwardChainingEngine
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.statistical.evaluation import ModelEvaluator
from src.adversarial.minimax_engine import AdversarialSearchEngine
from data.benchmark_dataset import generate_benchmark_emails


def run_experiments():
    print("=" * 70)
    print("PHISHING EMAIL DETECTION & DSS - EXPERIMENT ANALYSIS")
    print("=" * 70)

    train_emails, test_emails = generate_benchmark_emails()
    extractor = FeatureExtractor()

    for s in train_emails + test_emails:
        s["features"], s["evidence"] = extractor.extract_features(s["raw"])

    # 1. Feature Prevalence Analysis
    print("\n[1] FEATURE PREVALENCE IN DATASET (200 Emails):")
    total_phish = sum(1 for s in train_emails + test_emails if s["label"] == 1)
    total_safe = sum(1 for s in train_emails + test_emails if s["label"] == 0)

    print(f"    Total Phishing: {total_phish} | Total Legitimate: {total_safe}")
    print(f"    {'Feature Name':<25} | {'Phishing (n=100)':<16} | {'Legitimate (n=100)':<16}")
    print("    " + "-" * 62)

    for feat in FeatureExtractor.FEATURE_NAMES:
        phish_count = sum(1 for s in train_emails + test_emails if s["label"] == 1 and s["features"].get(feat, 0) == 1)
        safe_count = sum(1 for s in train_emails + test_emails if s["label"] == 0 and s["features"].get(feat, 0) == 1)
        print(f"    {feat:<25} | {phish_count:<16} | {safe_count:<16}")

    # 2. Train Naive Bayes & Log-Odds Feature Importance
    clf = NaiveBayesClassifier()
    clf.train(train_emails)

    print("\n[2] NAIVE BAYES FEATURE LOG-ODDS RATIO (Importance Ranking):")
    importance = clf.get_feature_importance()
    print(f"    {'Feature':<25} | {'P(feat|Phish)':<14} | {'P(feat|Safe)':<14} | {'Log-Odds Ratio':<14}")
    print("    " + "-" * 72)
    for item in importance:
        print(f"    {item['feature']:<25} | {item['prob_given_phishing']:<14.3f} | {item['prob_given_safe']:<14.3f} | {item['log_odds_ratio']:<14.3f}")

    # 3. Adversarial Search Evasion Sensitivity
    print("\n[3] ADVERSARIAL EVASION SENSITIVITY (Minimax Game Search):")
    adv_engine = AdversarialSearchEngine()
    sample = test_emails[0]
    sim = adv_engine.run_adversarial_simulation(sample["features"])

    print(f"    Sample: {sample['id']} ({sample['type']})")
    print(f"    Optimal Attacker Move: {sim['optimal_attacker_tactic']['name']}")
    print(f"    Search Tree Evaluated Nodes: {sim['search_statistics']['nodes_evaluated']} | Alpha-Beta Prunings: {sim['search_statistics']['pruning_cutoffs']}")
    print(f"    Game Payoff: {sim['game_payoff']}")

    print("\n" + "=" * 70)
    print("Experiments completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_experiments()
