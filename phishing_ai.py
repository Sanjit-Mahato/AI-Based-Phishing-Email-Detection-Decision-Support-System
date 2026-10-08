#!/usr/bin/env python3
"""
AI-Based Phishing Email Detection & Decision Support System
Primary Project Pipeline & Month 2 Review Benchmark Runner

Authors / Team Aahvaan (Group 1 - CCSAI0301 - NIET):
  - Maneesh Ray (Team Lead & AI Solution Architect)
  - Chandan Kumar (Search Algorithm & Optimisation Analyst)
  - Devanshu (Heuristic & Decision Intelligence Specialist)
  - Sanjit Kumar (Knowledge Representation & Expert System Designer)
  - Amresh Singh (Statistical AI Analyst & Documentation Lead)

Modules Applied:
  - Unit 1: Informed Search & Heuristic Feature Scoring
  - Unit 2: Adversarial Search (Minimax with Alpha-Beta Pruning)
  - Unit 3: Knowledge Representation (Horn Clauses, Forward & Backward Chaining)
  - Unit 4: Statistical Reasoning (Bayes' Theorem, Naive Bayes, Laplace Smoothing)
"""

import os
import sys
import json

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.feature_extractor import FeatureExtractor
from src.heuristics.baseline_scorer import BaselineHeuristicScorer
from src.expert_system.forward_chaining import ForwardChainingEngine
from src.expert_system.backward_chaining import BackwardChainingEngine
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.statistical.evaluation import ModelEvaluator
from src.dss.decision_support import DecisionSupportSystem
from src.adversarial.minimax_engine import AdversarialSearchEngine
from data.benchmark_dataset import generate_benchmark_emails


def run_benchmark_and_evaluation(save_output_file: bool = True):
    print("=" * 80)
    print("AI-BASED PHISHING EMAIL DETECTION & DECISION SUPPORT SYSTEM")
    print("Comprehensive PBL Review & Evaluation Pipeline")
    print("=" * 80)

    # 1. Load / Generate benchmark datasets (200 total: 140 train, 60 test)
    train_emails, test_emails = generate_benchmark_emails()
    print(f"[*] Dataset initialized: {len(train_emails)} training emails, {len(test_emails)} test emails.")
    print(f"[*] Test set breakdown: 28 Phishing, 32 Legitimate emails.")

    # 2. Extract features for training and test sets
    extractor = FeatureExtractor()

    for s in train_emails:
        s["features"], s["evidence"] = extractor.extract_features(s["raw"])
    for s in test_emails:
        s["features"], s["evidence"] = extractor.extract_features(s["raw"])

    # 3. Train Naive Bayes Classifier (Module 4)
    nb_clf = NaiveBayesClassifier(alpha=1.0, threshold=0.5)
    nb_clf.train(train_emails)

    # Save trained model
    os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)
    model_path = os.path.join(BASE_DIR, "models", "trained_naive_bayes.json")
    nb_clf.save_to_file(model_path)
    print(f"[*] Trained Naive Bayes model saved to: {model_path}")

    # 4. Initialize All Detectors
    heuristic = BaselineHeuristicScorer()
    forward_engine = ForwardChainingEngine()
    backward_engine = BackwardChainingEngine()
    dss = DecisionSupportSystem(classifier=nb_clf)

    y_true = [s["label"] for s in test_emails]

    # Detector 1: Heuristic baseline (flagged if score >= 3)
    y_pred_heuristic = []
    for s in test_emails:
        res = heuristic.evaluate(s["features"])
        y_pred_heuristic.append(1 if res["is_flagged"] else 0)

    # Detector 2: Rule base (flagged: Suspicious or Phishing)
    y_pred_rule_flagged = []
    # Detector 3: Rule base (Phishing only)
    y_pred_rule_phishing_only = []
    for s in test_emails:
        res = forward_engine.infer(s["features"])
        y_pred_rule_flagged.append(1 if res["is_flagged"] else 0)
        y_pred_rule_phishing_only.append(1 if res["verdict"] == "Phishing" else 0)

    # Detector 4: Naive Bayes (>= 0.5)
    y_pred_nb = []
    for s in test_emails:
        res = nb_clf.predict(s["features"])
        y_pred_nb.append(res["predicted_label"])

    # Detector 5: Combined DSS (flagged)
    y_pred_combined = []
    for s in test_emails:
        res = dss.analyze_email(s, include_adversarial=False)
        y_pred_combined.append(1 if res["is_flagged"] else 0)

    # Compute metrics for all 5 detectors
    m_heuristic = ModelEvaluator.compute_metrics(y_true, y_pred_heuristic)
    m_rule_flagged = ModelEvaluator.compute_metrics(y_true, y_pred_rule_flagged)
    m_rule_phish = ModelEvaluator.compute_metrics(y_true, y_pred_rule_phishing_only)
    m_nb = ModelEvaluator.compute_metrics(y_true, y_pred_nb)
    m_combined = ModelEvaluator.compute_metrics(y_true, y_pred_combined)

    # 5. Format Results Table matching Month 2 Progress Report Section 8
    print("\n" + "-" * 80)
    print("RESULTS ON 60 TEST EMAILS (28 Phishing, 32 Legitimate):")
    print("-" * 80)
    header = f"{'Detector':<26} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<6} | {'False +':<7} | {'False -':<7}"
    print(header)
    print("-" * 80)

    rows = [
        ("Heuristic baseline", m_heuristic),
        ("Rule base (flagged)", m_rule_flagged),
        ("Rule base (Phishing only)", m_rule_phish),
        ("Naive Bayes (>= 0.5)", m_nb),
        ("Combined (flagged)", m_combined)
    ]

    for name, m in rows:
        print(f"{name:<26} | {m['accuracy']:<8.3f} | {m['precision']:<9.3f} | {m['recall']:<6.3f} | {m['false_positives']:<7} | {m['false_negatives']:<7}")
    print("-" * 80)

    # 6. 5-Fold Cross Validation
    cv_res = ModelEvaluator.cross_validate_naive_bayes(train_emails + test_emails, k_folds=5, seed=42)
    acc_strs = ", ".join([f"{a:.3f}" for a in cv_res["fold_accuracies"]])
    print(f"\n[*] Naive Bayes 5-fold cross-validation accuracy: {acc_strs} (mean {cv_res['mean_accuracy']:.3f})")

    # 7. Backward Chaining Explanation Example
    sample_phish_raw = (
        "From: Security Desk <service@secure-alert.xyz>\n"
        "Reply-To: credentials-catcher@malicious-host.xyz\n"
        "Subject: Immediate action required: Account Suspended\n\n"
        "Please visit: http://192.168.1.100/login to verify your account within 24 hours.\n"
    )
    sample_feats, _ = extractor.extract_features(sample_phish_raw)
    explanation_res = backward_engine.explain(sample_feats)
    print("\n" + "-" * 80)
    print("[*] Module 3 Backward Chaining Explainability Demonstration:")
    print(f"    Raw Email Trigger: reply_to_mismatch, suspicious_tld, ip_in_url, urgency_words")
    print(f"    Backward Chaining Goal: prove 'phishing'")
    print(f"    Generated Explanation: \"{explanation_res['explanation']}\"")
    print("-" * 80)

    # 8. Adversarial Game Minimax Demonstration
    adv_engine = AdversarialSearchEngine()
    adv_res = adv_engine.run_adversarial_simulation(sample_feats)
    print("\n[*] Module 2 Adversarial Game Search (Minimax with Alpha-Beta Pruning):")
    print(f"    Attacker Optimal Strategy: {adv_res['optimal_attacker_tactic']['name']}")
    print(f"    Evaluated Nodes: {adv_res['search_statistics']['nodes_evaluated']} | Alpha-Beta Pruned Branches: {adv_res['search_statistics']['pruning_cutoffs']}")
    print(f"    Game Payoff Value: {adv_res['game_payoff']}")
    print("=" * 80 + "\n")

    # Save to phishing_output.txt if requested
    if save_output_file:
        output_txt_path = os.path.join(BASE_DIR, "phishing_output.txt")
        with open(output_txt_path, "w", encoding="utf-8") as f:
            f.write("AI-BASED PHISHING EMAIL DETECTION & DECISION SUPPORT SYSTEM\n")
            f.write("BENCHMARK EXECUTION LOG & VERIFICATION OUTPUT\n\n")
            f.write(header + "\n")
            f.write("-" * 80 + "\n")
            for name, m in rows:
                f.write(f"{name:<26} | {m['accuracy']:<8.3f} | {m['precision']:<9.3f} | {m['recall']:<6.3f} | {m['false_positives']:<7} | {m['false_negatives']:<7}\n")
            f.write("-" * 80 + "\n\n")
            f.write(f"Naive Bayes 5-fold cross-validation accuracy: {acc_strs} (mean {cv_res['mean_accuracy']:.3f})\n\n")
            f.write(f"Backward Chaining Proof: {explanation_res['explanation']}\n\n")
            f.write(f"Adversarial Minimax: Nodes={adv_res['search_statistics']['nodes_evaluated']}, Pruned={adv_res['search_statistics']['pruning_cutoffs']}, Optimal={adv_res['optimal_attacker_tactic']['name']}\n")
        print(f"[*] Results saved to {output_txt_path}")


if __name__ == "__main__":
    run_benchmark_and_evaluation()
