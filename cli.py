#!/usr/bin/env python3
"""
Interactive Command Line Interface (CLI)
AI-Based Phishing Email Detection & Decision Support System
"""

import os
import sys
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.feature_extractor import FeatureExtractor
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.statistical.evaluation import ModelEvaluator
from src.dss.decision_support import DecisionSupportSystem
from src.adversarial.minimax_engine import AdversarialSearchEngine
from data.benchmark_dataset import generate_benchmark_emails
from data.kaggle_loader import KaggleDatasetLoader
from phishing_ai import run_benchmark_and_evaluation

PRESET_EMAILS = [
    {
        "name": "1. High-Risk Banking Credential Harvester (Phishing)",
        "text": (
            "From: Chase Security Alert <alerts@chase-bank-verify.xyz>\n"
            "Reply-To: security-drop@attacker-server.xyz\n"
            "Subject: Urgent: Your online banking access is temporarily suspended\n"
            "Attachment: security_update.exe\n\n"
            "Dear Customer,\n\n"
            "We detected unauthorized login attempts from an unknown device. "
            "Your online banking access has been suspended. You must immediately verify your account "
            "within 24 hours to prevent permanent closure.\n\n"
            "Click here to restore your account:\n"
            "http://192.168.1.105/auth/verify?session=9283748192384729182374912837491283\n\n"
            "Security Team, Chase Financial Services"
        )
    },
    {
        "name": "2. Evasive Spear-Phishing / Executive Impersonation (Suspicious)",
        "text": (
            "From: HR Department <hr@company-internal.net>\n"
            "Reply-To: external-hr-auditor@consulting-partners.com\n"
            "Subject: Action Required: Mandatory Annual Policy Sign-off\n\n"
            "Hi team,\n\n"
            "Please review the updated corporate compensation and benefit policies before the end of the day.\n"
            "Immediate sign-off is required by management.\n\n"
            "Access the document here: http://corporate-review.online-work.club/login\n"
        )
    },
    {
        "name": "3. Legitimate University Project Notification (Safe)",
        "text": (
            "From: Dr. Mohd Nazim <mnazim@niet.co.in>\n"
            "Reply-To: mnazim@niet.co.in\n"
            "Subject: AI-PBL Review Schedule and Submission Guidelines\n\n"
            "Dear Students,\n\n"
            "Please find the schedule for Review 2 on Moodle. Make sure to commit your source code "
            "and progress reports before the deadline. Reach out if you have any technical queries.\n\n"
            "Portal: https://moodle.niet.co.in/course/view.php?id=301\n\n"
            "Best regards,\nDr. Mohd Nazim"
        )
    }
]


def print_banner():
    print("""
================================================================================
     AI-BASED PHISHING EMAIL DETECTION & DECISION SUPPORT SYSTEM
       NIET Greater Noida - BTech CSE - AI PBL (Course: CCSAI0301)
================================================================================
  Team: Maneesh Ray | Chandan Kumar | Devanshu | Sanjit Kumar | Amresh Singh
  Modules: Heuristic Search | Adversarial Minimax | Horn Clauses | Bayes Net
================================================================================
""")


def analyze_email_interactive(dss: DecisionSupportSystem):
    print("\n--- ANALYZE EMAIL ---")
    print("Choose an option:")
    for i, p in enumerate(PRESET_EMAILS, 1):
        print(f"  [{i}] Preset: {p['name']}")
    print("  [4] Paste Custom Email Text")
    print("  [0] Back to Main Menu")

    choice = input("\nEnter choice (0-4): ").strip()
    if choice == "0":
        return
    elif choice in ["1", "2", "3"]:
        raw_text = PRESET_EMAILS[int(choice) - 1]["text"]
    elif choice == "4":
        print("\nPaste your email text below (include From/Subject headers if available).")
        print("Enter EOF by typing '---END---' on an empty line when finished:")
        lines = []
        while True:
            line = input()
            if line.strip() == "---END---":
                break
            lines.append(line)
        raw_text = "\n".join(lines).strip()
        if not raw_text:
            print("[!] Empty input. Aborting.")
            return
    else:
        print("[!] Invalid option.")
        return

    print("\n[+] Analyzing email through all 4 AI modules...")
    result = dss.analyze_email(raw_text, include_adversarial=True)

    print("\n" + "=" * 70)
    print("DECISION SUPPORT SYSTEM (DSS) VERDICT & THREAT ASSESSMENT")
    print("=" * 70)
    verdict = result["final_verdict"]
    color = "\033[91m" if verdict == "Phishing" else ("\033[93m" if verdict == "Suspicious" else "\033[92m")
    reset = "\033[0m"

    print(f"Final Verdict       : {color}{verdict.upper()}{reset}")
    print(f"Risk Index (0-100)  : {result['risk_index']} / 100")
    print(f"Confidence Level    : {result['confidence_percentage']}%")
    print(f"Summary Explanation : {result['summary_explanation']}")

    print("\n" + "-" * 70)
    print("MODULE BREAKDOWN:")
    print("-" * 70)
    u1 = result["modules"]["unit_1_heuristic"]
    print(f"1. Unit 1 Heuristic Search  : Score {u1['score']}/{u1['max_score']} (Risk: {u1['risk_level']})")
    if u1["active_factors"]:
        for factor in u1["active_factors"]:
            print(f"   * Active indicator: {factor['feature']} (Weight: {factor['weight']})")

    u3 = result["modules"]["unit_3_expert_system"]
    print(f"2. Unit 3 Expert System     : Proved '{u3['backward_chaining']['proved_verdict']}' via Horn Clauses")
    print(f"   * Explanation: {u3['backward_chaining']['explanation']}")
    if u3["forward_chaining"]["fired_rules"]:
        print(f"   * Fired Rules: {', '.join([r['rule_id'] for r in u3['forward_chaining']['fired_rules']])}")

    u4 = result["modules"]["unit_4_statistical"]
    print(f"3. Unit 4 Naive Bayes       : P(Phishing) = {u4['probability_phishing'] * 100:.1f}% | P(Safe) = {u4['probability_safe'] * 100:.1f}%")

    u2 = result["modules"]["unit_2_adversarial"]
    if u2:
        print(f"4. Unit 2 Adversarial Game  : Minimax Alpha-Beta Search")
        print(f"   * Optimal Attacker Move : {u2['optimal_attacker_tactic']['name']}")
        print(f"   * Evaluated Nodes       : {u2['search_statistics']['nodes_evaluated']} (Pruned branches: {u2['search_statistics']['pruning_cutoffs']})")
        print(f"   * Game Payoff Value     : {u2['game_payoff']}")

    print("\n" + "-" * 70)
    print("ACTIONABLE SECURITY RECOMMENDATIONS:")
    print("-" * 70)
    for rec in result["recommendations"]:
        print(f"[{rec['level']}] {rec['action']}: {rec['detail']}")
    print("=" * 70 + "\n")


def run_kaggle_evaluation():
    print("\n--- KAGGLE DATASET EVALUATION (Phishing_Email.csv) ---")
    loader = KaggleDatasetLoader()
    if not loader.exists():
        print("[!] Phishing_Email.csv not found in parent directory.")
        return

    n_str = input("Enter number of samples to evaluate (e.g. 1000, 2000, 5000) [Default: 1000]: ").strip()
    max_samples = int(n_str) if n_str.isdigit() else 1000

    print(f"[+] Loading {max_samples} balanced emails from Kaggle dataset...")
    samples = loader.load_samples(max_samples=max_samples)
    print(f"[+] Loaded {len(samples)} emails. Running 70/30 train/test evaluation...")

    split = int(0.7 * len(samples))
    train = samples[:split]
    test = samples[split:]

    clf = NaiveBayesClassifier()
    clf.train(train)

    y_true = [s["label"] for s in test]
    y_pred = [clf.predict(s["features"])["predicted_label"] for s in test]

    metrics = ModelEvaluator.compute_metrics(y_true, y_pred)
    print("\n" + "-" * 70)
    print(f"EVALUATION RESULTS ON KAGGLE TEST SET ({len(test)} samples):")
    print("-" * 70)
    print(f"Accuracy         : {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision        : {metrics['precision']:.4f}")
    print(f"Recall           : {metrics['recall']:.4f}")
    print(f"F1 Score         : {metrics['f1_score']:.4f}")
    print(f"True Positives   : {metrics['true_positives']}")
    print(f"False Positives  : {metrics['false_positives']}")
    print(f"True Negatives   : {metrics['true_negatives']}")
    print(f"False Negatives  : {metrics['false_negatives']}")
    print("-" * 70 + "\n")


def main():
    # Load trained model if available, else train on benchmark
    model_path = os.path.join(BASE_DIR, "models", "trained_naive_bayes.json")
    if os.path.exists(model_path):
        clf = NaiveBayesClassifier.load_from_file(model_path)
    else:
        train_emails, _ = generate_benchmark_emails()
        extractor = FeatureExtractor()
        for s in train_emails:
            s["features"], _ = extractor.extract_features(s["raw"])
        clf = NaiveBayesClassifier()
        clf.train(train_emails)
        os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)
        clf.save_to_file(model_path)

    dss = DecisionSupportSystem(classifier=clf)

    while True:
        print_banner()
        print("MAIN MENU:")
        print("  [1] Analyze Single Email (Presets or Custom Raw Text)")
        print("  [2] Run Month 2 Benchmark & 5-Fold Cross-Validation")
        print("  [3] Run Large-Scale Evaluation on Kaggle Dataset")
        print("  [4] Launch Cyber-Defense Web Application Dashboard")
        print("  [0] Exit")

        choice = input("\nEnter selection (0-4): ").strip()
        if choice == "1":
            analyze_email_interactive(dss)
        elif choice == "2":
            run_benchmark_and_evaluation()
        elif choice == "3":
            run_kaggle_evaluation()
        elif choice == "4":
            print("\n[+] Launching Web Dashboard server...")
            os.system(f"python3 {os.path.join(BASE_DIR, 'run_server.py')}")
        elif choice == "0":
            print("\nGoodbye!")
            break
        else:
            print("[!] Invalid option. Please select 0 to 4.")


if __name__ == "__main__":
    main()
