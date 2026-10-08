"""
Naive Bayes Classifier (Unit/Module 4: Statistical Reasoning & Uncertain Knowledge)
Computes posterior probability P(phishing | features) using Bayes' Theorem with Laplace smoothing in log-space.
"""

import math
import json
from typing import Dict, List, Any, Tuple


class NaiveBayesClassifier:
    """
    Binary Naive Bayes classifier over binary indicator features.
    Computes P(Class | Features) using log likelihoods and Laplace smoothing (k=1).
    """

    FEATURE_NAMES = [
        "reply_to_mismatch",
        "ip_in_url",
        "suspicious_tld",
        "urgency_words",
        "executable_attachment",
        "no_https",
        "long_url"
    ]

    def __init__(self, alpha: float = 1.0, threshold: float = 0.5):
        self.alpha = alpha  # Laplace smoothing parameter
        self.threshold = threshold
        self.classes = [0, 1]  # 0: Legitimate / Safe, 1: Phishing
        self.class_counts = {0: 0, 1: 0}
        self.total_samples = 0
        self.feature_counts = {
            c: {feat: 0 for feat in self.FEATURE_NAMES}
            for c in self.classes
        }
        self.priors = {0: 0.5, 1: 0.5}
        self.likelihoods = {
            c: {feat: 0.5 for feat in self.FEATURE_NAMES}
            for c in self.classes
        }
        self.is_trained = False

    def train(self, samples: List[Dict[str, Any]]) -> 'NaiveBayesClassifier':
        """
        Trains model on a list of samples.
        Each sample must have 'features' (dict or vector) and 'label' (1 for Phishing, 0 for Legitimate).
        """
        self.class_counts = {0: 0, 1: 0}
        self.feature_counts = {
            c: {feat: 0 for feat in self.FEATURE_NAMES}
            for c in self.classes
        }
        self.total_samples = len(samples)

        if self.total_samples == 0:
            raise ValueError("Training set cannot be empty.")

        for sample in samples:
            label = int(sample["label"])
            self.class_counts[label] += 1
            feat_dict = sample["features"]

            for feat in self.FEATURE_NAMES:
                val = feat_dict.get(feat, 0)
                if val == 1:
                    self.feature_counts[label][feat] += 1

        # Calculate priors: P(Class)
        for c in self.classes:
            self.priors[c] = self.class_counts[c] / self.total_samples

        # Calculate likelihoods: P(feat=1 | Class) with Laplace smoothing
        for c in self.classes:
            c_count = self.class_counts[c]
            for feat in self.FEATURE_NAMES:
                # With Laplace smoothing (k=alpha, num_values=2):
                prob_1 = (self.feature_counts[c][feat] + self.alpha) / (c_count + 2 * self.alpha)
                self.likelihoods[c][feat] = prob_1

        self.is_trained = True
        return self

    def predict_proba(self, features: Dict[str, int]) -> Dict[str, float]:
        """
        Calculates posterior probabilities P(Phishing | features) and P(Safe | features)
        using Bayes' theorem in log space to prevent numerical underflow.
        """
        if not self.is_trained:
            # Return baseline prior if not trained
            return {"phishing": 0.5, "safe": 0.5}

        log_posteriors = {}

        for c in self.classes:
            # log P(C)
            prior = self.priors[c]
            log_prob = math.log(prior if prior > 0 else 1e-9)

            # log P(features | C) = sum log P(f_i | C)
            for feat in self.FEATURE_NAMES:
                val = features.get(feat, 0)
                p1 = self.likelihoods[c][feat]
                p = p1 if val == 1 else (1.0 - p1)
                p = max(1e-9, min(1.0 - 1e-9, p))
                log_prob += math.log(p)

            log_posteriors[c] = log_prob

        # Softmax / Log-sum-exp normalization
        max_log = max(log_posteriors.values())
        exp_0 = math.exp(log_posteriors[0] - max_log)
        exp_1 = math.exp(log_posteriors[1] - max_log)
        total_exp = exp_0 + exp_1

        prob_phishing = exp_1 / total_exp
        prob_safe = exp_0 / total_exp

        return {
            "phishing": round(prob_phishing, 4),
            "safe": round(prob_safe, 4)
        }

    def predict(self, features: Dict[str, int]) -> Dict[str, Any]:
        """
        Returns classification label, verdict, and posterior probability.
        """
        probs = self.predict_proba(features)
        prob_phishing = probs["phishing"]
        predicted_label = 1 if prob_phishing >= self.threshold else 0
        verdict = "Phishing" if predicted_label == 1 else "Safe"

        return {
            "predicted_label": predicted_label,
            "verdict": verdict,
            "probability_phishing": prob_phishing,
            "probability_safe": probs["safe"],
            "threshold": self.threshold
        }

    def get_feature_importance(self) -> List[Dict[str, Any]]:
        """
        Computes feature log-odds ratios P(feat=1|Phishing) / P(feat=1|Safe)
        to identify the strongest indicators of phishing.
        """
        importance = []
        for feat in self.FEATURE_NAMES:
            p_phish = self.likelihoods[1][feat]
            p_safe = self.likelihoods[0][feat]
            log_ratio = math.log((p_phish + 1e-6) / (p_safe + 1e-6))
            importance.append({
                "feature": feat,
                "prob_given_phishing": round(p_phish, 4),
                "prob_given_safe": round(p_safe, 4),
                "log_odds_ratio": round(log_ratio, 4)
            })

        importance.sort(key=lambda x: x["log_odds_ratio"], reverse=True)
        return importance

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alpha": self.alpha,
            "threshold": self.threshold,
            "class_counts": self.class_counts,
            "total_samples": self.total_samples,
            "priors": self.priors,
            "likelihoods": self.likelihoods,
            "is_trained": self.is_trained
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NaiveBayesClassifier':
        clf = cls(alpha=data.get("alpha", 1.0), threshold=data.get("threshold", 0.5))
        clf.class_counts = {int(k): v for k, v in data.get("class_counts", {}).items()}
        clf.total_samples = data.get("total_samples", 0)
        clf.priors = {int(k): v for k, v in data.get("priors", {}).items()}
        clf.likelihoods = {int(k): v for k, v in data.get("likelihoods", {}).items()}
        clf.is_trained = data.get("is_trained", False)
        return clf

    def save_to_file(self, file_path: str) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, file_path: str) -> 'NaiveBayesClassifier':
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
