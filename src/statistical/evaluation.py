"""
Evaluation Metrics & Cross-Validation (Unit/Module 4: Statistical Reasoning & Evaluation)
Computes confusion matrix, accuracy, precision, recall, F1, and k-fold cross validation.
"""

import random
from typing import List, Dict, Any, Callable
from .naive_bayes import NaiveBayesClassifier


class ModelEvaluator:
    """Computes statistical evaluation metrics and executes cross-validation."""

    @staticmethod
    def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
        """
        Computes TP, FP, TN, FN, Accuracy, Precision, Recall, and F1.
        y_true and y_pred contain 1 (positive/phishing) and 0 (negative/safe).
        """
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

        total = len(y_true)
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "total_samples": total
        }

    @staticmethod
    def cross_validate_naive_bayes(
        samples: List[Dict[str, Any]],
        k_folds: int = 5,
        seed: int = 42,
        alpha: float = 1.0,
        threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Performs stratified or randomized k-fold cross-validation on Naive Bayes.
        """
        rng = random.Random(seed)
        shuffled = list(samples)
        rng.shuffle(shuffled)

        fold_size = len(shuffled) // k_folds
        fold_accuracies = []
        fold_metrics = []

        for i in range(k_folds):
            test_start = i * fold_size
            test_end = (i + 1) * fold_size if i < k_folds - 1 else len(shuffled)

            test_fold = shuffled[test_start:test_end]
            train_fold = shuffled[:test_start] + shuffled[test_end:]

            clf = NaiveBayesClassifier(alpha=alpha, threshold=threshold)
            clf.train(train_fold)

            y_true = [s["label"] for s in test_fold]
            y_pred = [clf.predict(s["features"])["predicted_label"] for s in test_fold]

            metrics = ModelEvaluator.compute_metrics(y_true, y_pred)
            fold_accuracies.append(metrics["accuracy"])
            fold_metrics.append(metrics)

        mean_acc = sum(fold_accuracies) / len(fold_accuracies)
        variance = sum((acc - mean_acc) ** 2 for acc in fold_accuracies) / len(fold_accuracies)
        std_acc = variance ** 0.5

        return {
            "k_folds": k_folds,
            "fold_accuracies": [round(a, 4) for a in fold_accuracies],
            "mean_accuracy": round(mean_acc, 4),
            "std_accuracy": round(std_acc, 4),
            "fold_metrics": fold_metrics
        }
