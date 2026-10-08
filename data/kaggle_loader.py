"""
Kaggle Dataset Loader
Streams and processes the real-world Phishing_Email.csv dataset for high-volume evaluation.
"""

import csv
import os
import random
from typing import List, Dict, Any, Optional
from src.preprocessing.feature_extractor import FeatureExtractor


class KaggleDatasetLoader:
    """Loads and preprocesses real-world Kaggle phishing emails."""

    SEARCH_PATHS = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../Phishing_Email.csv")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../Phishing_Email.csv")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "Phishing_Email.csv"))
    ]

    def __init__(self, csv_path: Optional[str] = None):
        self.csv_path = csv_path
        if not self.csv_path:
            for p in self.SEARCH_PATHS:
                if os.path.exists(p):
                    self.csv_path = p
                    break
            if not self.csv_path:
                self.csv_path = self.SEARCH_PATHS[0]
        self.feature_extractor = FeatureExtractor()

    def exists(self) -> bool:
        return os.path.exists(self.csv_path)

    def load_samples(
        self,
        max_samples: int = 2000,
        balance: bool = True,
        seed: int = 42
    ) -> List[Dict[str, Any]]:
        """
        Loads samples from Phishing_Email.csv with feature extraction.
        Returns list of dicts with: id, raw, label (1=phishing, 0=safe), features, evidence.
        """
        if not self.exists():
            raise FileNotFoundError(f"Kaggle dataset not found at {self.csv_path}")

        phish_samples = []
        safe_samples = []
        target_per_class = max_samples // 2 if balance else max_samples

        with open(self.csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader, None)

            for idx, row in enumerate(reader):
                if len(row) < 3:
                    continue
                raw_text = row[1].strip()
                email_type = row[2].strip()

                if not raw_text:
                    continue

                if "phish" in email_type.lower():
                    if len(phish_samples) < target_per_class:
                        phish_samples.append({
                            "id": f"kaggle_phish_{idx}",
                            "raw": raw_text,
                            "label": 1,
                            "type": "Phishing Email"
                        })
                elif "safe" in email_type.lower():
                    if len(safe_samples) < target_per_class:
                        safe_samples.append({
                            "id": f"kaggle_safe_{idx}",
                            "raw": raw_text,
                            "label": 0,
                            "type": "Safe Email"
                        })

                if len(phish_samples) >= target_per_class and len(safe_samples) >= target_per_class:
                    break

        all_samples = phish_samples + safe_samples
        rng = random.Random(seed)
        rng.shuffle(all_samples)

        # Extract features for all loaded samples
        for s in all_samples:
            feats, ev = self.feature_extractor.extract_features(s["raw"])
            s["features"] = feats
            s["evidence"] = ev

        return all_samples
