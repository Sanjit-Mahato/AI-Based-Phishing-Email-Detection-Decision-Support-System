"""
Unit Test Suite for Batch CSV Analyzer
Tests bulk email scanning, auto column mapping, threat reporting, and CSV export.
"""

import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.dss.batch_analyzer import BatchCSVAnalyzer


class TestBatchCSVAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = BatchCSVAnalyzer()
        self.sample_csv_text = (
            "id,sender,subject,body\n"
            "1,security@paypal-update.top,Urgent Security Alert,Please verify immediately http://192.168.1.5/login\n"
            "2,newsletter@medium.com,Weekly Digest,Here are the top stories for this week https://medium.com/story\n"
        )

    def test_analyze_csv_text_custom(self):
        result = self.analyzer.analyze_csv_text(self.sample_csv_text)
        self.assertIn("summary", result)
        self.assertIn("results", result)
        self.assertEqual(result["summary"]["total_emails"], 2)
        self.assertGreaterEqual(result["summary"]["phishing_count"], 1)
        self.assertGreaterEqual(result["summary"]["safe_count"], 1)

    def test_sample_file_analysis(self):
        sample_path = os.path.join(BASE_DIR, "data", "sample_email_list.csv")
        self.assertTrue(os.path.exists(sample_path), "sample_email_list.csv must exist")

        with open(sample_path, "r", encoding="utf-8") as f:
            csv_text = f.read()

        result = self.analyzer.analyze_csv_text(csv_text)
        summary = result["summary"]
        self.assertEqual(summary["total_emails"], 15)
        self.assertIn("indicator_prevalence", summary)
        self.assertGreater(len(result["results"]), 0)
        item0 = result["results"][0]
        self.assertIn("full_email", item0)
        self.assertIn("body", item0)
        self.assertIn("urls", item0)
        self.assertIn("attachments", item0)

    def test_generate_csv_report(self):
        result = self.analyzer.analyze_csv_text(self.sample_csv_text)
        csv_report = self.analyzer.generate_csv_report(result["results"])
        self.assertIn("Verdict", csv_report)
        self.assertIn("Recommended Security Action", csv_report)
        self.assertIn("paypal-update.top", csv_report)


    def test_tabular_phishing_dataset(self):
        parent_dir = os.path.dirname(BASE_DIR)
        tabular_path = os.path.join(parent_dir, "email_phishing_data.csv")
        if not os.path.exists(tabular_path):
            tabular_path = os.path.join(BASE_DIR, "email_phishing_data.csv")

        self.assertTrue(os.path.exists(tabular_path), "email_phishing_data.csv must exist in workspace")

        with open(tabular_path, "r", encoding="utf-8") as f:
            csv_text = f.read(2 * 1024 * 1024)  # read top chunk with headers

        result = self.analyzer.analyze_csv_text(csv_text, max_rows=50)
        self.assertIn("summary", result)
        self.assertIn("results", result)
        summary = result["summary"]
        self.assertGreater(summary["total_emails"], 0)
        self.assertIn("phishing_count", summary)
        self.assertIn("safe_count", summary)
        self.assertIn("indicator_prevalence", summary)
        self.assertEqual(len(summary["indicator_prevalence"]), 7)

        # Check item telemetry
        item0 = result["results"][0]
        self.assertTrue(len(item0["sender"]) > 0)
        self.assertTrue(len(item0["subject"]) > 0)
        self.assertTrue(len(item0["snippet"]) > 0)
        self.assertIn("[Data Metrics]", item0["snippet"])
        self.assertIn("DATASET EMAIL FEATURE TELEMETRY", item0["raw_content"])


if __name__ == "__main__":
    unittest.main()
