"""
REST API and Web Dashboard Server
Runs an HTTP server delivering the Cyber-Defense Web Application and REST endpoints.
Uses Python standard library (http.server) for 100% dependency-free execution.
"""

import os
import sys
import json
import math
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.preprocessing.feature_extractor import FeatureExtractor
from src.statistical.naive_bayes import NaiveBayesClassifier
from src.statistical.evaluation import ModelEvaluator
from src.dss.decision_support import DecisionSupportSystem
from src.adversarial.minimax_engine import AdversarialSearchEngine
from src.expert_system.knowledge_base import KnowledgeBase
from data.benchmark_dataset import generate_benchmark_emails
from data.kaggle_loader import KaggleDatasetLoader

WEB_DIR = os.path.join(BASE_DIR, "web")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handles requests in separate threads for responsiveness."""
    daemon_threads = True


class AppRequestHandler(BaseHTTPRequestHandler):
    # Shared model and engine instances
    dss = None
    classifier = None

    @classmethod
    def initialize_system(cls):
        model_path = os.path.join(BASE_DIR, "models", "trained_naive_bayes.json")
        if os.path.exists(model_path):
            cls.classifier = NaiveBayesClassifier.load_from_file(model_path)
        else:
            train_emails, _ = generate_benchmark_emails()
            extractor = FeatureExtractor()
            for s in train_emails:
                s["features"], _ = extractor.extract_features(s["raw"])
            cls.classifier = NaiveBayesClassifier()
            cls.classifier.train(train_emails)
            os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)
            cls.classifier.save_to_file(model_path)

        cls.dss = DecisionSupportSystem(classifier=cls.classifier)

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.do_GET()

    def send_json(self, data: Any, status_code: int = 200):
        def clean_floats(o):
            if isinstance(o, float):
                if math.isinf(o) or math.isnan(o):
                    return None
                return o
            elif isinstance(o, dict):
                return {k: clean_floats(v) for k, v in o.items()}
            elif isinstance(o, list):
                return [clean_floats(v) for v in o]
            return o

        clean_data = clean_floats(data)
        body = json.dumps(clean_data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url_parts = urlparse(self.path)
        path = url_parts.path

        if path == "/api/presets":
            from cli import PRESET_EMAILS
            self.send_json({"presets": PRESET_EMAILS})
            return

        elif path == "/api/rules":
            rules = [r.to_dict() for r in KnowledgeBase.get_default_rules()]
            self.send_json({"rules": rules})
            return

        elif path == "/api/benchmark":
            train_emails, test_emails = generate_benchmark_emails()
            extractor = FeatureExtractor()
            for s in train_emails:
                s["features"], _ = extractor.extract_features(s["raw"])
            for s in test_emails:
                s["features"], _ = extractor.extract_features(s["raw"])

            from src.heuristics.baseline_scorer import BaselineHeuristicScorer
            from src.expert_system.forward_chaining import ForwardChainingEngine

            heuristic = BaselineHeuristicScorer()
            forward_engine = ForwardChainingEngine()

            y_true = [s["label"] for s in test_emails]
            y_pred_heur = [1 if heuristic.evaluate(s["features"])["is_flagged"] else 0 for s in test_emails]
            y_pred_rule_flag = [1 if forward_engine.infer(s["features"])["is_flagged"] else 0 for s in test_emails]
            y_pred_rule_phish = [1 if forward_engine.infer(s["features"])["verdict"] == "Phishing" else 0 for s in test_emails]
            y_pred_nb = [self.classifier.predict(s["features"])["predicted_label"] for s in test_emails]
            y_pred_dss = [1 if self.dss.analyze_email(s, include_adversarial=False)["is_flagged"] else 0 for s in test_emails]

            cv_res = ModelEvaluator.cross_validate_naive_bayes(train_emails + test_emails, k_folds=5)

            data = {
                "test_sample_count": len(test_emails),
                "phishing_count": sum(y_true),
                "legitimate_count": len(y_true) - sum(y_true),
                "table": [
                    {"detector": "Heuristic baseline", **ModelEvaluator.compute_metrics(y_true, y_pred_heur)},
                    {"detector": "Rule base (flagged)", **ModelEvaluator.compute_metrics(y_true, y_pred_rule_flag)},
                    {"detector": "Rule base (Phishing only)", **ModelEvaluator.compute_metrics(y_true, y_pred_rule_phish)},
                    {"detector": "Naive Bayes (>= 0.5)", **ModelEvaluator.compute_metrics(y_true, y_pred_nb)},
                    {"detector": "Combined (flagged)", **ModelEvaluator.compute_metrics(y_true, y_pred_dss)}
                ],
                "cross_validation": cv_res
            }
            self.send_json(data)
            return

        # Static file serving
        self.serve_static(path)

    def do_POST(self):
        url_parts = urlparse(self.path)
        path = url_parts.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            req_data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req_data = {}

        if path == "/api/analyze":
            email_text = req_data.get("email_text", "")
            include_adv = req_data.get("include_adversarial", True)
            if not email_text:
                self.send_json({"error": "Missing email_text in request"}, 400)
                return

            result = self.dss.analyze_email(email_text, include_adversarial=include_adv)
            self.send_json(result)
            return

        elif path == "/api/adversarial":
            features = req_data.get("features", {})
            adv_engine = AdversarialSearchEngine()
            result = adv_engine.run_adversarial_simulation(features)
            self.send_json(result)
            return

        elif path == "/api/kaggle-eval":
            samples_count = int(req_data.get("samples", 500))
            loader = KaggleDatasetLoader()
            if not loader.exists():
                self.send_json({"error": "Kaggle dataset Phishing_Email.csv not found"}, 404)
                return

            samples = loader.load_samples(max_samples=samples_count)
            split = int(0.7 * len(samples))
            train = samples[:split]
            test = samples[split:]

            clf = NaiveBayesClassifier()
            clf.train(train)

            y_true = [s["label"] for s in test]
            y_pred = [clf.predict(s["features"])["predicted_label"] for s in test]
            metrics = ModelEvaluator.compute_metrics(y_true, y_pred)

            self.send_json({
                "samples_evaluated": len(samples),
                "test_size": len(test),
                "metrics": metrics
            })
            return

        self.send_json({"error": "Endpoint not found"}, 404)

    def serve_static(self, path: str):
        if path in ["/", ""]:
            path = "/index.html"

        safe_path = os.path.normpath(path.lstrip("/"))
        file_path = os.path.join(WEB_DIR, safe_path)

        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            mime_type = mime_type or "application/octet-stream"
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error(500, f"Error reading file: {e}")
        else:
            self.send_error(404, "File not found")

    def log_message(self, format, *args):
        # Quiet standard logging to keep terminal tidy
        pass


def run_server(port: int = 8080):
    AppRequestHandler.initialize_system()
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, AppRequestHandler)
    print("=" * 80)
    print(f"Cyber-Defense Decision Support Web Server running at: http://localhost:{port}")
    print("Serving interactive dashboard and REST endpoints.")
    print("Press Ctrl+C to stop server.")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
