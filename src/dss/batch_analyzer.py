"""
Batch CSV Analyzer Module
Parses and analyzes CSV datasets containing lists of emails, generating comprehensive
threat intelligence reports and exportable security summaries.
"""

import csv
import io
from typing import Dict, List, Any, Optional
from .decision_support import DecisionSupportSystem
from ..preprocessing.email_parser import EmailParser


class BatchCSVAnalyzer:
    """Processes CSV email lists and compiles aggregate threat analytics."""

    TEXT_COLUMN_CANDIDATES = [
        "email text", "email_text", "text", "body", "email", "content", 
        "message", "raw", "email body", "email_body", "mail"
    ]
    SENDER_COLUMN_CANDIDATES = ["sender", "from", "from_email", "sender_email", "sender_address"]
    SUBJECT_COLUMN_CANDIDATES = ["subject", "email_subject", "title", "subject_line"]
    LABEL_COLUMN_CANDIDATES = ["label", "email type", "email_type", "type", "class", "target"]

    def __init__(self, dss: Optional[DecisionSupportSystem] = None):
        self.dss = dss or DecisionSupportSystem()

    def analyze_csv_text(self, csv_content: str, max_rows: int = 1000) -> Dict[str, Any]:
        """
        Parses CSV string, detects columns, analyzes emails, and returns aggregated report.
        """
        f = io.StringIO(csv_content.strip())
        reader = csv.reader(f)

        try:
            headers = next(reader)
        except StopIteration:
            return {"error": "CSV file is empty."}

        # Normalize header strings
        headers_lower = [h.strip().lower() for h in headers]

        # 1. Identify primary text column
        text_col_idx = -1
        for candidate in self.TEXT_COLUMN_CANDIDATES:
            if candidate in headers_lower:
                text_col_idx = headers_lower.index(candidate)
                break

        # Fallback: find longest column in first row or first non-empty text column
        if text_col_idx == -1:
            for idx, h in enumerate(headers_lower):
                if h not in ["id", "", "index", "no", "sr"]:
                    text_col_idx = idx
                    break
            if text_col_idx == -1:
                text_col_idx = 0

        # Optional columns
        sender_col_idx = next((headers_lower.index(c) for c in self.SENDER_COLUMN_CANDIDATES if c in headers_lower), -1)
        subject_col_idx = next((headers_lower.index(c) for c in self.SUBJECT_COLUMN_CANDIDATES if c in headers_lower), -1)
        label_col_idx = next((headers_lower.index(c) for c in self.LABEL_COLUMN_CANDIDATES if c in headers_lower), -1)

        analyzed_items = []
        verdict_counts = {"Phishing": 0, "Suspicious": 0, "Safe": 0}
        indicator_counts = {
            "reply_to_mismatch": 0,
            "ip_in_url": 0,
            "suspicious_tld": 0,
            "urgency_words": 0,
            "executable_attachment": 0,
            "no_https": 0,
            "long_url": 0
        }
        total_risk_sum = 0.0

        for row_idx, row in enumerate(reader):
            if row_idx >= max_rows:
                break
            if not row or len(row) <= text_col_idx:
                continue

            raw_email = row[text_col_idx].strip()
            if not raw_email:
                continue

            # Construct enriched raw email if sender/subject are in separate columns
            constructed_raw = []
            sender_val = row[sender_col_idx].strip() if sender_col_idx != -1 and len(row) > sender_col_idx else ""
            subject_val = row[subject_col_idx].strip() if subject_col_idx != -1 and len(row) > subject_col_idx else ""
            original_label = row[label_col_idx].strip() if label_col_idx != -1 and len(row) > label_col_idx else ""

            if sender_val and not raw_email.lower().startswith("from:"):
                constructed_raw.append(f"From: {sender_val}")
            if subject_val and "subject:" not in raw_email.lower():
                constructed_raw.append(f"Subject: {subject_val}")
            constructed_raw.append(raw_email)

            full_email_text = "\n".join(constructed_raw)

            # Analyze through DSS
            result = self.dss.analyze_email(full_email_text, include_adversarial=False)
            verdict = result["final_verdict"]
            risk = result["risk_index"]

            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            total_risk_sum += risk

            # Track indicator triggers
            features = result.get("features", {})
            active_flags = []
            for feat_name, is_active in features.items():
                if is_active == 1:
                    indicator_counts[feat_name] = indicator_counts.get(feat_name, 0) + 1
                    active_flags.append(feat_name)

            # Extract clean snippet
            parsed = result.get("parsed_email", {})
            sender_display = parsed.get("sender") or sender_val or "N/A"
            subject_display = parsed.get("subject") or subject_val or "(No Subject)"
            body_snippet = (parsed.get("body") or raw_email)[:120].replace('\n', ' ')

            full_body = parsed.get("body") or raw_email
            urls = parsed.get("urls") or []
            attachments = parsed.get("attachments") or []
            reply_to = parsed.get("reply_to") or ""
            top_rec = result["recommendations"][0]["action"] if result.get("recommendations") else "N/A"

            analyzed_items.append({
                "row_id": row_idx + 1,
                "sender": sender_display,
                "subject": subject_display,
                "snippet": body_snippet,
                "full_email": full_email_text,
                "body": full_body,
                "reply_to": reply_to,
                "urls": urls,
                "attachments": attachments,
                "evidence": result.get("evidence", {}),
                "recommendations": result.get("recommendations", []),
                "verdict": verdict,
                "risk_score": risk,
                "confidence": result["confidence_percentage"],
                "active_flags": active_flags,
                "flags_count": len(active_flags),
                "primary_reason": result.get("summary_explanation", ""),
                "action": top_rec,
                "original_label": original_label
            })

        total_scanned = len(analyzed_items)
        if total_scanned == 0:
            return {"error": "No valid email rows found in CSV."}

        avg_risk = round(total_risk_sum / total_scanned, 1)

        # Indicator prevalence percentages
        indicator_percentages = {
            k: {
                "count": v,
                "percentage": round((v / total_scanned) * 100, 1)
            }
            for k, v in indicator_counts.items()
        }

        summary_data = {
            "total_scanned": total_scanned,
            "total_emails": total_scanned,
            "phishing_count": verdict_counts["Phishing"],
            "phishing_percentage": round((verdict_counts["Phishing"] / total_scanned) * 100, 1),
            "suspicious_count": verdict_counts["Suspicious"],
            "suspicious_percentage": round((verdict_counts["Suspicious"] / total_scanned) * 100, 1),
            "safe_count": verdict_counts["Safe"],
            "safe_percentage": round((verdict_counts["Safe"] / total_scanned) * 100, 1),
            "average_risk_score": avg_risk,
            "indicator_prevalence": indicator_percentages
        }

        csv_export = BatchCSVAnalyzer.generate_report_csv(analyzed_items)

        return {
            "summary": summary_data,
            "indicator_prevalence": indicator_percentages,
            "results": analyzed_items,
            "csv_export": csv_export
        }

    @staticmethod
    def generate_report_csv(analyzed_items: List[Dict[str, Any]]) -> str:
        """Generates an exportable CSV string with complete analysis results."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Row ID", "Sender", "Subject", "Verdict", "Risk Score (0-100)",
            "Confidence %", "Triggered Flags Count", "Triggered Indicators", 
            "Primary Decision Reason", "Recommended Security Action", "Original Label"
        ])

        for item in analyzed_items:
            writer.writerow([
                item["row_id"],
                item["sender"],
                item["subject"],
                item["verdict"],
                item["risk_score"],
                item["confidence"],
                item["flags_count"],
                "; ".join(item["active_flags"]),
                item["primary_reason"],
                item["action"],
                item.get("original_label", "")
            ])

        return output.getvalue()

    generate_csv_report = generate_report_csv
    analyze_csv_content = analyze_csv_text
