"""
Feature Extractor Module
Extracts 7 core binary indicators matching Unit/Module 1 and Month 2 specifications,
along with detailed evidence context for explainable decision support.
"""

import re
from typing import Dict, List, Any, Tuple
from .email_parser import EmailParser


class FeatureExtractor:
    """Extracts 7 binary indicators and explainability metadata from parsed emails."""

    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.club', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf',
        '.gq', '.work', '.click', '.buzz', '.loan', '.support', '.live',
        '.cam', '.icu', '.best', '.monster', '.rest', '.bar'
    }

    URGENCY_KEYWORDS = [
        r'\bimmediat(?:e|ely)\b',
        r'\burgent(?:ly)?\b',
        r'\bverify (?:your )?(?:account|identity|details|wallet|bank)\b',
        r'\baccount (?:has been |is )?(?:suspended|locked|terminated|blocked|compromised|limited)\b',
        r'\bunauthorized (?:access|activity|transaction|login)\b',
        r'\bact now\b',
        r'\b24 hours?\b',
        r'\bwithin \d+ (?:hours?|mins?|minutes?|days?)\b',
        r'\bsecurity alert\b',
        r'\bpassword (?:expires|reset|expired)\b',
        r'\bfinal notice\b',
        r'\bupdate (?:your )?(?:billing|payment|security|information)\b',
        r'\baction required\b',
        r'\bclick here to (?:verify|confirm|restore|reactivate)\b'
    ]

    EXECUTABLE_EXTENSIONS = {
        '.exe', '.scr', '.bat', '.vbs', '.js', '.cmd', '.iso', '.hta',
        '.wsf', '.pif', '.dll', '.jar', '.com', '.msi', '.ps1'
    }

    IP_URL_REGEX = re.compile(
        r'https?://(?:(?:\d{1,3}\.){3}\d{1,3}|0x[0-9a-fA-F]+|\d{8,11})(?::\d+)?(?:/|$)',
        re.IGNORECASE
    )

    FEATURE_NAMES = [
        "reply_to_mismatch",
        "ip_in_url",
        "suspicious_tld",
        "urgency_words",
        "executable_attachment",
        "no_https",
        "long_url"
    ]

    def __init__(self):
        self.urgency_regex = re.compile("|".join(self.URGENCY_KEYWORDS), re.IGNORECASE)

    def extract_features(self, email_input: Any) -> Tuple[Dict[str, int], Dict[str, Any]]:
        """
        Extracts 7 binary features (0 or 1) and evidence dictionary.
        email_input can be a raw string or an already parsed dictionary.
        """
        if isinstance(email_input, str):
            parsed = EmailParser.parse_raw_text(email_input)
        elif isinstance(email_input, dict):
            if "raw" in email_input and "urls" not in email_input:
                parsed = EmailParser.parse_raw_text(email_input.get("raw", ""))
            else:
                parsed = email_input
        else:
            raise ValueError("Input must be a string or dictionary")

        sender = parsed.get("sender", "")
        reply_to = parsed.get("reply_to", "")
        subject = parsed.get("subject", "")
        body = parsed.get("body", "")
        urls: List[str] = parsed.get("urls", [])
        attachments: List[str] = parsed.get("attachments", [])

        full_text = f"{subject}\n{body}"

        # 1. reply_to_mismatch
        sender_domain = EmailParser.extract_domain(sender) if sender else ""
        reply_domain = EmailParser.extract_domain(reply_to) if reply_to else ""
        
        reply_to_mismatch = 0
        mismatch_evidence = ""
        if reply_to and sender:
            if sender_domain != reply_domain:
                reply_to_mismatch = 1
                mismatch_evidence = f"Sender domain '{sender_domain}' != Reply-To '{reply_domain}'"
        elif "reply-to" in full_text.lower():
            # Check for embedded spoofing cues in text
            match = re.search(r'reply-to:\s*([^\s\n]+)', full_text, re.IGNORECASE)
            if match and sender_domain and sender_domain not in match.group(1).lower():
                reply_to_mismatch = 1
                mismatch_evidence = f"Sender '{sender}' differs from embedded Reply-To '{match.group(1)}'"

        # 2. ip_in_url
        ip_in_url = 0
        ip_evidence = []
        for u in urls:
            if self.IP_URL_REGEX.search(u):
                ip_in_url = 1
                ip_evidence.append(u)

        # 3. suspicious_tld
        suspicious_tld = 0
        tld_evidence = []
        domains_to_check = [EmailParser.extract_domain(u) for u in urls]
        if sender_domain:
            domains_to_check.append(sender_domain)
        if reply_domain:
            domains_to_check.append(reply_domain)

        for domain in domains_to_check:
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious_tld = 1
                    tld_evidence.append(f"{domain} (uses {tld})")
                    break

        # 4. urgency_words
        urgency_matches = self.urgency_regex.findall(full_text)
        urgency_words = 1 if len(urgency_matches) > 0 else 0

        # 5. executable_attachment
        executable_attachment = 0
        attachment_evidence = []
        # Check attachments header or mentions in text
        for att in attachments:
            att_lower = att.lower().strip()
            for ext in self.EXECUTABLE_EXTENSIONS:
                if att_lower.endswith(ext):
                    executable_attachment = 1
                    attachment_evidence.append(att)
                    break
        if not executable_attachment:
            # Check text for mentions like "invoice.exe", "payment.scr", "order.iso"
            for ext in self.EXECUTABLE_EXTENSIONS:
                found = re.findall(rf'[\w-]+\{ext}\b', full_text, re.IGNORECASE)
                if found:
                    executable_attachment = 1
                    attachment_evidence.extend(found)
                    break

        # 6. no_https
        no_https = 0
        http_evidence = []
        for u in urls:
            if u.lower().startswith("http://"):
                no_https = 1
                http_evidence.append(u)

        # 7. long_url
        long_url = 0
        long_url_evidence = []
        for u in urls:
            if len(u) > 75:
                long_url = 1
                long_url_evidence.append(f"{u[:50]}... ({len(u)} chars)")

        features = {
            "reply_to_mismatch": reply_to_mismatch,
            "ip_in_url": ip_in_url,
            "suspicious_tld": suspicious_tld,
            "urgency_words": urgency_words,
            "executable_attachment": executable_attachment,
            "no_https": no_https,
            "long_url": long_url
        }

        evidence = {
            "parsed": {
                "sender": sender,
                "reply_to": reply_to,
                "subject": subject,
                "url_count": len(urls),
                "attachment_count": len(attachments)
            },
            "reply_to_mismatch": mismatch_evidence,
            "ip_in_url": ip_evidence,
            "suspicious_tld": tld_evidence,
            "urgency_words": list(set([m.lower() for m in urgency_matches])),
            "executable_attachment": attachment_evidence,
            "no_https": http_evidence,
            "long_url": long_url_evidence
        }

        return features, evidence

    def features_to_vector(self, features: Dict[str, int]) -> List[int]:
        """Converts feature dictionary to standard binary feature vector."""
        return [features.get(name, 0) for name in self.FEATURE_NAMES]
