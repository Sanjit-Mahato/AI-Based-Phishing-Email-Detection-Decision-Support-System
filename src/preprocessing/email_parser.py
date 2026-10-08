"""
Email Parser Module
Extracts headers, URLs, attachments, and text body from raw emails or structured dictionaries.
"""

import re
from typing import Dict, List, Any


class EmailParser:
    """Parses raw email text strings or structured input dictionaries."""

    # Regex patterns
    URL_PATTERN = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\']*)?'
        r'|https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s"\']*)?'
        r'|www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s"\']*)?',
        re.IGNORECASE
    )
    
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        re.IGNORECASE
    )

    SENDER_HEADER = re.compile(r'^(?:From|Sender):\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    REPLY_TO_HEADER = re.compile(r'^Reply-To:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    SUBJECT_HEADER = re.compile(r'^Subject:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    ATTACHMENT_HEADER = re.compile(r'^(?:Attachment|Attachments|Attached-File):\s*(.+)$', re.IGNORECASE | re.MULTILINE)

    @classmethod
    def parse_raw_text(cls, raw_text: str) -> Dict[str, Any]:
        """
        Parses raw email string containing headers and body.
        If structured headers (From:, Reply-To:) are absent, treats the entire input as body
        and scans for embedded emails, URLs, and cues.
        """
        raw_text = raw_text.strip()
        sender = ""
        reply_to = ""
        subject = ""
        attachments: List[str] = []

        sender_match = cls.SENDER_HEADER.search(raw_text)
        if sender_match:
            sender = sender_match.group(1).strip()

        reply_match = cls.REPLY_TO_HEADER.search(raw_text)
        if reply_match:
            reply_to = reply_match.group(1).strip()

        subject_match = cls.SUBJECT_HEADER.search(raw_text)
        if subject_match:
            subject = subject_match.group(1).strip()

        att_matches = cls.ATTACHMENT_HEADER.findall(raw_text)
        for att in att_matches:
            for item in att.split(','):
                if item.strip():
                    attachments.append(item.strip())

        # Extract URLs
        urls = cls.URL_PATTERN.findall(raw_text)

        # Body: remove known header lines if present
        body_lines = []
        for line in raw_text.splitlines():
            if (cls.SENDER_HEADER.match(line) or 
                cls.REPLY_TO_HEADER.match(line) or 
                cls.SUBJECT_HEADER.match(line) or 
                cls.ATTACHMENT_HEADER.match(line)):
                continue
            body_lines.append(line)
        body = "\n".join(body_lines).strip()
        if not body:
            body = raw_text

        # If sender is missing, look for email address patterns
        if not sender:
            emails_found = cls.EMAIL_PATTERN.findall(raw_text)
            if emails_found:
                sender = emails_found[0]

        return {
            "sender": sender,
            "reply_to": reply_to,
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachments": attachments,
            "raw": raw_text
        }

    @classmethod
    def extract_domain(cls, email_or_url: str) -> str:
        """Extracts domain from an email address or URL."""
        if "@" in email_or_url:
            parts = email_or_url.split("@")
            domain_part = parts[-1].strip("<> \t\r\n").lower()
            return domain_part
        # URL domain extraction
        match = re.search(r'https?://([^/:\s]+)', email_or_url, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return email_or_url.strip().lower()
