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

    SENDER_HEADER = re.compile(r'^(?:From|Sender|Author)\s*:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    REPLY_TO_HEADER = re.compile(r'^(?:Reply-To|Return-Path)\s*:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    SUBJECT_HEADER = re.compile(r'^(?:Subject|Re|Fwd)\s*:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
    ATTACHMENT_HEADER = re.compile(r'^(?:Attachment|Attachments|Attached-File):\s*(.+)$', re.IGNORECASE | re.MULTILINE)

    @classmethod
    def normalize_spaced_artifacts(cls, text: str) -> str:
        """Fixes spaced URLs, emails, and punctuation common in tokenized datasets."""
        if not text:
            return ""
        # Fix spaced protocol: http : / / -> http://
        t = re.sub(r'https?\s*:\s*/\s*/\s*', lambda m: 'https://' if 'https' in m.group(0).lower() else 'http://', text, flags=re.I)
        # Fix spaced domain dots: www . example . com
        t = re.sub(r'(?<=\w)\s*\.\s*(?=\w)', '.', t)
        # Fix spaced slashes: word / word -> word/word
        t = re.sub(r'(?<=\w)\s*/\s*(?=\w)', '/', t)
        # Fix spaced emails: word @ word -> word@word
        t = re.sub(r'(?<=\w)\s*@\s*(?=\w)', '@', t)
        return t

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
            s_cand = subject_match.group(1).strip()
            if len(s_cand) > 65:
                s_cand = s_cand[:65].rsplit(' ', 1)[0] + '...'
            subject = s_cand

        att_matches = cls.ATTACHMENT_HEADER.findall(raw_text)
        for att in att_matches:
            for item in att.split(','):
                if item.strip():
                    attachments.append(item.strip())

        # Extract URLs from raw and normalized text
        norm_text = cls.normalize_spaced_artifacts(raw_text)
        urls = cls.URL_PATTERN.findall(raw_text)
        norm_urls = cls.URL_PATTERN.findall(norm_text)
        for nu in norm_urls:
            if nu not in urls:
                urls.append(nu)

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

        # If sender is missing, look for embedded headers, emails, forward lines, or signoffs
        if not sender:
            # 1. Embedded From: or Sender:
            emb_from = re.search(r'(?:^|[\r\n]|[\s,;])(?:from|sender|author)\s*:\s*([^;\r\n]{3,60})', raw_text, re.IGNORECASE)
            if emb_from:
                cand = emb_from.group(1).strip().strip('<>"\'')
                cand = re.split(r'\s+(?:on\s+\d|to\s*:|cc\s*:|date\s*:|subject\s*:)', cand, flags=re.I)[0].strip()
                if cand and not cand.lower().startswith("http") and len(cand) >= 3:
                    sender = cand

        if not sender:
            # 2. Email address in raw or normalized text
            emails_found = cls.EMAIL_PATTERN.findall(raw_text) or cls.EMAIL_PATTERN.findall(norm_text)
            if emails_found:
                sender = emails_found[0]

        if not sender:
            # 3. Forwarded by or sent by
            fwd_m = re.search(r'(?:forwarded by|sent by)\s+([a-zA-Z]{2,25}(?:\s+[a-zA-Z]{2,25})?)', raw_text, re.IGNORECASE)
            if fwd_m:
                sender = fwd_m.group(1).title()

        if not sender:
            # 4. Sign-off name
            sign_m = re.search(r'(?:thanks|thank you|regards|sincerely|cheers|best)\s*,\s*([a-zA-Z]{2,25}(?:\s+[a-zA-Z]{2,25})?)', raw_text, re.IGNORECASE)
            if sign_m:
                sender = sign_m.group(1).strip().title()

        # If subject is missing, check for embedded re:, fwd:, subject:, or derive from first sentence
        if not subject:
            emb_subj = re.search(r'(?:^|[\r\n]|[\s,;])(?:subject|re|fwd)\s*:\s*([^;\r\n]{3,80})', raw_text, re.IGNORECASE)
            if emb_subj:
                s = emb_subj.group(1).strip()
                s = re.sub(r'\s+([.,;:/?!])', r'\1', s)
                s = re.sub(r'([.,;:/?!])\s+(?=[0-9])', r'\1', s)
                if len(s) >= 4:
                    clean_s = s[:60].strip()
                    subject = clean_s[:1].upper() + clean_s[1:]

        if not subject and body:
            first_line = body.split('\n')[0].strip()
            first_line = re.sub(r'^(?:url:\s*\S+|date:\s*[^;\n]+|begin forwarded text)\s*', '', first_line, flags=re.I).strip()
            first_line = re.sub(r'\s+([.,;:/?!])', r'\1', first_line)
            first_part = re.split(r'[.!?\n]', first_line)[0].strip()
            if len(first_part) > 50:
                first_part = first_part[:50].rsplit(' ', 1)[0] + '...'
            if first_part and len(first_part) >= 4:
                subject = first_part[:1].upper() + first_part[1:]

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
