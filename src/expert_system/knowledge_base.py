"""
Knowledge Base Module (Unit/Module 3: Knowledge Representation & Reasoning)
Defines Horn clauses, propositional facts, and semantic frame representation for the Expert System.
"""

from typing import List, Dict, Set, Any


class HornRule:
    """Represents a definite Horn clause: P1 AND P2 AND ... AND Pk -> Conclusion"""

    def __init__(self, rule_id: str, premises: List[str], conclusion: str, description: str):
        self.rule_id = rule_id
        self.premises = premises
        self.conclusion = conclusion
        self.description = description

    def is_satisfied(self, facts: Set[str]) -> bool:
        """Returns True if all premises are present in the facts set."""
        return all(premise in facts for premise in self.premises)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "premises": self.premises,
            "conclusion": self.conclusion,
            "description": self.description
        }


class KnowledgeBase:
    """
    Standard 13 Horn Clause rules as designed in Month 2 Progress Report,
    covering spoofed sender, bad link, dangerous file, and urgency combinations.
    """

    @classmethod
    def get_default_rules(cls) -> List[HornRule]:
        return [
            # Intermediate Horn clauses
            HornRule(
                "R1",
                ["reply_to_mismatch"],
                "spoofed_sender",
                "If reply-to header mismatches sender domain, sender is spoofed."
            ),
            HornRule(
                "R2",
                ["ip_in_url"],
                "bad_link",
                "If URL contains an IP address rather than hostname, it is a bad link."
            ),
            HornRule(
                "R3",
                ["suspicious_tld"],
                "bad_link",
                "If URL uses a known high-risk TLD, it is a bad link."
            ),
            HornRule(
                "R4",
                ["long_url", "no_https"],
                "deceptive_link",
                "If URL is abnormally long and lacks HTTPS, it is deceptive."
            ),
            HornRule(
                "R5",
                ["deceptive_link"],
                "bad_link",
                "A deceptive link is classified as a bad link."
            ),
            HornRule(
                "R6",
                ["executable_attachment"],
                "dangerous_file",
                "If email has an executable attachment, it contains a dangerous file."
            ),

            # Phishing conclusions (Module 3 High Severity)
            HornRule(
                "R7",
                ["spoofed_sender", "bad_link"],
                "phishing",
                "Spoofed sender combined with bad link proves phishing."
            ),
            HornRule(
                "R8",
                ["spoofed_sender", "dangerous_file"],
                "phishing",
                "Spoofed sender combined with dangerous attachment proves phishing."
            ),
            HornRule(
                "R9",
                ["bad_link", "dangerous_file"],
                "phishing",
                "Bad link combined with dangerous attachment proves phishing."
            ),
            HornRule(
                "R10",
                ["bad_link", "urgency_words"],
                "phishing",
                "Bad link combined with psychological urgency triggers proves phishing."
            ),
            HornRule(
                "R11",
                ["dangerous_file", "urgency_words"],
                "phishing",
                "Dangerous attachment accompanied by urgent coercion proves phishing."
            ),

            # Suspicious conclusions (Moderate Severity)
            HornRule(
                "R12",
                ["spoofed_sender", "urgency_words"],
                "suspicious",
                "Spoofed sender with urgency words indicates suspicious activity."
            ),
            HornRule(
                "R13",
                ["bad_link"],
                "suspicious",
                "Presence of any bad link raises a suspicious alert."
            )
        ]

    @classmethod
    def create_email_frame(cls, parsed_data: Dict[str, Any], features: Dict[str, int]) -> Dict[str, Any]:
        """
        Creates a Semantic Net / Frame representation (Unit 3) of the email entity.
        Frames represent concepts with slots and slot values.
        """
        return {
            "entity": "EmailMessage",
            "slots": {
                "sender": parsed_data.get("sender", "unknown"),
                "reply_to": parsed_data.get("reply_to", "none"),
                "subject": parsed_data.get("subject", ""),
                "has_attachment": bool(features.get("executable_attachment", 0)),
                "has_bad_link": bool(features.get("ip_in_url", 0) or features.get("suspicious_tld", 0)),
                "has_urgency": bool(features.get("urgency_words", 0)),
                "ssl_secured": not bool(features.get("no_https", 0)),
                "features_active": [k for k, v in features.items() if v == 1]
            }
        }
