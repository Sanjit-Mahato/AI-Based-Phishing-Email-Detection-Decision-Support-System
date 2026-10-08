"""
Adversarial Evasion Tactics Module (Unit/Module 2: Adversarial Search & Game Playing)
Models concrete cyber-attacker perturbation actions aimed at bypassing phishing detectors.
"""

from typing import Dict, List, Any


class AdversarialTactic:
    """Represents an attacker evasion action and its effect on features."""

    def __init__(self, tactic_id: str, name: str, targets: List[str], cost: float, description: str):
        self.tactic_id = tactic_id
        self.name = name
        self.targets = targets  # feature names suppressed or modified
        self.cost = cost        # attacker execution cost / effort (0.0 to 1.0)
        self.description = description

    def apply(self, features: Dict[str, int]) -> Dict[str, int]:
        """Applies mutation to suppress targeted indicator features."""
        mutated = features.copy()
        for target in self.targets:
            if target in mutated and mutated[target] == 1:
                mutated[target] = 0
        return mutated


class EvasionTacticsRegistry:
    """Catalog of realistic cyber-attacker evasion tactics."""

    TACTICS = [
        AdversarialTactic(
            tactic_id="T1_HOMOGLYPH_URL",
            name="URL Typosquatting & Homoglyphs",
            targets=["ip_in_url", "suspicious_tld"],
            cost=0.35,
            description="Replaces raw IP or spam TLD with typosquatted lookalike domain (e.g. 'paypa1.com' or punycode)."
        ),
        AdversarialTactic(
            tactic_id="T2_SSL_MASQUERADE",
            name="HTTPS Certificate Masquerade",
            targets=["no_https"],
            cost=0.15,
            description="Procures a free SSL certificate (Let's Encrypt) on malicious host to defeat HTTP-only filters."
        ),
        AdversarialTactic(
            tactic_id="T3_URGENCY_DILUTION",
            name="Tone Modulation & Urgency Dilution",
            targets=["urgency_words"],
            cost=0.25,
            description="Replaces crude panic terms with subtle corporate compliance phrasing ('Annual Policy Review')."
        ),
        AdversarialTactic(
            tactic_id="T4_ATTACHMENT_CLOAKING",
            name="Payload Cloaking & Cloud Storage",
            targets=["executable_attachment"],
            cost=0.40,
            description="Hosts executable payload inside password-protected ISO/ZIP or shared Google Drive/OneDrive link."
        ),
        AdversarialTactic(
            tactic_id="T5_REPLY_ALIGNMENT",
            name="Lookalike Header Domain Alignment",
            targets=["reply_to_mismatch"],
            cost=0.30,
            description="Registers matching lookalike domain for Reply-To to bypass naive mismatch checks."
        ),
        AdversarialTactic(
            tactic_id="T6_URL_SHORTENING",
            name="URL Shortening & Multi-Hop Redirect",
            targets=["long_url", "ip_in_url", "suspicious_tld"],
            cost=0.20,
            description="Chains bit.ly / tinyurl redirects to compress long URLs and conceal destination TLD."
        )
    ]

    @classmethod
    def get_all_tactics(cls) -> List[AdversarialTactic]:
        return list(cls.TACTICS)
