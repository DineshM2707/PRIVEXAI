import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    label: str
    regex: re.Pattern[str]
    replacement: str


PATTERNS = {
    "student_name": Pattern(
        "Student name",
        re.compile(
            r"\bstudent\s+name\s*[:=-]\s*[A-Z][A-Za-z'-]{1,30}(?:\s+[A-Z][A-Za-z'-]{1,30}){1,2}",
            re.IGNORECASE,
        ),
        "[STUDENT NAME REDACTED]",
    ),
    "student_id": Pattern(
        "Student ID",
        re.compile(
            r"\b(?:student[\s_-]*(?:id|no|number)|roll[\s_-]*(?:no|number))\s*[:#=-]?\s*[A-Z0-9][A-Z0-9-]{3,19}\b",
            re.IGNORECASE,
        ),
        "[STUDENT ID REDACTED]",
    ),
    "academic_record": Pattern(
        "Academic result",
        re.compile(
            r"\b(?:GPA|CGPA|grade|marks?)\s*[:=]\s*(?:\d{1,3}(?:\.\d{1,2})?\s*%?|[A-F][+-]?)\b",
            re.IGNORECASE,
        ),
        "[ACADEMIC RESULT REDACTED]",
    ),
    "api_secret": Pattern(
        "API secret",
        re.compile(
            r"\b(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b"
        ),
        "[SECRET REDACTED]",
    ),
    "pan_like_id": Pattern(
        "PAN-like ID",
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE),
        "[ID REDACTED]",
    ),
    "account_number": Pattern(
        "Account-like number",
        re.compile(
            r"\b(?:account|acct)(?:\s*(?:no|number|#))?\s*[:=-]?\s*\d{8,16}\b",
            re.IGNORECASE,
        ),
        "[ACCOUNT REDACTED]",
    ),
    "aadhaar_like_id": Pattern(
        "Aadhaar-like ID",
        re.compile(r"(?<!\d)(?:\d{4}[\s-]?){2}\d{4}(?!\d)"),
        "[ID REDACTED]",
    ),
    "email": Pattern(
        "Email address",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        "[EMAIL REDACTED]",
    ),
    "phone": Pattern(
        "Phone number",
        re.compile(r"(?<!\d)(?:\+?91[\s.-]?)?[6-9]\d{9}(?!\d)"),
        "[PHONE REDACTED]",
    ),
}

TEXT_CONTEXT_RULES = (
    (
        "Text suggests a public or external share",
        re.compile(
            r"\b(?:public(?:ly)?|external(?:ly)?)\b[\s\S]{0,35}\b(?:share|send|upload|post|link|recipient|transfer)\b"
            r"|\b(?:share|send|upload|post|forward|transfer)\b[\s\S]{0,35}\b(?:public(?:ly)?|external(?:ly)?)\b",
            re.IGNORECASE,
        ),
        15,
    ),
    (
        "Text suggests sharing a credential",
        re.compile(
            r"\b(?:paste|post|share|send|forward|upload)\b[\s\S]{0,30}\b(?:secret|credential|api key|token|password)\b",
            re.IGNORECASE,
        ),
        10,
    ),
)

GENERIC_ACCOUNT_NUMBER = re.compile(r"(?<!\d)(?:\d[\s-]?){8,17}\d(?!\d)")
FINANCIAL_CONTEXT = re.compile(
    r"\b(?:account|acct|wire|transfer|routing|iban|bank|card|payment|transaction|invoice|deposit|withdrawal)\b",
    re.IGNORECASE,
)

FINDING_EXPLANATIONS = {
    "student_name": ("Student name label followed by a name-shaped value.", 0.98),
    "student_id": ("Student or roll-number label followed by an identifier-shaped value.", 0.98),
    "academic_record": ("Academic metric label followed by a grade or score.", 0.97),
    "api_secret": ("Value matches a recognized API-secret token prefix and shape.", 0.99),
    "pan_like_id": ("Value matches a PAN-like identifier shape; confirm its nearby label.", 0.78),
    "aadhaar_like_id": ("Value matches a 12-digit spaced identifier shape.", 0.84),
    "account_number": ("Value matches a financial account-number shape.", 0.76),
    "email": ("Value matches a standard email-address shape.", 0.99),
    "phone": ("Value matches a 10-digit phone-number shape.", 0.90),
}


def scan_text(text: str) -> tuple[dict[str, list[str]], str]:
    matches: dict[str, list[str]] = {}
    claimed_spans: list[tuple[int, int]] = []
    replacements: list[tuple[int, int, str]] = []
    for category, pattern in PATTERNS.items():
        found = []
        for match in pattern.regex.finditer(text):
            if any(match.start() < end and start < match.end() for start, end in claimed_spans):
                continue
            found.append(match.group(0))
            claimed_spans.append(match.span())
            replacements.append((*match.span(), pattern.replacement))
        if found:
            matches[category] = found[:20]

    account_matches = []
    account_replacement = PATTERNS["account_number"].replacement
    for match in GENERIC_ACCOUNT_NUMBER.finditer(text):
        if any(match.start() < end and start < match.end() for start, end in claimed_spans):
            continue
        nearby_text = text[max(0, match.start() - 48) : min(len(text), match.end() + 48)]
        digit_count = sum(character.isdigit() for character in match.group(0))
        if not FINANCIAL_CONTEXT.search(nearby_text) and digit_count < 14:
            continue
        account_matches.append(match.group(0))
        claimed_spans.append(match.span())
        replacements.append((*match.span(), account_replacement))
    if account_matches:
        matches.setdefault("account_number", []).extend(account_matches[:20])
        matches["account_number"] = matches["account_number"][:20]

    protected = text
    for start, end, replacement in sorted(replacements, reverse=True):
        protected = protected[:start] + replacement + protected[end:]
    return matches, protected[:500]


def explain_findings(
    text: str,
    matches: dict[str, list[str]],
) -> dict[str, dict[str, str | float]]:
    explanations: dict[str, dict[str, str | float]] = {}
    for category, values in matches.items():
        explanation, confidence = FINDING_EXPLANATIONS[category]
        contextual_label = {
            "pan_like_id": re.compile(r"\b(?:pan|tax|identity|government\s+id)\b", re.IGNORECASE),
            "aadhaar_like_id": re.compile(r"\b(?:aadhaar|identity|government\s+id)\b", re.IGNORECASE),
            "account_number": FINANCIAL_CONTEXT,
            "phone": re.compile(r"\b(?:phone|mobile|contact|call)\b", re.IGNORECASE),
        }.get(category)
        if contextual_label is not None and any(
            contextual_label.search(text[max(0, text.find(value) - 48) : text.find(value) + len(value) + 48])
            for value in values
        ):
            confidence = min(0.99, confidence + 0.14)
            explanation += " Nearby financial/contact/identity context strengthens this match."
        elif category in {"pan_like_id", "aadhaar_like_id", "account_number"}:
            explanation += " Pattern match only; verify the surrounding context."
        explanations[category] = {
            "confidence": round(confidence, 2),
            "explanation": explanation,
        }
    return explanations


def contextual_risk_cues(text: str) -> list[dict[str, str | int]]:
    return [
        {"label": label, "points": points}
        for label, pattern, points in TEXT_CONTEXT_RULES
        if pattern.search(text)
    ]


def assess_risk(
    matches: dict[str, list[str]],
    policy_rules: dict[str, dict[str, str | int]],
    destination_authorized: bool,
    context: str,
    text: str,
) -> tuple[int, str, str, list[dict[str, str | int]]]:
    factors: list[dict[str, str | int]] = []
    score = 0
    configured_actions: list[str] = []
    for category, occurrences in matches.items():
        rule = policy_rules.get(category)
        if rule is None:
            continue
        weight = int(rule["weight"])
        contribution = min(weight * min(len(occurrences), 3), 60)
        score += contribution
        configured_actions.append(str(rule["action"]))
        factors.append(
            {
                "label": f"{PATTERNS[category].label} detected · {rule['action']} policy",
                "points": contribution,
            }
        )

    if not destination_authorized:
        score += 25
        factors.append({"label": "Destination is not marked as authorized", "points": 25})
    else:
        score -= 10
        factors.append({"label": "Destination is marked as authorized", "points": -10})

    context_points = {"internal": 0, "partner": 10, "public": 20}[context]
    if context_points:
        score += context_points
        factors.append({"label": f"{context.title()} sharing context", "points": context_points})
    for cue in contextual_risk_cues(text):
        score += int(cue["points"])
        factors.append(cue)

    score = max(0, min(100, score))
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    if score >= 70 or (score >= 40 and "block" in configured_actions):
        decision = "block"
    elif score >= 50 and not matches:
        decision = "review"
    elif matches and (score >= 20 or "mask" in configured_actions or "block" in configured_actions):
        decision = "mask"
    else:
        decision = "allow"
    return score, severity, decision, factors
