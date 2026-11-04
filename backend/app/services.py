from collections import Counter

from sqlalchemy.orm import Session

from app.detection import PATTERNS, assess_risk, scan_text
from app.models import Incident, Policy, ScanEvent, User


DEFAULT_POLICIES = (
    ("student_name", "mask", 20, "Student names are educational-record identifiers."),
    ("student_id", "mask", 25, "Student identifiers should be protected."),
    ("academic_record", "mask", 20, "Academic results are sensitive student information."),
    ("api_secret", "block", 45, "Credentials can grant direct access to systems."),
    ("pan_like_id", "block", 35, "Government identifier should not leave approved systems."),
    ("aadhaar_like_id", "block", 35, "Government identifier should not leave approved systems."),
    ("account_number", "mask", 25, "Financial account-like values require masking."),
    ("email", "mask", 15, "Personal contact information should be masked."),
    ("phone", "mask", 15, "Personal contact information should be masked."),
)

RECOMMENDED_ACTIONS = {
    "block": "Review the destination and revoke or rotate any exposed credentials.",
    "mask": "Use the protected preview and verify recipient authorization before sharing.",
    "review": "Pause sharing and have an authorized reviewer assess the destination and context.",
    "allow": "Confirm the business purpose and apply least-privilege sharing.",
}


def ensure_default_policies(db: Session) -> None:
    existing = {policy.category for policy in db.query(Policy).all()}
    for category, action, weight, description in DEFAULT_POLICIES:
        if category not in existing:
            db.add(
                Policy(
                    category=category,
                    action=action,
                    weight=weight,
                    description=description,
                    enabled=True,
                )
            )
    db.commit()


def evaluate_scan(
    db: Session,
    user: User,
    text: str,
    source: str,
    destination: str,
    destination_authorized: bool,
    context: str,
) -> tuple[dict, Incident | None]:
    matches, protected = scan_text(text)
    policies = {
        policy.category: {"action": policy.action, "weight": policy.weight}
        for policy in db.query(Policy).filter(Policy.enabled.is_(True)).all()
    }
    score, severity, decision, factors = assess_risk(
        matches, policies, destination_authorized, context, text
    )
    scan_event = ScanEvent(
        actor_id=user.id,
        source=source,
        destination=destination,
        categories=list(matches),
        risk_score=score,
        decision="allow",
    )
    scan_event.decision = decision

    findings = [
        {
            "category": category,
            "count": len(occurrences),
            "masked_examples": [PATTERNS[category].replacement] * min(len(occurrences), 3),
        }
        for category, occurrences in matches.items()
    ]
    db.add(scan_event)
    db.flush()
    incident = None
    if matches or decision in {"block", "review"}:
        counts = {category: len(occurrences) for category, occurrences in matches.items()}
        incident = Incident(
            actor_id=user.id,
            scan_id=scan_event.id,
            source=source,
            destination=destination,
            categories=list(matches),
            finding_counts=counts,
            risk_factors=factors,
            risk_score=score,
            severity=severity,
            decision=decision,
            recommended_action=RECOMMENDED_ACTIONS[decision],
            status="open",
            masked_preview=(
                protected
                if matches
                else "No sensitive patterns detected; submitted sample text not retained."
            ),
        )
        db.add(incident)
    db.commit()
    if incident is not None:
        db.refresh(incident)

    messages = {
        "allow": "No policy threshold was met. The sample would be allowed.",
        "mask": "Sensitive values were masked. The protected sample is shown below.",
        "block": "Policy risk threshold was met. The sample transfer would be blocked.",
        "review": "Context indicates elevated risk. An authorized reviewer should decide before sharing.",
    }
    return (
        {
            "incident_id": incident.id if incident else None,
            "decision": decision,
            "risk_score": score,
            "severity": severity,
            "findings": findings,
            "risk_factors": factors,
            "protected_preview": protected,
            "recommended_action": (
                incident.recommended_action
                if incident is not None
                else "No sensitive pattern was found in the submitted text."
            ),
            "message": messages[decision],
        },
        incident,
    )


def seed_demo_incidents(db: Session, user: User) -> None:
    if db.query(ScanEvent).count():
        return
    examples = (
        ("Payments sandbox", "Unapproved export", ["api_secret"], "block", 88, "critical", 0),
        ("Claims sample", "External partner", ["email", "phone"], "mask", 48, "medium", 1),
        ("Finance test", "Public demo sink", ["account_number"], "block", 71, "high", 2),
        ("Support fixture", "Internal archive", ["email"], "mask", 31, "medium", 3),
        ("Synthetic gateway", "Unapproved export", ["pan_like_id"], "block", 76, "high", 4),
        ("Claims sample", "Approved archive", ["phone"], "mask", 24, "low", 5),
        ("Demo workspace", "Internal archive", [], "allow", 0, "low", 6),
    )
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    for source, destination, categories, decision, score, severity, days_ago in examples:
        event = ScanEvent(
            actor_id=user.id,
            source=source,
            destination=destination,
            categories=categories,
            risk_score=score,
            decision=decision,
            created_at=now - timedelta(days=days_ago),
        )
        db.add(event)
        db.flush()
        if categories:
            db.add(
                Incident(
                    actor_id=user.id,
                    scan_id=event.id,
                    source=source,
                    destination=destination,
                    categories=categories,
                    finding_counts={category: 1 for category in categories},
                    risk_factors=[{"label": "Synthetic demonstration record", "points": score}],
                    risk_score=score,
                    severity=severity,
                    decision=decision,
                    recommended_action=RECOMMENDED_ACTIONS[decision],
                    status="open",
                    masked_preview="Synthetic demonstration record; no customer content stored.",
                    created_at=event.created_at,
                )
            )
    db.commit()


def build_analytics(events: list[ScanEvent], incidents: list[Incident]) -> dict:
    from datetime import date, timedelta

    today = date.today()
    by_day: dict[str, list[ScanEvent]] = {}
    categories: Counter[str] = Counter()
    for event in events:
        day = event.created_at.date().isoformat()
        by_day.setdefault(day, []).append(event)
        categories.update(event.categories)
    trends = []
    for days_ago in range(6, -1, -1):
        day = (today - timedelta(days=days_ago)).isoformat()
        records = by_day.get(day, [])
        trends.append(
            {
                "date": day,
                "scans": len(records),
                "blocked": sum(item.decision == "block" for item in records),
                "masked": sum(item.decision == "mask" for item in records),
            }
        )
    return {
        "total_scans": len(events),
        "incidents": len(incidents),
        "blocked": sum(item.decision == "block" for item in events),
        "masked": sum(item.decision == "mask" for item in events),
        "reviewed": sum(item.decision == "review" for item in events),
        "high_risk": sum(item.risk_score >= 60 for item in events),
        "average_risk": (
            round(sum(item.risk_score for item in events) / len(events))
            if events
            else 0
        ),
        "trends": trends,
        "category_counts": dict(categories),
    }
