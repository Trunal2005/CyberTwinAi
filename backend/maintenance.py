"""Explicit local retention for old unreviewed low-risk simulation/replay only."""

import argparse
import json
from datetime import datetime, timezone
from sqlalchemy import select, delete
from backend.db import Event, Flow, PreventionDecision, SessionLocal, audit


def retain(db, before, origin, confirmed=False):
    if origin not in ("simulation", "replay"):
        raise ValueError("Live evidence is not eligible for this retention tool")
    protected = select(PreventionDecision.event_id).where(
        PreventionDecision.outcome.not_in(["detection_only", "below_threshold"])
    )
    ids = list(
        db.scalars(
            select(Event.id)
            .where(
                Event.origin == origin,
                Event.timestamp < before,
                Event.risk < 40,
                Event.status == "open",
                Event.id.not_in(protected),
            )
            .order_by(Event.id)
            .limit(1000)
        )
    )
    result = {
        "eligible_events": len(ids),
        "batch_limit": 1000,
        "origin": origin,
        "before": before.isoformat(),
        "confirmed": confirmed,
    }
    if confirmed and ids:
        db.execute(
            delete(PreventionDecision).where(PreventionDecision.event_id.in_(ids))
        )
        db.execute(delete(Event).where(Event.id.in_(ids)))
        unused = list(
            db.scalars(
                select(Flow.id)
                .where(
                    Flow.origin == origin,
                    Flow.last_seen < before,
                    Flow.id.not_in(
                        select(Event.flow_id).where(Event.flow_id.is_not(None))
                    ),
                )
                .limit(1000)
            )
        )
        if unused:
            db.execute(delete(Flow).where(Flow.id.in_(unused)))
        audit(db, "local-maintenance", "retention_applied", **result)
        db.commit()
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--before", required=True)
    p.add_argument("--origin", choices=["simulation", "replay"], required=True)
    p.add_argument("--confirm", action="store_true")
    args = p.parse_args()
    cutoff = datetime.fromisoformat(args.before.replace("Z", "+00:00"))
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    with SessionLocal() as db:
        print(json.dumps(retain(db, cutoff, args.origin, args.confirm), indent=2))
