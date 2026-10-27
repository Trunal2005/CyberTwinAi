from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import select

from backend import ml
from backend.db import Event, audit, config, now
from backend.firewall import create_block


def classify(item, history):
    f = item.features
    evidence, risk, rule = [], 0, "flow-baseline"
    if f.failed_auth >= 5:
        risk = min(95, 60 + f.failed_auth * 2)
        evidence.append(
            f"{f.failed_auth} failed authentication attempts reported by source"
        )
        rule = "AUTH-001"
    ports = {e.dst_port for e in history if e.dst_port is not None}
    if item.dst_port is not None:
        ports.add(item.dst_port)
    if len(ports) >= 8:
        risk = max(risk, 78)
        evidence.append(
            f"{len(ports)} distinct destination ports within a 60-second event-time window"
        )
        rule = "SCAN-001"
    if f.frequency >= 100 or len(history) >= 99:
        risk = max(risk, 80)
        evidence.append("At least 100 connections per minute reported or observed")
        rule = "RATE-001"
    if f.bytes > 10000000 and f.duration < 10:
        risk = max(risk, 65)
        evidence.append(
            "More than 10 MB transferred in under 10 seconds; investigate context"
        )
        rule = "BURST-001"
    if item.signature:
        risk = max(risk, {1: 95, 2: 75, 3: 45}[item.signature_severity])
        evidence.append("Engine signature: " + item.signature)
        rule = "ENGINE-SIGNATURE"
    if not evidence:
        evidence = [
            "No configured rule threshold crossed; this does not establish safety."
        ]
    severity = (
        "critical"
        if risk >= 90
        else "high"
        if risk >= 70
        else "medium"
        if risk >= 40
        else "low"
    )
    return risk, severity, rule, evidence


def ingest(db, item, origin="simulation", source="generated"):
    history = list(
        db.scalars(
            select(Event)
            .where(
                Event.src_ip == str(item.src_ip),
                Event.origin == origin,
                Event.timestamp >= item.timestamp - timedelta(seconds=60),
                Event.timestamp <= item.timestamp,
            )
            .limit(1000)
        )
    )
    risk, severity, rule, evidence = classify(item, history)
    prediction = ml.predict(item.features.model_dump(), item.dst_port)
    event = Event(
        timestamp=item.timestamp,
        src_ip=str(item.src_ip),
        dst_ip=str(item.dst_ip),
        src_port=item.src_port,
        dst_port=item.dst_port,
        protocol=item.protocol,
        category=item.category,
        origin=origin,
        detection_source=source,
        rule=rule,
        severity=severity,
        risk=risk,
        ml_score=prediction["score"],
        confidence=prediction["confidence"],
        evidence=evidence,
        features=item.features.model_dump(),
        action="alert" if risk >= 40 else "observed",
    )
    db.add(event)
    db.flush()
    cfg = config(db)
    if cfg["mode"] == "automatic" and risk >= cfg["threshold"]:
        try:
            # A bounded action budget also applies to automated enforcement.
            from backend.security import limiter

            limiter.check("automatic-enforcement", 10)
            block = create_block(
                db,
                item.src_ip,
                f"{rule}: rule risk {risk}",
                cfg["duration_minutes"],
                "pipeline",
                event,
            )
            event.action = (
                "simulated block" if block.adapter == "simulated" else "verified block"
            )
        except HTTPException as exc:
            event.action = "block prevented"
            audit(
                db,
                "pipeline",
                "enforcement_prevented",
                event_id=event.id,
                reason=exc.detail,
            )
    elif cfg["mode"] == "manual" and risk >= cfg["threshold"]:
        event.action = "approval required"
    db.commit()
    return event


def from_eve(raw):
    from backend.schemas import EventInput

    flow, alert = raw.get("flow", {}), raw.get("alert", {})
    return EventInput.model_validate(
        {
            "timestamp": raw["timestamp"],
            "src_ip": raw["src_ip"],
            "dst_ip": raw["dest_ip"],
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dest_port"),
            "protocol": raw.get("proto", "OTHER")
            if raw.get("proto") in ["TCP", "UDP", "ICMP"]
            else "OTHER",
            "category": raw.get("event_type", "connection"),
            "signature": alert.get("signature"),
            "signature_severity": alert.get("severity", 3),
            "features": {
                "duration": max(0, flow.get("age", 0)),
                "bytes": flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0),
                "packets": flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0),
            },
        }
    )
