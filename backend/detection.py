from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import select

from backend import ml
from backend.db import (
    Event,
    PreventionDecision,
    Setting,
    Flow,
    audit,
    aware,
    config,
    now,
)
from backend.observations import persist_flow, record_key, observed_number
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
    # A vertical scan is source -> one target and transport, not eight unrelated hosts.
    target_history = [
        e
        for e in history
        if e.dst_ip == str(item.dst_ip) and e.protocol == item.protocol
    ]
    ports = {e.dst_port for e in target_history if e.dst_port is not None}
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
    if (
        {"bytes", "duration"}.issubset(f.model_fields_set)
        and f.bytes > 10000000
        and f.duration < 10
    ):
        risk = max(risk, 65)
        evidence.append(
            "More than 10 MB transferred in under 10 seconds; investigate context"
        )
        rule = "BURST-001"
    if item.signature:
        risk = max(risk, {1: 95, 2: 75, 3: 45}[item.signature_severity])
        evidence.append("Engine signature: " + item.signature)
        rule = "ENGINE-SIGNATURE"
    rejected = [
        e
        for e in target_history
        if (e.observation or {}).get("connection_state")
        in ("REJ", "S0", "RSTOS0", "SH")
    ]
    if item.connection_state in ("REJ", "S0", "RSTOS0", "SH") and len(rejected) >= 4:
        risk = max(risk, 72)
        rule = "CONN-REJECT-001"
        evidence.append(
            f"{len(rejected) + 1} rejected/incomplete connections to this target in 60 seconds; not password failures"
        )
    import statistics

    baseline = [
        e.features.get("bytes")
        for e in target_history
        if e.dst_port == item.dst_port and e.features.get("bytes") is not None
    ]
    if len(baseline) >= 30 and "bytes" in item.features.model_fields_set:
        std = statistics.stdev(baseline)
        if std > 0 and f.bytes > statistics.mean(baseline) + 4 * std:
            risk = max(risk, 60)
            rule = "STAT-BYTES-001"
            evidence.append(
                f"Bytes exceed mean + 4 sample standard deviations of {len(baseline)} same-service observations; contextual anomaly only"
            )
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
    key = record_key(item, origin, source)
    existing = db.scalar(select(Event).where(Event.record_key == key))
    if existing:
        return existing
    flow = persist_flow(db, item, origin, source)
    db.flush()
    history = list(
        db.scalars(
            select(Event)
            .where(
                Event.src_ip == str(item.src_ip),
                Event.origin == origin,
                Event.detection_source == source,
                Event.flow_id.in_(select(Flow.id).where(Flow.sensor == flow.sensor)),
                Event.timestamp >= item.timestamp - timedelta(seconds=60),
                Event.timestamp <= item.timestamp,
            )
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(1000)
        )
    )
    # Multiple EVE alert/flow records may describe one connection. Count it once.
    seen = set()
    unique = []
    for e in history:
        identity = e.flow_id or str(e.id)
        if identity != flow.id and identity not in seen:
            seen.add(identity)
            unique.append(e)
    history = unique
    risk, severity, rule, evidence = classify(item, history)
    policy = db.get(Setting, "network_policy")
    for restriction in policy.value.get("restrictions", []) if policy else []:
        import ipaddress

        if (
            str(item.dst_ip) == restriction["destination"]
            and item.dst_port == restriction["port"]
            and not any(
                item.src_ip in ipaddress.ip_network(n)
                for n in restriction["allowed_sources"]
            )
        ):
            risk = max(risk, 80)
            severity = "high" if risk < 90 else "critical"
            rule = "ACCESS-001"
            evidence.append(
                "Observed source is outside configured permitted CIDRs for this destination/service"
            )
    available = item.features.model_dump(exclude_unset=True)
    prediction = ml.predict(available, item.dst_port)
    flow.risk = max(flow.risk, risk)
    linked = history if rule == "RATE-001" else []
    if rule in ("SCAN-001", "CONN-REJECT-001", "STAT-BYTES-001"):
        linked = [
            e
            for e in history
            if e.dst_ip == str(item.dst_ip) and e.protocol == item.protocol
        ]
    if rule == "CONN-REJECT-001":
        linked = [
            e
            for e in linked
            if (e.observation or {}).get("connection_state")
            in ("REJ", "S0", "RSTOS0", "SH")
        ]
    if rule == "STAT-BYTES-001":
        linked = [
            e
            for e in linked
            if e.dst_port == item.dst_port and e.features.get("bytes") is not None
        ]
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
        features=available,
        flow_id=flow.id,
        record_key=key,
        observation=item.model_dump(mode="json", exclude={"features"}),
        detection={
            "id": key[:24],
            "rule": rule,
            "description": "; ".join(evidence),
            "model_at_ingestion": prediction,
            "related_event_ids": [e.id for e in linked][:1000],
            "related_flow_ids": [e.flow_id for e in linked][:1000],
            "context_event_ids": [e.id for e in history][:1000],
            "risk_semantics": "Maximum risk of all matching indicators; primary rule is the last matching rule. Related IDs describe the primary rule; context IDs support other evidence.",
            "detected_at": now().isoformat(),
            "recommended_action": "Inspect original observations, service ownership and allowlists before approving prevention",
            "limitations": "60-second preceding event-time window, latest 1,000 source records. Late arrivals do not rewrite prior alerts. Batch replays are sorted by timestamp.",
        },
        action="alert" if risk >= 40 else "observed",
    )
    db.add(event)
    db.flush()
    cfg = config(db)
    steps = [
        {"stage": "IDS", "result": f"{rule}; risk {risk}"},
        {"stage": "Policy", "result": f"{cfg['mode']}; threshold {cfg['threshold']}"},
    ]
    decision = PreventionDecision(
        event_id=event.id,
        flow_id=flow.id,
        policy=cfg["mode"],
        outcome="detection_only" if cfg["mode"] == "detection" else "below_threshold",
        steps=steps,
    )
    db.add(decision)
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
            decision.block_id = block.id
            decision.outcome = (
                "simulated"
                if block.adapter == "simulated"
                else "set_membership_verified"
            )
            decision.steps = steps + [
                {
                    "stage": "Adapter",
                    "result": "SIMULATED — NO REAL PACKETS WERE BLOCKED"
                    if block.adapter == "simulated"
                    else "nftables set membership verified; packet drop NOT VERIFIED",
                }
            ]
        except HTTPException as exc:
            event.action = "block prevented"
            decision.outcome = "rejected_or_failed"
            decision.steps = steps + [{"stage": "Safeguard", "result": str(exc.detail)}]
            audit(
                db,
                "pipeline",
                "enforcement_prevented",
                event_id=event.id,
                reason=exc.detail,
            )
    elif cfg["mode"] == "manual" and risk >= cfg["threshold"]:
        event.action = "approval required"
        decision.outcome = "approval_required"
    db.commit()
    return event


def from_eve(raw):
    from backend.schemas import EventInput

    flow, alert = raw.get("flow", {}), raw.get("alert", {})
    features = {}
    if flow.get("age") is not None:
        features["duration"] = observed_number(flow["age"])
    for field, a, b in [
        ("bytes", "bytes_toserver", "bytes_toclient"),
        ("packets", "pkts_toserver", "pkts_toclient"),
    ]:
        if flow.get(a) is not None and flow.get(b) is not None:
            features[field] = observed_number(flow[a]) + observed_number(flow[b])
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
            "features": features,
            "sensor_flow_id": str(raw["flow_id"])
            if raw.get("flow_id") is not None
            else None,
            "app_protocol": raw.get("app_proto"),
            "connection_state": flow.get("state"),
            "bytes_src": flow.get("bytes_toserver"),
            "bytes_dst": flow.get("bytes_toclient"),
            "tcp_flags": raw.get("tcp", {}).get("tcp_flags"),
            "first_seen": flow.get("start"),
            "last_seen": flow.get("end"),
            "raw_record": raw,
            "limitations": [
                "EVE alert action/signature is sensor-reported evidence, not proof of CyberTwin packet dropping",
                "Missing counters and authentication features remain unavailable",
            ],
        }
    )
