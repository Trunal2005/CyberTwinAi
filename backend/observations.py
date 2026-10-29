"""Observation normalization. Missing data remains absent, never measured zero."""

import hashlib
import ipaddress
import json
import math
from datetime import datetime, timezone
from sqlalchemy import select
from backend.db import Flow, aware, now


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()


def observed_number(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(
            "Sensor counters/timestamps must be finite nonnegative JSON numbers"
        )
    return value


def persist_flow(db, item, origin, source):
    sensor = item.sensor or source
    # Sensor IDs still include a time window to handle sensor-ID reuse after restarts.
    first = item.first_seen or item.timestamp
    last = item.last_seen or item.timestamp
    if first > last:
        raise ValueError("first_seen must not be after last_seen")
    tuple5 = [
        str(item.src_ip),
        item.src_port,
        str(item.dst_ip),
        item.dst_port,
        item.protocol,
    ]
    window = int(first.timestamp() // (3600 if item.sensor_flow_id else 60))
    identity = digest([origin, sensor, tuple5, window, item.sensor_flow_id])
    row = db.get(Flow, identity)
    features = item.features.model_dump(exclude_unset=True)
    values = {
        "packets": features.get("packets"),
        "total_bytes": features.get("bytes"),
        "duration": features.get("duration"),
        "bytes_src": item.bytes_src,
        "bytes_dst": item.bytes_dst,
    }
    if row is None:
        row = Flow(
            id=identity,
            origin=origin,
            sensor=sensor,
            sensor_flow_id=item.sensor_flow_id,
            first_seen=first,
            last_seen=last,
            src_ip=str(item.src_ip),
            dst_ip=str(item.dst_ip),
            src_port=item.src_port,
            dst_port=item.dst_port,
            ip_version=ipaddress.ip_address(str(item.src_ip)).version,
            protocol=item.protocol,
            app_protocol=item.app_protocol,
            state=item.connection_state,
            tcp_flags=item.tcp_flags,
            availability={k: v is not None for k, v in values.items()},
            limitations=item.limitations
            or ["Endpoint observation only; intermediate routing not observed"],
            risk=0,
            **values,
        )
        db.add(row)
    else:
        row.first_seen = min(aware(row.first_seen), first)
        row.last_seen = max(aware(row.last_seen), last)
        # EVE flow records use cumulative counters; multiple engine records must not add them twice.
        for k, v in values.items():
            if v is not None:
                setattr(row, k, max(getattr(row, k) or 0, v))
        row.availability = {k: getattr(row, k) is not None for k in values}
        if item.connection_state:
            row.state = item.connection_state
        if item.tcp_flags:
            row.tcp_flags = item.tcp_flags
        if item.app_protocol:
            row.app_protocol = item.app_protocol
    return row


def record_key(item, origin, source):
    # Include the normalized tuple as well: arbitrary raw_record metadata cannot
    # make two distinct observations collide. Unset ingestion-time defaults are excluded.
    raw = item.model_dump(mode="json", exclude_unset=True)
    provenance = "collector" if source == "suricata" else origin
    return digest([provenance, item.sensor or source, raw])


def from_zeek(raw):
    from backend.schemas import EventInput

    features = {}
    if raw.get("duration") is not None:
        features["duration"] = observed_number(raw["duration"])
    if raw.get("orig_pkts") is not None and raw.get("resp_pkts") is not None:
        features["packets"] = observed_number(raw["orig_pkts"]) + observed_number(
            raw["resp_pkts"]
        )
    # Payload and IP byte counters have different semantics; retain both raw, prefer IP totals.
    a, b = raw.get("orig_ip_bytes"), raw.get("resp_ip_bytes")
    if a is not None and b is not None:
        features["bytes"] = observed_number(a) + observed_number(b)
    protocol = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmp6": "ICMP"}.get(
        raw.get("proto"), "OTHER"
    )
    try:
        first = datetime.fromtimestamp(observed_number(raw["ts"]), timezone.utc)
    except (OverflowError, OSError):
        raise ValueError("Unsupported Zeek timestamp")
    from datetime import timedelta

    return EventInput(
        timestamp=first,
        first_seen=first,
        last_seen=first + timedelta(seconds=features.get("duration", 0)),
        src_ip=raw["id.orig_h"],
        dst_ip=raw["id.resp_h"],
        src_port=raw.get("id.orig_p") if protocol in ("TCP", "UDP") else None,
        dst_port=raw.get("id.resp_p") if protocol in ("TCP", "UDP") else None,
        protocol=protocol,
        category="zeek-connection",
        sensor_flow_id=raw.get("uid"),
        app_protocol=raw.get("service"),
        connection_state=raw.get("conn_state"),
        features=features,
        bytes_src=a,
        bytes_dst=b,
        raw_record=raw,
        limitations=[
            "Zeek conn_state is connection evidence, not password-authentication evidence",
            "orig_bytes/resp_bytes are payload bytes; orig_ip_bytes/resp_ip_bytes are IP bytes",
        ],
    )
