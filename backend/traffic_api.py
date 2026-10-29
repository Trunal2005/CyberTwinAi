"""Authenticated flow analysis, packet replay, journey and modeled route endpoints."""

import csv
import io
import json
import subprocess
import sys
from datetime import datetime
from ipaddress import ip_address, ip_network
import networkx as nx
import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_
from backend.db import (
    Flow,
    Event,
    Device,
    Block,
    PreventionDecision,
    Setting,
    AccessRule,
    Connection,
    audit,
    aware,
    now,
)
from backend.security import admin, db_session, limiter
from backend.schemas import EventInput
from backend.detection import ingest

router = APIRouter(prefix="/api")


def record(row):
    return jsonable_encoder(
        {
            c.name: aware(getattr(row, c.name))
            if isinstance(getattr(row, c.name), datetime)
            else getattr(row, c.name)
            for c in row.__table__.columns
        }
    )


def flow_query(
    src="",
    dst="",
    protocol="",
    port=None,
    origin="",
    sensor="",
    since=None,
    until=None,
    severity="",
):
    q = select(Flow)
    for col, value in [
        (Flow.src_ip, src),
        (Flow.dst_ip, dst),
        (Flow.protocol, protocol),
        (Flow.origin, origin),
        (Flow.sensor, sensor),
    ]:
        if value:
            q = q.where(col == value)
    if port is not None:
        q = q.where(Flow.dst_port == port)
    if since:
        q = q.where(Flow.last_seen >= since)
    if until:
        q = q.where(Flow.first_seen <= until)
    ranges = {
        "low": (0, 39),
        "medium": (40, 69),
        "high": (70, 89),
        "critical": (90, 100),
    }
    if severity:
        if severity not in ranges:
            raise HTTPException(422, "Unknown severity")
        q = q.where(Flow.risk.between(*ranges[severity]))
    return q


def analytics(rows):
    data = [record(r) for r in rows]
    f = pd.DataFrame(data)
    result = {
        "flows": len(rows),
        "packets": None,
        "bytes": None,
        "packet_coverage": 0,
        "byte_coverage": 0,
        "protocols": [],
        "sources": [],
        "destinations": [],
        "ports": [],
        "conversations": [],
        "timeline": [],
        "normal": sum(r.risk < 40 for r in rows),
        "suspicious": sum(r.risk >= 40 for r in rows),
        "duration_mean": None,
        "rate_bps": None,
        "directional_bytes": {"source": None, "destination": None},
        "scope": "Latest 5,000 matching normalized conversations. Byte counts retain source semantics; mixed sensors may observe the same traffic.",
        "formula": "Packets/bytes=sum(available counters), coverage=non-null rows. Minute buckets use flow first_seen, not individual packet timestamps. Rate=8*known bytes/(latest last_seen-earliest first_seen), a capture-span average, not link utilization.",
    }
    if not rows:
        return result
    for name, col in [("packets", "packets"), ("bytes", "total_bytes")]:
        vals = [getattr(r, col) for r in rows if getattr(r, col) is not None]
        result[name] = sum(vals) if vals else None
        result["packet_coverage" if name == "packets" else "byte_coverage"] = len(vals)
    for key, col in [
        ("protocols", "protocol"),
        ("sources", "src_ip"),
        ("destinations", "dst_ip"),
        ("ports", "dst_port"),
    ]:
        result[key] = [
            {"name": str(int(k)) if col == "dst_port" else str(k), "count": int(v)}
            for k, v in f[col].dropna().value_counts().head(12).items()
        ]
    durations = f.duration.dropna()
    result["duration_mean"] = float(durations.mean()) if len(durations) else None
    for key, col in [("source", "bytes_src"), ("destination", "bytes_dst")]:
        result["directional_bytes"][key] = (
            int(f[col].sum()) if f[col].notna().any() else None
        )
    first = min(aware(r.first_seen) for r in rows)
    last = max(aware(r.last_seen) for r in rows)
    seconds = (last - first).total_seconds()
    if seconds > 0 and result["bytes"] is not None:
        result["rate_bps"] = round(result["bytes"] * 8 / seconds, 2)
    f["bucket"] = (
        pd.to_datetime(f.first_seen, format="ISO8601", utc=True)
        .dt.floor("min")
        .astype(str)
    )
    for bucket, g in f.groupby("bucket", sort=True):
        result["timeline"].append(
            {
                "time": bucket,
                "flows": len(g),
                "packets": int(g.packets.sum()) if g.packets.notna().any() else None,
                "bytes": int(g.total_bytes.sum())
                if g.total_bytes.notna().any()
                else None,
                "suspicious": int((g.risk >= 40).sum()),
            }
        )
    for key, g in f.groupby(["src_ip", "dst_ip", "protocol"], dropna=False):
        result["conversations"].append(
            {
                "src": key[0],
                "dst": key[1],
                "protocol": key[2],
                "flows": len(g),
                "bytes": int(g.total_bytes.sum())
                if g.total_bytes.notna().any()
                else None,
            }
        )
    result["conversations"] = sorted(
        result["conversations"], key=lambda r: r["flows"], reverse=True
    )[:20]
    return result


@router.get("/traffic")
def traffic(
    src: str = Query("", max_length=45),
    dst: str = Query("", max_length=45),
    protocol: str = "",
    port: int | None = Query(None, ge=0, le=65535),
    origin: str = "",
    sensor: str = Query("", max_length=80),
    since: datetime | None = None,
    until: datetime | None = None,
    severity: str = "",
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=100),
    user=Depends(admin),
    db=Depends(db_session),
):
    q = flow_query(src, dst, protocol, port, origin, sensor, since, until, severity)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = list(db.scalars(q.order_by(Flow.first_seen.desc(), Flow.id).limit(5000)))
    selected = list(
        db.scalars(
            q.order_by(Flow.first_seen.desc(), Flow.id)
            .offset((page - 1) * size)
            .limit(size)
        )
    )
    decisions = (
        list(
            db.scalars(
                select(PreventionDecision)
                .where(PreventionDecision.flow_id.in_([r.id for r in rows]))
                .order_by(PreventionDecision.timestamp.desc())
                .limit(100)
            )
        )
        if rows
        else []
    )
    return {
        "items": [record(r) for r in selected],
        "total": total,
        "page": page,
        "size": size,
        "analytics": analytics(rows),
        "truncated": total > 5000,
        "latest_decisions": [record(r) for r in decisions],
    }


@router.get("/traffic/export")
def export_traffic(
    format: str = "json", origin: str = "", user=Depends(admin), db=Depends(db_session)
):
    rows = list(
        db.scalars(
            flow_query(origin=origin).order_by(Flow.first_seen.desc()).limit(5000)
        )
    )
    values = [record(r) for r in rows]
    if format == "json":
        body = json.dumps(
            {
                "flows": values,
                "analytics": analytics(rows),
                "exported_at": now().isoformat(),
            },
            indent=2,
        )
        media = "application/json"
    elif format == "csv":
        buffer = io.StringIO()
        fields = [
            "id",
            "origin",
            "sensor",
            "first_seen",
            "last_seen",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "packets",
            "total_bytes",
            "duration",
            "risk",
        ]
        writer = csv.DictWriter(buffer, fields, extrasaction="ignore")
        writer.writeheader()
        for r in values:
            writer.writerow(
                {
                    k: "'" + str(v)
                    if str(v).startswith(("=", "+", "-", "@", "\t", "\r"))
                    else v
                    for k, v in r.items()
                }
            )
        body = buffer.getvalue()
        media = "text/csv"
    else:
        raise HTTPException(422, "Choose json or csv")
    return Response(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="cybertwin-flows.{format}"'
        },
    )


@router.post("/traffic/pcap")
def upload_pcap(
    file: UploadFile = File(...), user=Depends(admin), db=Depends(db_session)
):
    limiter.check(f"pcap:{user.id}", 5)
    if not (file.filename or "").lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(422, "Choose a .pcap or .pcapng capture")
    try:
        raw = file.file.read(2_000_001)
    finally:
        file.file.close()
    if len(raw) > 2_000_000:
        raise HTTPException(413, "Capture exceeds 2 MB")
    try:
        child = subprocess.run(
            [sys.executable, "-m", "backend.pcap_worker"],
            input=raw,
            capture_output=True,
            timeout=12,
            shell=False,
        )
        result = json.loads(child.stdout)
        if child.returncode or result.get("error"):
            raise ValueError(result.get("error", "Capture parser failed"))
        items = [EventInput.model_validate(r) for r in result["observations"]]
    except (ValueError, KeyError, subprocess.SubprocessError) as exc:
        raise HTTPException(422, f"Capture rejected: {str(exc)[:180]}")
    before = db.scalar(select(func.count(Event.id)))
    ids = []
    for item in sorted(items, key=lambda r: r.timestamp):
        ids.append(ingest(db, item, "replay", "pcap").id)
    from backend.main import monitor

    if not monitor["running"]:
        monitor["mode"] = "replay"
    audit(
        db,
        user.username,
        "pcap_replayed",
        capture=result["capture_sha256"],
        event_ids=ids,
        packets=result["packets"],
    )
    db.commit()
    return {
        "origin": "replay",
        "event_ids": ids,
        "packets": result["packets"],
        "conversations": len(items),
        "new_events": db.scalar(select(func.count(Event.id))) - before,
        "non_ip_packets": result["non_ip_packets"],
    }


def journey(db, flow):
    devices = list(db.scalars(select(Device)))
    by_ip = {d.ip: d for d in devices}
    source = by_ip.get(flow.src_ip)
    target = by_ip.get(flow.dst_ip)
    graph = nx.DiGraph()
    graph.add_nodes_from(d.id for d in devices)
    from backend.twin import permits

    for e in db.scalars(select(Connection)):
        rule = db.get(AccessRule, e.id)
        if permits(rule, flow.protocol, flow.dst_port):
            graph.add_edge(e.source, e.target)
    path = []
    if source and target:
        try:
            path = nx.shortest_path(graph, source.id, target.id)
        except nx.NetworkXNoPath:
            pass
    events = list(
        db.scalars(
            select(Event)
            .where(Event.flow_id == flow.id)
            .order_by(Event.timestamp)
            .limit(200)
        )
    )
    decisions = list(
        db.scalars(
            select(PreventionDecision)
            .where(PreventionDecision.flow_id == flow.id)
            .limit(200)
        )
    )
    return {
        "flow": record(flow),
        "source_device": record(source) if source else None,
        "destination_device": record(target) if target else None,
        "modeled_path": path,
        "path_label": "MODELED PATH — transit hops were not observed",
        "events": [record(e) for e in events],
        "decisions": [
            {
                **record(r),
                "block": record(db.get(Block, r.block_id))
                if r.block_id and db.get(Block, r.block_id)
                else None,
            }
            for r in decisions
        ],
        "ml": __import__("backend.ml", fromlist=["predict"]).predict(
            events[-1].features, flow.dst_port
        )
        if events
        else None,
        "explanation": {
            "ip": "Layer 3 endpoint address; not proof of user identity",
            "port": "TCP/UDP endpoint service selector; absent for ICMP",
            "packets": "Observed packet count, unavailable where sensor did not supply it",
            "bytes": "Captured IP bytes for PCAP; sensor byte semantics for logs",
            "route": "Endpoint evidence cannot establish intermediate router or switch forwarding",
        },
    }


@router.get("/flows/{id}/journey")
def flow_journey(id: str, user=Depends(admin), db=Depends(db_session)):
    row = db.get(Flow, id)
    if not row:
        raise HTTPException(404, "Flow not found")
    return journey(db, row)


@router.get("/network/observations")
def overlay(origin: str = "", user=Depends(admin), db=Depends(db_session)):
    rows = list(
        db.scalars(
            flow_query(origin=origin).order_by(Flow.first_seen.desc()).limit(500)
        )
    )
    devices = {d.ip: d.id for d in db.scalars(select(Device))}
    blocks = {
        b.ip: record(b)
        for b in db.scalars(
            select(Block).where(Block.state == "active", Block.expires > now())
        )
    }
    return {
        "flows": [
            {
                **record(r),
                "source_node": devices.get(r.src_ip),
                "target_node": devices.get(r.dst_ip),
                "block": blocks.get(r.src_ip),
            }
            for r in rows
        ],
        "scope": "Latest 500 flows. Straight endpoint overlays are observations, not measured physical routes.",
    }


@router.get("/network/route")
def modeled_route(
    source: str = Query(max_length=60),
    target: str = Query(max_length=60),
    protocol: str = "",
    port: int | None = Query(None, ge=0, le=65535),
    user=Depends(admin),
    db=Depends(db_session),
):
    from backend.twin import permits

    graph = nx.DiGraph()
    graph.add_nodes_from(db.scalars(select(Device.id)))
    if source not in graph or target not in graph:
        raise HTTPException(422, "Choose two existing virtual assets")
    for e in db.scalars(select(Connection)):
        if permits(db.get(AccessRule, e.id), protocol or None, port):
            graph.add_edge(e.source, e.target)
    try:
        path = nx.shortest_path(graph, source, target)
    except nx.NetworkXNoPath:
        path = []
    return {
        "path": path,
        "reachable": bool(path),
        "label": "MODELED PATH — no observed transit-hop evidence",
        "protocol": protocol or None,
        "port": port,
    }


class Restriction(BaseModel):
    destination: str = Field(max_length=45)
    port: int = Field(ge=0, le=65535)
    allowed_sources: list[str] = Field(max_length=50)


class NetworkPolicy(BaseModel):
    restrictions: list[Restriction] = Field(default_factory=list, max_length=30)
    confirmed: bool = False


@router.get("/network/policy")
def network_policy(user=Depends(admin), db=Depends(db_session)):
    row = db.get(Setting, "network_policy")
    return row.value if row else {"restrictions": []}


@router.put("/network/policy")
def set_policy(body: NetworkPolicy, user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"network-policy:{user.id}", 10)
    if not body.confirmed:
        raise HTTPException(409, "Confirm network observation policy")
    try:
        restrictions = [
            {
                "destination": str(ip_address(r.destination)),
                "port": r.port,
                "allowed_sources": [
                    str(ip_network(n, strict=False)) for n in r.allowed_sources
                ],
            }
            for r in body.restrictions
        ]
    except ValueError:
        raise HTTPException(422, "Invalid destination IP or source CIDR")
    row = db.get(Setting, "network_policy") or Setting(key="network_policy")
    row.value = {"restrictions": restrictions}
    db.add(row)
    audit(db, user.username, "network_policy_changed", restrictions=restrictions)
    db.commit()
    return row.value
