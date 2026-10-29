import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import secrets
import random
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import pandas as pd
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, IPvAnyAddress, ValidationError
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError

from backend import ml
from backend.db import (
    AccessRule,
    Audit,
    Block,
    Connection,
    Device,
    Event,
    Note,
    Scenario,
    Session,
    SessionLocal,
    Setting,
    User,
    audit,
    aware,
    config,
    now,
)
from backend.detection import from_eve, ingest
from backend.observations import from_zeek
from backend.firewall import adapter, create_block, expire_blocks, remove_block
from backend.schemas import (
    BlockInput,
    ConnectionInput,
    DeviceInput,
    EnforcementConfig,
    EventInput,
    Features,
    Login,
    SimulationInput,
)
from backend.security import admin, db_session, limiter, password_hash, password_ok
from backend.seed import sample_events
from backend.twin import analyze

logger = logging.getLogger("cybertwin")
monitor = {"running": False, "mode": "simulation", "error": None, "last_live": None}
collector = {
    "offset": 0,
    "inode": None,
    "discarding": False,
    "parse_errors": 0,
    "backlog_bytes": 0,
}
simulation_rng = random.Random(42)


def serialize(row):
    result = jsonable_encoder(
        {
            c.name: aware(getattr(row, c.name))
            if isinstance(getattr(row, c.name), datetime)
            else getattr(row, c.name)
            for c in row.__table__.columns
        }
    )
    if isinstance(row, Block):
        result["verification_scope"] = (
            "SIMULATED — NO REAL PACKETS WERE BLOCKED"
            if row.adapter == "simulated"
            else "Historical set membership only; actual packet dropping NOT VERIFIED. Reconcile for current membership."
        )
        result["packet_drop_verified"] = False
    return result


async def worker():
    while True:
        try:
            with SessionLocal() as db:
                expire_blocks(db)
                if monitor["running"] and monitor["mode"] == "simulation":
                    # Reproducible sequence of simulated patterns; timestamps are current.
                    item = sample_events(12)[simulation_rng.randrange(12)].model_copy(
                        update={"timestamp": now()}
                    )
                    ingest(db, item)
                elif monitor["running"] and monitor["mode"] == "live":
                    path = Path(os.environ["SURICATA_EVE_PATH"])
                    stat = path.stat()
                    if (
                        collector["inode"] != stat.st_ino
                        or stat.st_size < collector["offset"]
                    ):
                        collector.update(offset=0, inode=stat.st_ino, discarding=False)
                    with path.open("rb") as stream:
                        stream.seek(collector["offset"])
                        for _ in range(200):
                            raw_line = stream.readline(65537)
                            if not raw_line:
                                break
                            if collector["discarding"]:
                                collector["offset"] = stream.tell()
                                collector["discarding"] = not raw_line.endswith(b"\n")
                                continue
                            if len(raw_line) > 65536:
                                collector["parse_errors"] += 1
                                collector["offset"] = stream.tell()
                                collector["discarding"] = not raw_line.endswith(b"\n")
                                monitor["error"] = "Oversized EVE record rejected"
                                continue
                            if not raw_line.endswith(b"\n"):
                                break
                            collector["offset"] = stream.tell()
                            try:
                                raw = json.loads(raw_line)
                                if "src_ip" not in raw or "dest_ip" not in raw:
                                    continue
                                item = from_eve(raw)
                                # Historical data in a configured file is replay, never live.
                                fresh = (
                                    now() - timedelta(seconds=90)
                                    <= item.timestamp
                                    <= now() + timedelta(seconds=5)
                                )
                                ingest(
                                    db, item, "live" if fresh else "replay", "suricata"
                                )
                                if fresh:
                                    monitor["last_live"] = now()
                                    monitor["error"] = None
                            except (ValueError, KeyError, TypeError, ValidationError):
                                collector["parse_errors"] += 1
                                monitor["error"] = (
                                    "Invalid EVE record rejected; check source schema"
                                )
                    collector["backlog_bytes"] = max(
                        0, stat.st_size - collector["offset"]
                    )
                    checkpoint = db.get(Setting, "collector_checkpoint") or Setting(
                        key="collector_checkpoint"
                    )
                    checkpoint.value = {
                        "path": str(path.resolve()),
                        "inode": stat.st_ino,
                        "offset": collector["offset"],
                        "discarding": collector["discarding"],
                    }
                    db.add(checkpoint)
                    db.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Monitoring worker failed")
            monitor["error"] = "Collector or database error; review server log"
        await asyncio.sleep(3)


@asynccontextmanager
async def lifespan(app):
    # Schema migrations are an explicit setup step, never hidden at startup.
    task = asyncio.create_task(worker())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="CyberTwin AI", version="1.0.0", lifespan=lifespan)
from backend.traffic_api import router as traffic_router

app.include_router(traffic_router)
origins = os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        # Browser CSRF protection. SameSite strict cookies are an additional layer.
        if (
            origin
            and origin not in origins
            and origin != str(request.base_url).rstrip("/")
        ):
            return JSONResponse(
                {"error": {"code": 403, "message": "Untrusted request origin"}}, 403
            )
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse(
                {"error": {"code": 403, "message": "Cross-site mutation rejected"}}, 403
            )
        size = request.headers.get("content-length")
        if size and (not size.isdigit() or int(size) > 2_100_000):
            return JSONResponse(
                {"error": {"code": 413, "message": "Request exceeds 2 MB limit"}}, 413
            )
        # Enforce the same bound for chunked requests, without trusting Content-Length.
        chunks, received = [], 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > 2_100_000:
                return JSONResponse(
                    {"error": {"code": 413, "message": "Request exceeds 2 MB limit"}},
                    413,
                )
            chunks.append(chunk)
        request._body = b"".join(chunks)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    if request.method not in ("GET", "HEAD") and request.url.path.startswith(
        ("/api/blocks", "/api/enforcement")
    ):
        try:
            with SessionLocal() as db:
                audit(
                    db,
                    getattr(request.state, "actor", "unauthenticated"),
                    "enforcement_request_rejected",
                    endpoint=request.url.path,
                    code=exc.status_code,
                    reason=str(exc.detail),
                )
                db.commit()
        except Exception:
            logger.exception("Could not audit rejected enforcement request")
    return JSONResponse(
        {"error": {"code": exc.status_code, "message": exc.detail}}, exc.status_code
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return JSONResponse(
        {
            "error": {
                "code": 422,
                "message": "Invalid input",
                "fields": [
                    {"field": ".".join(map(str, e["loc"])), "message": e["msg"]}
                    for e in exc.errors()
                ],
            }
        },
        422,
    )


@app.exception_handler(IntegrityError)
async def conflict(request, exc):
    return JSONResponse(
        {"error": {"code": 409, "message": "Duplicate or conflicting database record"}},
        409,
    )


@app.exception_handler(Exception)
async def internal_error(request, exc):
    logger.error("Unhandled API error", exc_info=exc)
    return JSONResponse(
        {"error": {"code": 500, "message": "Internal error; review server log"}}, 500
    )


@app.post("/api/auth/login")
def login(body: Login, request: Request, response: Response, db=Depends(db_session)):
    limiter.check("login:" + (request.client.host if request.client else "unknown"), 5)
    user = db.scalar(select(User).where(User.username == body.username))
    # Spend the same hashing work for unknown usernames.
    stored = user.password_hash if user else "0" * 32 + "$" + "0" * 64
    if not password_ok(body.password, stored) or not user:
        audit(db, body.username, "login_failed")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(48)
    db.add(
        Session(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            user_id=user.id,
            expires=now() + timedelta(hours=8),
        )
    )
    audit(db, user.username, "login")
    db.commit()
    response.set_cookie(
        "ct_session",
        token,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE") == "true",
        samesite="strict",
        max_age=28800,
        path="/",
    )
    return {"username": user.username, "role": user.role}


@app.get("/api/auth/me")
def me(user=Depends(admin)):
    return {"username": user.username, "role": user.role}


@app.post("/api/auth/logout")
def logout(
    request: Request, response: Response, user=Depends(admin), db=Depends(db_session)
):
    row = db.get(
        Session,
        hashlib.sha256(request.cookies.get("ct_session", "").encode()).hexdigest(),
    )
    db.delete(row)
    audit(db, user.username, "logout")
    db.commit()
    response.delete_cookie("ct_session", path="/")
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"status": "ok", "application": "CyberTwin AI"}


def status_payload(db):
    live_configured = (
        bool(os.getenv("SURICATA_EVE_PATH"))
        and os.getenv("SURICATA_LIVE_CONFIRMED") == "true"
    )
    fresh = bool(
        monitor["last_live"] and monitor["last_live"] > now() - timedelta(seconds=90)
    )
    is_live = (
        live_configured
        and fresh
        and monitor["running"]
        and monitor["mode"] == "live"
        and not monitor["error"]
    )
    target = adapter()
    ready = target.ready()
    bundle = ml.load()
    db.execute(text("SELECT 1"))
    return {
        "mode": "LIVE MONITORING"
        if is_live
        else ("REPLAY" if monitor["mode"] == "replay" else "SIMULATION")
        if monitor["mode"] != "live"
        else "LIVE SOURCE WAITING",
        "monitoring": monitor["running"],
        "enforcement_enabled": target.name != "simulated"
        and ready
        and config(db)["mode"] != "detection",
        "enforcement": config(db),
        "adapter": target.name,
        "error": monitor["error"],
        "integrations": {
            "Suricata": "connected"
            if is_live
            else "error"
            if monitor["error"]
            else "disconnected"
            if live_configured
            else "unconfigured",
            "Zeek": "unconfigured",
            "Firewall adapter": "connected (simulation)"
            if target.name == "simulated"
            else "connected"
            if ready
            else "error",
            "ML model": "connected ("
            + bundle["metrics"].get("feature_schema", "legacy synthetic")
            + ")"
            if bundle
            else "unconfigured",
            "Database": "connected",
        },
        "last_live": monitor["last_live"],
        "collector": dict(collector),
        "live_configured": live_configured,
    }


@app.get("/api/status")
def status(user=Depends(admin), db=Depends(db_session)):
    return status_payload(db)


class MonitorInput(BaseModel):
    running: bool
    mode: Literal["simulation", "live"] = "simulation"


@app.post("/api/monitor")
def monitoring(body: MonitorInput, user=Depends(admin), db=Depends(db_session)):
    if body.running and body.mode == "live":
        path = os.getenv("SURICATA_EVE_PATH")
        if (
            not path
            or os.getenv("SURICATA_LIVE_CONFIRMED") != "true"
            or not Path(path).is_file()
        ):
            raise HTTPException(
                409, "Live source must be explicitly configured and readable"
            )
        # Start from end so starting monitoring never replays a historic file as live.
        info = Path(path).stat()
        checkpoint = db.get(Setting, "collector_checkpoint")
        saved = checkpoint.value if checkpoint else {}
        if (
            saved.get("path") == str(Path(path).resolve())
            and saved.get("inode") == info.st_ino
            and saved.get("offset", 0) <= info.st_size
        ):
            collector.update(
                offset=saved["offset"],
                inode=info.st_ino,
                discarding=saved.get("discarding", False),
            )
        else:
            collector.update(offset=info.st_size, inode=info.st_ino, discarding=False)
    monitor.update(running=body.running, mode=body.mode, error=None, last_live=None)
    audit(db, user.username, "monitor_changed", **body.model_dump())
    db.commit()
    return status_payload(db)


@app.get("/api/overview")
def overview(user=Depends(admin), db=Depends(db_session)):
    expire_blocks(db)
    rows = list(db.scalars(select(Event).order_by(Event.timestamp.desc()).limit(10000)))
    frame = pd.DataFrame(
        [
            {
                "timestamp": aware(e.timestamp),
                "risk": e.risk,
                "severity": e.severity,
                "src_ip": e.src_ip,
            }
            for e in rows
        ]
    )
    timeline, sources = [], []
    if not frame.empty:
        frame["bucket"] = (
            pd.to_datetime(frame.timestamp, utc=True)
            .dt.floor("5min")
            .dt.strftime("%H:%M")
        )
        # Keep dates in grouping to avoid combining different days at the same time.
        frame["time"] = (
            pd.to_datetime(frame.timestamp, utc=True).dt.floor("5min").astype(str)
        )
        for key, group in frame.sort_values("timestamp").groupby("time", sort=True):
            timeline.append(
                {
                    "time": key,
                    "label": group.bucket.iloc[0],
                    "events": len(group),
                    "threats": int((group.risk >= 40).sum()),
                    "risk": round(float(group.risk.mean()), 1),
                }
            )
        sources = [
            {"ip": ip, "count": int(count)}
            for ip, count in frame.src_ip.value_counts().head(5).items()
        ]
    total = db.scalar(select(func.count(Event.id)))
    suspicious = db.scalar(select(func.count(Event.id)).where(Event.risk >= 40))
    high = db.scalar(select(func.count(Event.id)).where(Event.risk >= 70))
    blocks = db.scalar(select(func.count(Block.id)).where(Block.state == "active"))
    return {
        "total": total,
        "suspicious": suspicious,
        "high": high,
        "blocks": blocks,
        "severity": [
            {
                "name": s,
                "value": db.scalar(
                    select(func.count(Event.id)).where(Event.severity == s)
                ),
            }
            for s in ["critical", "high", "medium", "low"]
        ],
        "timeline": timeline[-24:],
        "sources": sources,
        "recent": [serialize(e) for e in rows[:7]],
        "origins": {
            o: db.scalar(select(func.count(Event.id)).where(Event.origin == o))
            for o in ["simulation", "replay", "live"]
        },
        "analytics_window": "Latest 10,000 events; timeline shows latest 24 five-minute buckets",
        "network_health": "Unmeasured — virtual topology only",
        "status": status_payload(db),
    }


@app.post("/api/events")
def event_ingest(body: EventInput, user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"ingest:{user.id}", 60)
    return serialize(ingest(db, body, "simulation", "manual-test"))


@app.post("/api/events/sample")
def load_sample(user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"sample:{user.id}", 4)
    for item in sample_events():
        ingest(db, item)
    audit(db, user.username, "sample_loaded", count=48)
    db.commit()
    return {"count": 48, "origin": "simulation"}


@app.post("/api/events/import")
async def import_events(
    file: UploadFile = File(...), user=Depends(admin), db=Depends(db_session)
):
    limiter.check(f"import:{user.id}", 5)
    raw = await file.read(2_000_001)
    await file.close()
    if len(raw) > 2_000_000:
        raise HTTPException(413, "Maximum import size is 2 MB")
    try:
        data = raw.decode("utf-8-sig")
        if (file.filename or "").lower().endswith(".csv"):
            rows = list(csv.DictReader(io.StringIO(data)))
            for row in rows:
                row["features"] = {
                    k: row.pop(k)
                    for k in list(row)
                    if k in Features.model_fields and row[k] != ""
                }
                for k in ["src_port", "dst_port", "signature"]:
                    if row.get(k) == "":
                        row.pop(k)
        else:
            try:
                decoded = json.loads(data)
                rows = decoded if isinstance(decoded, list) else [decoded]
            except json.JSONDecodeError:
                rows = [json.loads(line) for line in data.splitlines() if line.strip()]
        if not 1 <= len(rows) <= 1000:
            raise ValueError("Import must contain 1–1000 records")
        # Validate the complete batch before any ingestion/automatic side effects.
        parsed = [
            (from_eve(row), "suricata-import")
            if "dest_ip" in row
            else (from_zeek(row), "zeek-import")
            if "id.orig_h" in row
            else (EventInput.model_validate({**row, "raw_record": row}), "file-import")
            for row in rows
        ]
    except (ValueError, KeyError, TypeError, UnicodeError, ValidationError) as exc:
        raise HTTPException(422, f"Invalid import: {str(exc)[:180]}")
    for item, source in sorted(parsed, key=lambda r: r[0].timestamp):
        ingest(db, item, "replay", source)
    monitor["mode"] = "replay" if not monitor["running"] else monitor["mode"]
    audit(db, user.username, "events_imported", count=len(parsed), origin="replay")
    db.commit()
    return {"count": len(parsed), "origin": "replay"}


@app.get("/api/events")
def events(
    q: str = Query("", max_length=100),
    severity: str = "",
    origin: str = "",
    suspicious: bool = False,
    sort: Literal["timestamp", "risk"] = "timestamp",
    direction: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    size: int = Query(15, ge=1, le=100),
    user=Depends(admin),
    db=Depends(db_session),
):
    query = select(Event)
    if q:
        query = query.where(
            or_(
                Event.src_ip.contains(q),
                Event.dst_ip.contains(q),
                Event.rule.contains(q),
                Event.category.contains(q),
            )
        )
    if severity:
        query = query.where(Event.severity == severity)
    if origin:
        query = query.where(Event.origin == origin)
    if suspicious:
        query = query.where(Event.risk >= 40)
    count = db.scalar(select(func.count()).select_from(query.subquery()))
    col = getattr(Event, sort)
    rows = db.scalars(
        query.order_by(
            col.desc() if direction == "desc" else col.asc(), Event.id.desc()
        )
        .offset((page - 1) * size)
        .limit(size)
    )
    return {
        "items": [serialize(e) for e in rows],
        "total": count,
        "page": page,
        "size": size,
    }


@app.get("/api/events/{id}")
def event_detail(id: int, user=Depends(admin), db=Depends(db_session)):
    event = db.get(Event, id)
    if not event:
        raise HTTPException(404, "Event not found")
    result = serialize(event)
    if event.flow_id:
        from backend.traffic_api import journey
        from backend.db import Flow

        result["journey"] = journey(db, db.get(Flow, event.flow_id))
    return result


class ReviewInput(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]


@app.patch("/api/events/{id}")
def review(id: int, body: ReviewInput, user=Depends(admin), db=Depends(db_session)):
    event = db.get(Event, id)
    if not event:
        raise HTTPException(404, "Event not found")
    event.status = body.status
    audit(db, user.username, "event_reviewed", event_id=id, status=body.status)
    db.commit()
    return serialize(event)


@app.get("/api/investigate/{ip}")
def investigate(ip: IPvAnyAddress, user=Depends(admin), db=Depends(db_session)):
    expire_blocks(db)
    ip = str(ip)
    query = select(Event).where(Event.src_ip == ip).order_by(Event.timestamp.desc())
    rows = list(db.scalars(query.limit(1000)))
    first = db.scalar(select(func.min(Event.timestamp)).where(Event.src_ip == ip))
    last = db.scalar(select(func.max(Event.timestamp)).where(Event.src_ip == ip))
    return {
        "ip": ip,
        "count": db.scalar(select(func.count(Event.id)).where(Event.src_ip == ip)),
        "history_limit": 1000,
        "first_seen": aware(first) if first else None,
        "last_seen": aware(last) if last else None,
        "risk": db.scalar(select(func.max(Event.risk)).where(Event.src_ip == ip)) or 0,
        "events": [serialize(e) for e in rows],
        "ports": sorted({e.dst_port for e in rows if e.dst_port is not None}),
        "protocols": sorted({e.protocol for e in rows}),
        "devices": [
            serialize(d)
            for d in db.scalars(
                select(Device).where(Device.ip.in_([e.dst_ip for e in rows]))
            )
        ],
        "blocks": [
            serialize(b) for b in db.scalars(select(Block).where(Block.ip == ip))
        ],
        "notes": [
            serialize(n)
            for n in db.scalars(
                select(Note).where(Note.ip == ip).order_by(Note.id.desc())
            )
        ],
        "attribution": "An observed IP is not proof of identity. NAT, VPNs, proxies, shared addresses and spoofing affect attribution.",
        "recommendations": [
            "Correlate with authentication and endpoint logs.",
            "Confirm asset ownership and business context.",
            "Review evidence and allowlists before blocking.",
        ],
    }


class NoteInput(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@app.post("/api/investigate/{ip}/notes")
def note(
    ip: IPvAnyAddress, body: NoteInput, user=Depends(admin), db=Depends(db_session)
):
    db.add(Note(ip=str(ip), text=body.text, author=user.username))
    audit(db, user.username, "investigation_note", ip=str(ip))
    db.commit()
    return {"ok": True}


@app.get("/api/blocks")
def blocks(q: str = "", state: str = "", user=Depends(admin), db=Depends(db_session)):
    expire_blocks(db)
    query = select(Block).where(Block.ip.contains(q))
    if state:
        query = query.where(Block.state == state)
    return [
        serialize(b) for b in db.scalars(query.order_by(Block.id.desc()).limit(1000))
    ]


@app.post("/api/blocks/preview")
def preview_block(body: BlockInput, user=Depends(admin), db=Depends(db_session)):
    from backend.security import validate_block_ip

    ip = validate_block_ip(str(body.ip))
    return {
        "ip": ip,
        "adapter": adapter().name,
        "duration_minutes": body.minutes,
        "reason": body.reason,
        "permitted_mode": config(db)["mode"] != "detection",
        "effect": "No packets affected"
        if adapter().name == "simulated"
        else "Drops traffic from this source on configured lab chains",
    }


@app.post("/api/blocks")
def block(body: BlockInput, user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"enforce:{user.id}", 10)
    if not body.confirmed:
        raise HTTPException(409, "Preview and confirmation required")
    from backend.db import PreventionDecision

    event = db.get(Event, body.event_id) if body.event_id else None
    if body.event_id and (not event or event.src_ip != str(body.ip)):
        raise HTTPException(422, "Selected alert must match the block source")
    if event and event.risk < config(db)["threshold"]:
        raise HTTPException(409, "Selected detection is below the configured threshold")
    try:
        row = create_block(db, body.ip, body.reason, body.minutes, user.username, event)
    except HTTPException as exc:
        if event:
            db.add(
                PreventionDecision(
                    event_id=event.id,
                    flow_id=event.flow_id,
                    policy=config(db)["mode"],
                    outcome="rejected_or_failed",
                    steps=[
                        {"stage": "Administrator request", "result": user.username},
                        {"stage": "Safeguard or adapter", "result": str(exc.detail)},
                    ],
                )
            )
            db.commit()
        raise
    if event:
        db.add(
            PreventionDecision(
                event_id=event.id,
                flow_id=event.flow_id,
                block_id=row.id,
                policy=config(db)["mode"],
                outcome="simulated"
                if row.adapter == "simulated"
                else "set_membership_verified",
                steps=[
                    {
                        "stage": "Detection",
                        "result": f"Event {event.id}; {event.rule}; risk {event.risk}",
                    },
                    {"stage": "Administrator approval", "result": user.username},
                    {
                        "stage": "Safeguards",
                        "result": "Validated source, policy, exclusions and adapter",
                    },
                    {
                        "stage": "Adapter",
                        "result": "SIMULATED — NO REAL PACKETS WERE BLOCKED"
                        if row.adapter == "simulated"
                        else "Kernel set membership verified; actual packet drop NOT VERIFIED",
                    },
                ],
            )
        )
        db.commit()
    return serialize(row)


@app.delete("/api/blocks/{id}")
def unblock(
    id: int, confirmed: bool = False, user=Depends(admin), db=Depends(db_session)
):
    limiter.check(f"enforce:{user.id}", 10)
    if not confirmed:
        raise HTTPException(409, "Confirmation required")
    row = db.get(Block, id)
    if not row:
        raise HTTPException(404, "Block not found")
    remove_block(db, row, user.username)
    return serialize(row)


@app.post("/api/blocks/{id}/reconcile")
def reconcile(
    id: int, confirmed: bool = False, user=Depends(admin), db=Depends(db_session)
):
    from backend.firewall import reconcile_block

    limiter.check(f"reconcile:{user.id}", 10)
    if not confirmed:
        raise HTTPException(409, "Confirm read-only reconciliation")
    row = db.get(Block, id)
    if not row:
        raise HTTPException(404, "Block not found")
    evidence = reconcile_block(db, row, user.username)
    return {**serialize(row), "reconciliation_evidence": evidence}


@app.get("/api/enforcement")
def enforcement(user=Depends(admin), db=Depends(db_session)):
    return {
        **config(db),
        "adapter": adapter().name,
        "protected": os.getenv("PROTECTED_CIDRS", "127.0.0.0/8,::1/128,10.10.0.0/24"),
        "allowlist": os.getenv("ALLOWLIST", ""),
    }


@app.post("/api/enforcement/preview")
def preview_config(
    body: EnforcementConfig, user=Depends(admin), db=Depends(db_session)
):
    return {
        "before": config(db),
        "after": body.model_dump(exclude={"confirmed"}),
        "adapter": adapter().name,
        "effect": "Automatic qualifying detections will request temporary blocks."
        if body.mode == "automatic"
        else "Administrator approval required."
        if body.mode == "manual"
        else "Observe only; existing blocks remain until removal or expiry.",
    }


@app.put("/api/enforcement")
def update_config(body: EnforcementConfig, user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"config:{user.id}", 10)
    if not body.confirmed:
        raise HTTPException(409, "Preview and confirmation required")
    if (
        body.mode != "detection"
        and adapter().name != "simulated"
        and not adapter().ready()
    ):
        raise HTTPException(
            409, "Real adapter is not explicitly configured and verified"
        )
    row = db.get(Setting, "enforcement") or Setting(key="enforcement")
    row.value = body.model_dump(exclude={"confirmed"})
    db.add(row)
    audit(db, user.username, "enforcement_configured", **row.value)
    db.commit()
    return row.value


@app.get("/api/network")
def network(user=Depends(admin), db=Depends(db_session)):
    return {
        "devices": [serialize(d) for d in db.scalars(select(Device))],
        "connections": [
            {
                **serialize(c),
                "allowed": (
                    db.get(AccessRule, c.id).allowed
                    if db.get(AccessRule, c.id)
                    else True
                ),
                "allowed_ports": db.get(AccessRule, c.id).allowed_ports
                if db.get(AccessRule, c.id)
                else None,
                "protocol": db.get(AccessRule, c.id).protocol
                if db.get(AccessRule, c.id)
                else None,
            }
            for c in db.scalars(select(Connection))
        ],
    }


@app.post("/api/network/devices")
def device(body: DeviceInput, user=Depends(admin), db=Depends(db_session)):
    if db.scalar(select(func.count(Device.id))) >= 100:
        raise HTTPException(409, "Virtual topology limited to 100 devices")
    row = Device(**body.model_dump(mode="json"))
    db.add(row)
    audit(db, user.username, "device_added", id=body.id)
    db.commit()
    return serialize(row)


@app.put("/api/network/devices/{id}")
def update_device(
    id: str, body: DeviceInput, user=Depends(admin), db=Depends(db_session)
):
    row = db.get(Device, id)
    if not row:
        raise HTTPException(404, "Device not found")
    if id != body.id:
        raise HTTPException(422, "Device IDs are immutable")
    for key, value in body.model_dump(mode="json").items():
        setattr(row, key, value)
    audit(db, user.username, "device_updated", id=id)
    db.commit()
    return serialize(row)


@app.delete("/api/network/devices/{id}")
def delete_device(id: str, user=Depends(admin), db=Depends(db_session)):
    row = db.get(Device, id)
    if not row:
        raise HTTPException(404, "Device not found")
    for edge in db.scalars(
        select(Connection).where(or_(Connection.source == id, Connection.target == id))
    ):
        rule = db.get(AccessRule, edge.id)
        if rule:
            db.delete(rule)
        db.delete(edge)
    db.delete(row)
    audit(db, user.username, "device_removed", id=id)
    db.commit()
    return {"ok": True}


@app.post("/api/network/connections")
def connection(body: ConnectionInput, user=Depends(admin), db=Depends(db_session)):
    if (
        body.source == body.target
        or not db.get(Device, body.source)
        or not db.get(Device, body.target)
    ):
        raise HTTPException(422, "Select two existing distinct virtual devices")
    if db.scalar(
        select(Connection).where(
            Connection.source == body.source, Connection.target == body.target
        )
    ):
        raise HTTPException(409, "Connection already exists")
    edge = Connection(source=body.source, target=body.target)
    db.add(edge)
    db.flush()
    db.add(
        AccessRule(
            connection_id=edge.id,
            allowed=body.allowed,
            allowed_ports=body.allowed_ports,
            protocol=body.protocol,
        )
    )
    audit(db, user.username, "connection_added", source=body.source, target=body.target)
    db.commit()
    return serialize(edge)


class AccessInput(BaseModel):
    allowed: bool
    allowed_ports: list[int] | None = Field(None, max_length=100)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None


@app.patch("/api/network/connections/{id}")
def access(id: int, body: AccessInput, user=Depends(admin), db=Depends(db_session)):
    if not db.get(Connection, id):
        raise HTTPException(404, "Connection not found")
    row = db.get(AccessRule, id) or AccessRule(connection_id=id)
    row.allowed = body.allowed
    if body.allowed_ports is not None and any(
        not 0 <= p <= 65535 for p in body.allowed_ports
    ):
        raise HTTPException(422, "Invalid modeled service port")
    # A boolean-only toggle preserves existing service constraints.
    if "allowed_ports" in body.model_fields_set:
        row.allowed_ports = body.allowed_ports
    if "protocol" in body.model_fields_set:
        row.protocol = body.protocol
    db.add(row)
    audit(
        db, user.username, "virtual_access_changed", connection=id, allowed=body.allowed
    )
    db.commit()
    return {"ok": True}


@app.delete("/api/network/connections/{id}")
def delete_connection(id: int, user=Depends(admin), db=Depends(db_session)):
    row = db.get(Connection, id)
    if not row:
        raise HTTPException(404, "Connection not found")
    rule = db.get(AccessRule, id)
    if rule:
        db.delete(rule)
    db.delete(row)
    audit(db, user.username, "connection_removed", connection=id)
    db.commit()
    return {"ok": True}


@app.post("/api/twin/analyze")
def twin(body: SimulationInput, user=Depends(admin), db=Depends(db_session)):
    limiter.check(f"twin:{user.id}", 20)
    device_ids = set(db.scalars(select(Device.id)))
    edge_ids = set(db.scalars(select(Connection.id)))
    if not set(body.patched + body.isolated).issubset(device_ids) or not set(
        body.blocked_connections
    ).issubset(edge_ids):
        raise HTTPException(422, "Scenario references unknown devices or connections")
    try:
        baseline = analyze(db, body.initial, protocol=body.protocol, port=body.dst_port)
        modified = analyze(
            db,
            body.initial,
            body.blocked_connections,
            body.patched,
            body.isolated,
            body.protocol,
            body.dst_port,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    result = {
        "baseline": baseline,
        "modified": modified,
        "changes": body.model_dump(),
        "mode": "simulation",
        "topology": {
            "devices": [serialize(d) for d in db.scalars(select(Device))],
            "connections": [
                {
                    **serialize(c),
                    "allowed": db.get(AccessRule, c.id).allowed
                    if db.get(AccessRule, c.id)
                    else True,
                }
                for c in db.scalars(select(Connection))
            ],
        },
    }
    db.add(Scenario(name=body.name, data=result))
    audit(db, user.username, "scenario_analyzed", name=body.name)
    db.commit()
    return result


@app.get("/api/twin/scenarios")
def scenarios(user=Depends(admin), db=Depends(db_session)):
    return [
        serialize(s)
        for s in db.scalars(select(Scenario).order_by(Scenario.id.desc()).limit(30))
    ]


@app.get("/api/ml/metrics")
def metrics(user=Depends(admin)):
    bundle = ml.load()
    return {
        "available": bool(bundle),
        "metrics": bundle["metrics"] if bundle else None,
        "instructions": "python -m backend.ml",
    }


class PredictionInput(BaseModel):
    features: Features
    dst_port: int | None = Field(None, ge=0, le=65535)
    feature_schema: str | None = Field(None, max_length=50)


@app.post("/api/ml/predict")
def prediction(body: PredictionInput, user=Depends(admin)):
    return ml.predict(
        body.features.model_dump(exclude_unset=True), body.dst_port, body.feature_schema
    )


@app.get("/api/audit")
def logs(user=Depends(admin), db=Depends(db_session)):
    return [
        serialize(a)
        for a in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(200))
    ]


def report_data(db, ip=None):
    from backend.db import Flow

    query = select(Event).order_by(Event.timestamp.desc()).limit(10000)
    if ip:
        query = (
            select(Event)
            .where(Event.src_ip == ip)
            .order_by(Event.timestamp.desc())
            .limit(10000)
        )
    events = [serialize(e) for e in db.scalars(query)]
    bundle = ml.load()
    scenario = db.scalar(select(Scenario).order_by(Scenario.id.desc()))
    return {
        "generated_at": now().isoformat(),
        "scope": "Latest 10,000 matching events; all origins explicitly labeled",
        "ip": ip,
        "events": events,
        "flows": [
            serialize(f)
            for f in db.scalars(
                select(Flow)
                .where(Flow.id.in_([e["flow_id"] for e in events if e.get("flow_id")]))
                .limit(5000)
            )
        ]
        if events
        else [],
        "summary": {
            "events": len(events),
            "high_risk": sum(e["risk"] >= 70 for e in events),
            "false_positive_reviews": sum(
                e["status"] == "false_positive" for e in events
            ),
        },
        "blocks": [
            serialize(b)
            for b in db.scalars(
                select(Block).where(Block.ip == ip) if ip else select(Block)
            )
        ],
        "audit": [
            serialize(a)
            for a in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(200))
        ]
        if not ip
        else [],
        "notes": [serialize(n) for n in db.scalars(select(Note).where(Note.ip == ip))]
        if ip
        else [],
        "twin": serialize(scenario) if scenario else None,
        "ml": bundle["metrics"] if bundle else "unavailable",
        "limitations": "Simulated blocks do not affect packets. IP is not identity. Graph paths are modeled possibilities. Model metrics apply only to the stated evaluation dataset.",
    }


@app.get("/api/reports")
def report(user=Depends(admin), db=Depends(db_session)):
    expire_blocks(db)
    return report_data(db)


@app.get("/api/reports/export")
def export(
    format: Literal["json", "csv", "pdf"] = "json",
    ip: IPvAnyAddress | None = None,
    user=Depends(admin),
    db=Depends(db_session),
):
    expire_blocks(db)
    data = report_data(db, str(ip) if ip else None)
    audit(
        db, user.username, "report_exported", format=format, ip=str(ip) if ip else None
    )
    db.commit()
    if format == "json":
        content, media = json.dumps(data, indent=2), "application/json"
    elif format == "csv":
        buffer = io.StringIO()
        fields = [
            "id",
            "flow_id",
            "record_key",
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "category",
            "origin",
            "detection_source",
            "rule",
            "severity",
            "risk",
            "ml_score",
            "confidence",
            "evidence",
            "action",
            "status",
        ]
        writer = csv.DictWriter(buffer, fields, extrasaction="ignore")
        writer.writeheader()
        for event in data["events"]:
            # Spreadsheet formula injection protection for user-controlled text.
            writer.writerow(
                {
                    k: (
                        "'" + str(v)
                        if str(v).startswith(("=", "+", "-", "@", "\t", "\r"))
                        else v
                    )
                    for k, v in event.items()
                }
            )
        content, media = buffer.getvalue(), "text/csv"
    else:
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from xml.sax.saxutils import escape

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer)
        styles = getSampleStyleSheet()
        paragraphs = [
            Paragraph("CyberTwin AI — Research Security Report", styles["Title"])
        ]
        # Include complete evidence/sections in paginated, wrapped paragraphs.
        for heading, value in data.items():
            paragraphs += [
                Spacer(1, 12),
                Paragraph(escape(heading.upper()), styles["Heading2"]),
            ]
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                payload = (
                    json.dumps(entry, ensure_ascii=True, default=str)
                    if not isinstance(entry, str)
                    else entry
                )
                paragraphs.append(Paragraph(escape(payload), styles["BodyText"]))
        doc.build(paragraphs)
        content, media = buffer.getvalue(), "application/pdf"
    return Response(
        content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="cybertwin-report.{format}"'
        },
    )


# Production serves the built SPA and API on the same origin; no external service required.
dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
walkthrough = Path(__file__).resolve().parents[1] / "deliverables" / "video"
if walkthrough.is_dir():
    # Public presentation artifacts only; no credentials, logs or DB files.
    app.mount(
        "/walkthrough",
        StaticFiles(directory=walkthrough, html=True),
        name="walkthrough",
    )

if dist.is_dir():
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/")
    def index():
        return FileResponse(dist / "index.html")
