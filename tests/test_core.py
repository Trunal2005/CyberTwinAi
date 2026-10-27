from datetime import timedelta
import json
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from backend.db import AccessRule, Audit, Block, Event, SessionLocal, Setting, now
from backend.detection import classify, from_eve
from backend.firewall import expire_blocks
from backend.schemas import EventInput
from backend.security import validate_block_ip
from backend.seed import seed_topology
from backend.twin import analyze


def event(**changes):
    return {
        "src_ip": "192.0.2.44",
        "dst_ip": "10.10.1.10",
        "dst_port": 22,
        "features": {"failed_auth": 18},
        **changes,
    }


def manual(auth):
    return auth.put("/api/enforcement", json={"mode": "manual", "confirmed": True})


def test_auth_required(client):
    for path in [
        "/api/events",
        "/api/blocks",
        "/api/network",
        "/api/reports",
        "/api/status",
        "/api/audit",
    ]:
        assert client.get(path).status_code == 401
    assert (
        client.post(
            "/api/blocks",
            json={"ip": "192.0.2.44", "reason": "test block", "confirmed": True},
        ).status_code
        == 401
    )
    assert client.get("/api/health").status_code == 200


def test_login_session_logout(auth):
    assert auth.get("/api/auth/me").json()["role"] == "admin"
    assert "HttpOnly" in auth.cookies.get("ct_session", "") or auth.cookies.get(
        "ct_session"
    )
    assert auth.post("/api/auth/logout").status_code == 200
    assert auth.get("/api/events").status_code == 401


def test_login_rate_limit(client):
    for _ in range(5):
        assert (
            client.post(
                "/api/auth/login", json={"username": "unknown", "password": "wrong"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/auth/login", json={"username": "unknown", "password": "wrong"}
        ).status_code
        == 429
    )


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "224.0.0.1",
        "fe80::1",
        "10.10.0.10",
        "198.51.100.99",
        "::ffff:127.0.0.1",
        "not-an-ip",
    ],
)
def test_protected_addresses(client, ip):
    with pytest.raises(HTTPException):
        validate_block_ip(ip)


def test_valid_ipv4_ipv6(client):
    assert validate_block_ip("192.0.2.44") == "192.0.2.44"
    assert validate_block_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_detection_logic():
    risk, severity, rule, evidence = classify(EventInput.model_validate(event()), [])
    assert risk == 95 and severity == "critical" and rule == "AUTH-001"
    assert "18" in evidence[0]
    assert classify(EventInput.model_validate(event(features={})), [])[0] == 0


def test_port_scan_event_time_and_origin(auth):
    for port in range(20, 28):
        result = auth.post("/api/events", json=event(dst_port=port, features={})).json()
    assert result["rule"] == "SCAN-001"
    assert result["risk"] == 78
    # Replayed observations are not correlated against simulated history.
    upload = auth.post(
        "/api/events/import",
        files={
            "file": (
                "events.json",
                json.dumps([event(dst_port=90, features={})]),
                "application/json",
            )
        },
    )
    assert upload.status_code == 200
    replay = auth.get("/api/events?origin=replay").json()["items"][0]
    assert replay["risk"] == 0


def test_api_validation_filters_review(auth):
    assert auth.post("/api/events", json=event(src_ip="bad")).status_code == 422
    assert auth.post("/api/events", json=event(dst_port=70000)).status_code == 422
    e = auth.post("/api/events", json=event()).json()
    assert (
        e["src_ip"] == "192.0.2.44"
        and e["origin"] == "simulation"
        and e["ml_score"] is None
    )
    assert (
        auth.get("/api/events?severity=critical&q=192.0.2.44&size=1").json()["total"]
        == 1
    )
    assert (
        auth.patch(
            f"/api/events/{e['id']}", json={"status": "false_positive"}
        ).status_code
        == 200
    )
    assert auth.get("/api/reports").json()["summary"]["false_positive_reviews"] == 1
    assert auth.get("/api/events/99999").status_code == 404
    assert e["timestamp"].endswith("+00:00") or e["timestamp"].endswith("Z")
    assert auth.get("/api/events?page=0").status_code == 422


def test_simulated_enforcement_confirmation_expiry_audit(auth):
    payload = {
        "ip": "192.0.2.44",
        "reason": "Investigated lab signal",
        "minutes": 1,
        "confirmed": True,
    }
    assert auth.post("/api/blocks", json=payload).status_code == 409
    assert manual(auth).status_code == 200
    assert (
        auth.post("/api/blocks", json={**payload, "confirmed": False}).status_code
        == 409
    )
    block = auth.post("/api/blocks", json=payload).json()
    assert (
        block["state"] == "active"
        and block["adapter"] == "simulated"
        and not block["verified"]
    )
    assert auth.get("/api/status").json()["enforcement_enabled"] is False
    assert auth.post("/api/blocks", json=payload).json()["id"] == block["id"]
    with SessionLocal() as db:
        db.get(Block, block["id"]).expires = now() - timedelta(seconds=1)
        db.commit()
        expire_blocks(db)
        assert db.get(Block, block["id"]).state == "expired"
        assert "block_expired" in [a.action for a in db.scalars(select(Audit))]


def test_automatic_safeguards(auth):
    auth.put(
        "/api/enforcement",
        json={"mode": "automatic", "threshold": 85, "confirmed": True},
    )
    result = auth.post("/api/events", json=event()).json()
    assert result["action"] == "simulated block"
    protected = auth.post("/api/events", json=event(src_ip="10.10.0.10")).json()
    assert protected["action"] == "block prevented"
    assert len(auth.get("/api/blocks").json()) == 1


def test_unblock_confirmation(auth):
    manual(auth)
    block = auth.post(
        "/api/blocks",
        json={"ip": "192.0.2.44", "reason": "lab signal review", "confirmed": True},
    ).json()
    assert auth.delete(f"/api/blocks/{block['id']}").status_code == 409
    assert (
        auth.delete(f"/api/blocks/{block['id']}?confirmed=true").json()["state"]
        == "removed"
    )


def test_failed_adapter_record_and_real_gates(auth, monkeypatch):
    import backend.firewall as fw

    manual(auth)

    def fail(*args):
        raise RuntimeError("lab failure")

    monkeypatch.setattr(fw.SimulatedAdapter, "block", fail)
    assert (
        auth.post(
            "/api/blocks",
            json={"ip": "192.0.2.44", "reason": "reviewed signal", "confirmed": True},
        ).status_code
        == 502
    )
    assert auth.get("/api/blocks").json()[0]["state"] == "error"
    monkeypatch.setenv("FIREWALL_ADAPTER", "nftables")
    assert (
        auth.put(
            "/api/enforcement", json={"mode": "automatic", "confirmed": True}
        ).status_code
        == 409
    )


def test_graph_analysis_and_comparison(auth):
    with SessionLocal() as db:
        seed_topology(db)
        baseline = analyze(db, "web")
        assert "Research database" in baseline["critical_assets"]
        assert baseline["path_count"] == 3
        isolated = analyze(db, "web", isolated=["web"])
        assert isolated["path_count"] == 0 and isolated["risk"] == 0
    response = auth.post(
        "/api/twin/analyze", json={"initial": "web", "patched": ["app", "db"]}
    )
    assert response.status_code == 200
    assert response.json()["modified"]["risk"] < response.json()["baseline"]["risk"]
    assert (
        auth.post("/api/twin/analyze", json={"initial": "missing"}).status_code == 422
    )
    assert (
        auth.post("/api/twin/analyze", json={"patched": ["missing"]}).status_code == 422
    )
    assert len(auth.get("/api/twin/scenarios").json()) == 1


def test_topology_crud(auth):
    body = {
        "id": "test",
        "name": "test asset",
        "kind": "server",
        "ip": "10.99.0.1",
        "criticality": 4,
        "vulnerability": 8,
    }
    assert auth.post("/api/network/devices", json=body).status_code == 200
    assert auth.post("/api/network/devices", json=body).status_code == 409
    assert (
        auth.put("/api/network/devices/test", json={**body, "vulnerability": 0}).json()[
            "vulnerability"
        ]
        == 0
    )
    assert (
        auth.post(
            "/api/network/connections", json={"source": "test", "target": "test"}
        ).status_code
        == 422
    )
    assert auth.delete("/api/network/devices/test").status_code == 200


def test_import_atomic_validation_and_provenance(auth):
    response = auth.post(
        "/api/events/import",
        files={
            "file": (
                "test.json",
                json.dumps([event(), event(src_ip="bad")]),
                "application/json",
            )
        },
    )
    assert response.status_code == 422
    assert auth.get("/api/events").json()["total"] == 0
    assert (
        auth.post(
            "/api/events/import",
            files={
                "file": (
                    "test.json",
                    json.dumps([event(origin="live")]),
                    "application/json",
                )
            },
        ).status_code
        == 200
    )
    assert auth.get("/api/events").json()["items"][0]["origin"] == "replay"
    assert (
        auth.post(
            "/api/events/import",
            files={"file": ("test.json", b"x" * 2_000_001, "application/json")},
        ).status_code
        == 413
    )


def test_suricata_mapping():
    row = from_eve(
        {
            "timestamp": now().isoformat(),
            "src_ip": "192.0.2.44",
            "dest_ip": "10.10.1.10",
            "proto": "TCP",
            "event_type": "alert",
            "alert": {"signature": "Lab alert", "severity": 1},
        }
    )
    assert classify(row, [])[0] == 95


def test_reports_investigation_notes_exports(auth):
    auth.post("/api/events", json=event())
    assert (
        auth.post(
            "/api/investigate/192.0.2.44/notes",
            json={"text": "Reviewed authentication logs"},
        ).status_code
        == 200
    )
    data = auth.get("/api/investigate/192.0.2.44").json()
    assert (
        data["count"] == 1
        and data["notes"][0]["text"] == "Reviewed authentication logs"
    )
    assert (
        auth.get("/api/reports/export?format=json").json()["events"][0]["origin"]
        == "simulation"
    )
    assert "src_ip" in auth.get("/api/reports/export?format=csv").text
    assert auth.get("/api/reports/export?format=pdf").content.startswith(b"%PDF")


def test_csrf_and_truthful_status(auth):
    assert (
        auth.post(
            "/api/events/sample", headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    status = auth.get("/api/status").json()
    assert (
        status["mode"] == "SIMULATION"
        and status["integrations"]["Suricata"] == "unconfigured"
    )
    assert (
        auth.post("/api/monitor", json={"running": True, "mode": "live"}).status_code
        == 409
    )
    assert (
        auth.post("/api/monitor", json={"running": True, "mode": "simulation"}).json()[
            "monitoring"
        ]
        is True
    )
    assert (
        auth.post("/api/monitor", json={"running": False, "mode": "simulation"}).json()[
            "monitoring"
        ]
        is False
    )


def test_ml_reproducible_and_separate(auth, monkeypatch, tmp_path):
    from backend import ml

    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "model.joblib"))
    metrics = ml.train()
    assert (
        metrics["test_samples"] == 600
        and sum(map(sum, metrics["confusion_matrix"])) == 600
    )
    first = auth.post(
        "/api/ml/predict", json={"features": {"frequency": 120, "failed_auth": 18}}
    ).json()
    assert first["available"] and 0 <= first["score"] <= 100
    assert auth.get("/api/ml/metrics").json()["available"]
    assert ml.train()["confusion_matrix"] == metrics["confusion_matrix"]


def test_live_collector_freshness_and_oversized_line(auth, monkeypatch, tmp_path):
    import asyncio
    import backend.main as main
    from tests.conftest import original_worker

    log = tmp_path / "eve.json"

    def record(timestamp):
        return (
            json.dumps(
                {
                    "timestamp": timestamp.isoformat(),
                    "src_ip": "192.0.2.44",
                    "dest_ip": "10.10.1.10",
                    "event_type": "flow",
                    "proto": "TCP",
                }
            )
            + "\n"
        )

    log.write_text(
        "x" * 70000 + "\n" + record(now() - timedelta(days=1)) + record(now()),
        encoding="utf-8",
    )
    monkeypatch.setenv("SURICATA_EVE_PATH", str(log))
    monkeypatch.setenv("SURICATA_LIVE_CONFIRMED", "true")
    main.monitor.update(running=True, mode="live", error=None, last_live=None)
    main.collector.update(offset=0, inode=None, discarding=False)

    async def stop_after_pass(seconds):
        raise asyncio.CancelledError()

    monkeypatch.setattr(main.asyncio, "sleep", stop_after_pass)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(original_worker())
    assert auth.get("/api/events?origin=live").json()["total"] == 1
    assert auth.get("/api/events?origin=replay").json()["total"] == 1
    assert auth.get("/api/status").json()["mode"] == "LIVE MONITORING"
    main.monitor["last_live"] = now() - timedelta(minutes=5)
    assert auth.get("/api/status").json()["mode"] == "LIVE SOURCE WAITING"
    assert auth.get("/api/status").json()["integrations"]["Suricata"] == "disconnected"


def test_nft_requires_hooked_drop_rules(client, monkeypatch):
    import backend.firewall as fw

    monkeypatch.setattr(fw.platform, "system", lambda: "Linux")
    monkeypatch.setenv("REAL_ENFORCEMENT", "true")
    obj = fw.NftablesAdapter()
    # A named set or unused rule without hooks must not enable real enforcement.
    monkeypatch.setattr(obj, "run", lambda *args: json.dumps({"nftables": []}))
    assert not obj.ready()
    objects = []
    for hook in ["input", "forward"]:
        objects.append({"chain": {"name": hook, "type": "filter", "hook": hook}})
        for version, protocol in [(4, "ip"), (6, "ip6")]:
            objects.append(
                {
                    "rule": {
                        "chain": hook,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {
                                            "protocol": protocol,
                                            "field": "saddr",
                                        }
                                    },
                                    "right": f"@blocked{version}",
                                }
                            },
                            {"drop": None},
                        ],
                    }
                }
            )
    monkeypatch.setattr(obj, "run", lambda *args: json.dumps({"nftables": objects}))
    assert obj.ready()


def test_db_constraints_and_migrations(client, tmp_path):
    import os
    import subprocess
    import sys
    from sqlalchemy import create_engine, inspect

    url = "sqlite:///" + str(tmp_path / "migrated.db").replace("\\", "/")
    env = {**os.environ, "DATABASE_URL": url}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    engine = create_engine(url)
    inspector = inspect(engine)
    from backend.db import Base

    assert set(inspector.get_table_names()) == set(Base.metadata.tables) | {
        "alembic_version"
    }
    assert "ck_event_origin" in {
        c["name"] for c in inspector.get_check_constraints("events")
    }
    assert "uq_connection_pair" in {
        c["name"] for c in inspector.get_unique_constraints("connections")
    }
    engine.dispose()


def test_nonadmin_and_rejected_enforcement_audit(auth):
    manual(auth)
    assert (
        auth.post(
            "/api/blocks",
            json={
                "ip": "127.0.0.1",
                "reason": "protected address test",
                "confirmed": True,
            },
        ).status_code
        == 422
    )
    assert any(
        a["action"] == "enforcement_request_rejected"
        for a in auth.get("/api/audit").json()
    )
    from backend.db import User

    with SessionLocal() as db:
        db.scalar(select(User).where(User.username == "tester")).role = "viewer"
        db.commit()
    assert auth.get("/api/blocks").status_code == 403


def test_real_enforcement_rejects_simulated_evidence(auth, monkeypatch):
    import backend.firewall as fw

    manual(auth)
    monkeypatch.setenv("FIREWALL_ADAPTER", "nftables")
    monkeypatch.setattr(fw.NftablesAdapter, "ready", lambda self: True)
    assert (
        auth.post("/api/events", json=event(origin="live")).json()["origin"]
        == "simulation"
    )
    response = auth.post(
        "/api/blocks",
        json={
            "ip": "192.0.2.44",
            "reason": "simulated evidence test",
            "confirmed": True,
        },
    )
    assert response.status_code == 409
    assert "live observation" in response.json()["error"]["message"]


def test_chunked_upload_bound_and_ml_validation(auth):
    result = auth.post(
        "/api/events",
        content=iter([b"x" * 1_500_000, b"x" * 1_500_000]),
        headers={"Content-Type": "application/json"},
    )
    assert result.status_code == 413
    from backend.ml import synthetic, validate_data

    x, y = synthetic()
    x.loc[0, "packets"] = float("nan")
    with pytest.raises(ValueError):
        validate_data(x, y)
