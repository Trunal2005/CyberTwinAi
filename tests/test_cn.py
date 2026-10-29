import io
import json
from datetime import timedelta
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from backend.db import Flow, Event, SessionLocal, now
from backend.detection import from_eve, ingest, classify
from backend.schemas import EventInput
from backend.firewall import NftablesAdapter
from pathlib import Path
from backend.pcap import parse_capture
from backend.observations import from_zeek


def test_nft_unblock_canonical_ipv6_regression(monkeypatch):
    obj = NftablesAdapter()
    deleted = []

    def run(*args):
        if args[0] == "delete":
            deleted.append(args)
            return ""
        return json.dumps(
            {
                "nftables": [
                    {
                        "set": {
                            "name": "blocked6",
                            "elem": []
                            if deleted
                            else [
                                {
                                    "elem": {
                                        "val": "2001:0db8:0:0:0:0:0:44",
                                        "timeout": 60,
                                    }
                                }
                            ],
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr(obj, "run", run)
    assert obj.unblock("2001:db8::44")
    assert len(deleted) == 1


def observation(**kw):
    return EventInput.model_validate(
        {
            "timestamp": now().isoformat(),
            "src_ip": "192.0.2.44",
            "dst_ip": "10.10.1.10",
            "dst_port": 443,
            "src_port": 45000,
            "features": {},
            **kw,
        }
    )


def test_scan_target_isolation_and_duplicate(auth):
    for i in range(8):
        row = auth.post(
            "/api/events",
            json=observation(dst_ip=f"10.10.1.{i + 1}", dst_port=20 + i).model_dump(
                mode="json"
            ),
        ).json()
    assert row["risk"] == 0
    payload = observation(dst_port=99).model_dump(mode="json")
    a = auth.post("/api/events", json=payload).json()
    b = auth.post("/api/events", json=payload).json()
    assert a["id"] == b["id"] and a["flow_id"] == b["flow_id"]


def test_missing_eve_values_remain_unavailable():
    raw = {
        "timestamp": now().isoformat(),
        "src_ip": "192.0.2.1",
        "dest_ip": "10.10.1.10",
        "proto": "UDP",
        "flow_id": 123,
        "event_type": "flow",
    }
    item = from_eve(raw)
    assert item.features.model_dump(exclude_unset=True) == {}
    assert item.raw_record == raw and item.sensor_flow_id == "123"
    assert classify(item, [])[0] == 0


@pytest.mark.parametrize("name", ["cn-demo.pcap", "cn-demo.pcapng"])
def test_capture_ipv4_ipv6_tcp_udp_icmp_and_counts(name):
    result = parse_capture(Path("samples", name).read_bytes())
    assert result["packets"] == 13 and len(result["observations"]) == 11
    rows = result["observations"]
    normal = next(
        r for r in rows if r["src_ip"] == "10.10.4.20" and r["dst_port"] == 443
    )
    assert (
        normal["features"]["packets"] == 3
        and normal["bytes_src"] + normal["bytes_dst"] == normal["features"]["bytes"]
    )
    assert normal["tcp_flags"] and "failed_auth" not in normal["features"]
    assert (
        "frequency" not in normal["features"]
        and "criticality" not in normal["features"]
    )
    assert {r["protocol"] for r in rows} >= {"TCP", "UDP", "ICMP"}
    assert any(
        r["src_ip"].startswith("2001:db8:")
        and r["src_port"] is None
        and r["dst_port"] is None
        for r in rows
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not a capture" * 10,
        Path("samples/cn-demo.pcap").read_bytes()[:-1],
        Path("samples/cn-demo.pcapng").read_bytes()[:-1],
    ],
)
def test_invalid_capture_is_rejected(raw):
    with pytest.raises(ValueError):
        parse_capture(raw)


def test_pcap_api_atomic_dedup_evidence_and_analytics(auth):
    raw = Path("samples/cn-demo.pcap").read_bytes()
    a = auth.post(
        "/api/traffic/pcap",
        files={"file": ("owned.pcap", raw, "application/octet-stream")},
    )
    assert a.status_code == 200, a.text
    assert a.json()["origin"] == "replay" and a.json()["new_events"] == 11
    b = auth.post(
        "/api/traffic/pcap",
        files={"file": ("retry.pcap", raw, "application/octet-stream")},
    )
    assert b.status_code == 200 and b.json()["new_events"] == 0
    t = auth.get("/api/traffic?origin=replay").json()
    assert t["total"] == 11 and t["analytics"]["packets"] == 13
    assert t["analytics"]["suspicious"] == 1
    assert auth.get("/api/traffic?protocol=UDP").json()["total"] == 1
    assert auth.get("/api/traffic?port=443").json()["total"] == 1
    f = next(
        r for r in t["items"] if r["src_ip"] == "192.0.2.44" and r["dst_port"] == 27
    )
    journey = auth.get(f"/api/flows/{f['id']}/journey").json()
    assert journey["events"][0]["rule"] == "SCAN-001"
    assert len(journey["events"][0]["detection"]["related_event_ids"]) == 7
    assert journey["events"][0]["observation"]["raw_record"]["capture_sha256"]
    assert journey["decisions"][0]["outcome"] == "detection_only"
    assert "MODELED PATH" in journey["path_label"]
    assert auth.get("/api/traffic/export?format=csv").status_code == 200
    assert auth.get("/api/traffic/export").json()["analytics"]["packets"] == 13
    assert (
        auth.post(
            "/api/traffic/pcap",
            files={"file": ("bad.pcap", b"invalid", "application/octet-stream")},
        ).status_code
        == 422
    )
    assert auth.get("/api/traffic").json()["total"] == 11


def test_traffic_timeline_accepts_mixed_timestamp_precision(auth):
    auth.post(
        "/api/events",
        json=observation(timestamp=now().replace(microsecond=123456)).model_dump(mode="json"),
    ).raise_for_status()
    auth.post(
        "/api/traffic/pcap",
        files={"file": ("owned.pcap", Path("samples/cn-demo.pcap").read_bytes(), "application/octet-stream")},
    ).raise_for_status()
    response = auth.get("/api/traffic")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 12
    assert sum(bucket["flows"] for bucket in data["analytics"]["timeline"]) == 12
    assert data["analytics"]["packets"] == 13


def test_sensor_cumulative_counters_and_raw_evidence(auth):
    raw = {
        "timestamp": now().isoformat(),
        "flow_id": 7,
        "event_type": "flow",
        "src_ip": "192.0.2.44",
        "dest_ip": "10.10.1.10",
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 3,
            "pkts_toclient": 2,
            "bytes_toserver": 180,
            "bytes_toclient": 120,
            "age": 2,
        },
    }

    def upload(r):
        return auth.post(
            "/api/events/import",
            files={"file": ("eve.json", json.dumps([r]), "application/json")},
        )

    assert upload(raw).status_code == 200
    raw["event_type"] = "alert"
    raw["alert"] = {
        "signature": "Owned test signature",
        "severity": 2,
        "signature_id": 99,
        "action": "allowed",
    }
    assert upload(raw).status_code == 200
    assert upload(raw).status_code == 200
    t = auth.get("/api/traffic").json()
    assert t["total"] == 1 and t["analytics"]["packets"] == 5
    events = auth.get("/api/events").json()
    assert events["total"] == 2
    assert (
        events["items"][0]["observation"]["raw_record"]["alert"]["signature_id"] == 99
    )


def test_zeek_json_semantics(auth):
    raw = {
        "ts": 1767225600,
        "uid": "sample-1",
        "id.orig_h": "2001:db8::1",
        "id.resp_h": "2001:db8::2",
        "id.orig_p": 1,
        "id.resp_p": 8,
        "proto": "icmp",
        "conn_state": "OTH",
        "orig_bytes": 100,
        "resp_bytes": 150,
    }
    item = from_zeek(raw)
    assert (
        item.src_port is None
        and item.dst_port is None
        and "bytes" not in item.features.model_fields_set
    )
    response = auth.post(
        "/api/events/import",
        files={"file": ("conn.json", json.dumps([raw]), "application/json")},
    )
    assert response.status_code == 200
    f = auth.get("/api/traffic").json()["items"][0]
    assert f["total_bytes"] is None and f["packets"] is None and f["origin"] == "replay"


def test_window_boundary_sensor_origin_and_out_of_order(auth):
    from backend.db import SessionLocal

    stamp = now()
    with SessionLocal() as db:
        for i in range(7):
            ingest(
                db,
                observation(
                    timestamp=stamp - timedelta(seconds=60), dst_port=20 + i, sensor="A"
                ),
                "replay",
                "fixture",
            )
        # Wrong target, wrong sensor and future records do not contribute to this scan.
        assert (
            ingest(
                db,
                observation(timestamp=stamp, dst_port=30, sensor="B"),
                "replay",
                "fixture",
            ).risk
            == 0
        )
        assert (
            ingest(
                db,
                observation(
                    timestamp=stamp + timedelta(seconds=1), dst_port=31, sensor="A"
                ),
                "simulation",
                "fixture",
            ).risk
            == 0
        )
        assert (
            ingest(
                db,
                observation(timestamp=stamp, dst_port=32, sensor="A"),
                "replay",
                "fixture",
            ).rule
            == "SCAN-001"
        )
        assert (
            ingest(
                db,
                observation(
                    timestamp=stamp - timedelta(seconds=61), dst_port=33, sensor="A"
                ),
                "replay",
                "fixture",
            ).risk
            == 0
        )


def test_rejected_connections_need_explicit_state_and_distinct_flows(auth):
    stamp = now()
    with SessionLocal() as db:
        for i in range(5):
            event = ingest(
                db,
                observation(
                    timestamp=stamp, src_port=45000 + i, connection_state="REJ"
                ),
                "replay",
                "zeek-test",
            )
        assert event.rule == "CONN-REJECT-001" and "password" in event.evidence[-1]


def test_manual_alert_to_block_timeline(auth):
    e = auth.post(
        "/api/events",
        json=observation(features={"failed_auth": 18}).model_dump(mode="json"),
    ).json()
    auth.put("/api/enforcement", json={"mode": "manual", "confirmed": True})
    payload = {
        "ip": e["src_ip"],
        "event_id": e["id"],
        "reason": "Reviewed owned lab detection",
        "confirmed": True,
    }
    r = auth.post("/api/blocks", json=payload)
    assert r.status_code == 200, r.text
    detail = auth.get(f"/api/flows/{e['flow_id']}/journey").json()
    assert detail["decisions"][-1]["block"]["adapter"] == "simulated"
    assert "NO REAL PACKETS" in detail["decisions"][-1]["steps"][-1]["result"]
    assert (
        auth.post("/api/blocks", json={**payload, "ip": "192.0.2.45"}).status_code
        == 422
    )


def test_model_feature_availability_and_path_cache(auth, monkeypatch, tmp_path):
    from backend import ml

    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "one.joblib"))
    metrics = ml.train()
    prediction = ml.predict({"packets": 3, "bytes": 120, "duration": 2}, 443)
    assert prediction["available"] and "failed_auth" in prediction["missing_features"]
    assert prediction["imputation"] == "Training-partition feature means"
    assert (
        prediction["features_used"]["failed_auth"] > 0
    )  # declared mean, not an invented observed authentication count
    assert metrics["confusion_matrix"] == [[244, 65], [74, 217]]
    assert (
        "false_negative_rate" in metrics and metrics["feature_schema"] == "synthetic-v1"
    )
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "missing.joblib"))
    assert not ml.predict({}, None)["available"]


def test_access_service_policy_and_topology_mapping(auth):
    from backend.seed import seed_topology

    with SessionLocal() as db:
        seed_topology(db)
    e = auth.post(
        "/api/events",
        json=observation(
            src_ip="10.10.4.20", dst_ip="10.10.2.10", dst_port=443
        ).model_dump(mode="json"),
    ).json()
    j = auth.get(f"/api/flows/{e['flow_id']}/journey").json()
    assert j["modeled_path"] == ["user", "app"]
    edges = auth.get("/api/network").json()["connections"]
    edge = next(r for r in edges if r["source"] == "user" and r["target"] == "app")
    assert (
        auth.patch(
            f"/api/network/connections/{edge['id']}",
            json={"allowed": True, "allowed_ports": [22], "protocol": "TCP"},
        ).status_code
        == 200
    )
    assert auth.get(f"/api/flows/{e['flow_id']}/journey").json()["modeled_path"] == []
    overlay = auth.get("/api/network/observations").json()["flows"][0]
    assert overlay["source_node"] == "user" and overlay["target_node"] == "app"
    assert (
        auth.put(
            "/api/network/policy",
            json={
                "confirmed": True,
                "restrictions": [
                    {
                        "destination": "10.10.1.10",
                        "port": 443,
                        "allowed_sources": ["10.10.0.0/24"],
                    }
                ],
            },
        ).status_code
        == 200
    )
    alert = auth.post("/api/events", json=observation().model_dump(mode="json")).json()
    assert alert["rule"] == "ACCESS-001"


def test_research_dataset_group_split(tmp_path):
    import numpy as np
    import pandas as pd
    from backend.research_ml import evaluate

    rng = np.random.default_rng(42)
    n = 240
    frame = pd.DataFrame(
        {
            "duration": rng.uniform(1, 20, n),
            "packets": rng.integers(1, 1000, n),
            "bytes": rng.integers(60, 100000, n),
            "dst_port": rng.choice([22, 443, 53], n),
            "Label": ["BENIGN" if i % 2 == 0 else "lab-label" for i in range(n)],
            "capture_group": [f"owned-group-{i // 40}" for i in range(n)],
        }
    )
    csv = tmp_path / "fixture.csv"
    frame.to_csv(csv, index=False)
    metrics = evaluate(
        csv,
        tmp_path / "research.joblib",
        "capture_group",
        provenance="Generated test fixture; NOT CIC dataset",
    )
    assert set(metrics["train_groups"]).isdisjoint(metrics["test_groups"])
    assert set(metrics["models"]) == {"majority", "linear", "random_forest"}
    assert sum(map(sum, metrics["confusion_matrix"])) == metrics["test_samples"]


def test_new_routes_require_auth(client):
    for path in [
        "/api/traffic",
        "/api/traffic/export",
        "/api/network/observations",
        "/api/flows/unknown/journey",
        "/api/network/policy",
    ]:
        assert client.get(path).status_code == 401


def test_distinct_connection_rate_and_statistical_baseline(auth):
    stamp = now()
    with SessionLocal() as db:
        for i in range(100):
            e = ingest(
                db,
                observation(timestamp=stamp, src_port=19000 + i),
                "replay",
                "rate-fixture",
            )
        assert e.rule == "RATE-001" and e.risk == 80
        assert len(e.detection["related_event_ids"]) == 99
        for i in range(30):
            e = ingest(
                db,
                observation(
                    timestamp=stamp,
                    src_ip="192.0.2.55",
                    src_port=29000 + i,
                    features={"bytes": 1000 + i, "duration": 1},
                ),
                "replay",
                "statistics-fixture",
            )
            assert e.risk == 0
        e = ingest(
            db,
            observation(
                timestamp=stamp,
                src_ip="192.0.2.55",
                src_port=30001,
                features={"bytes": 100000, "duration": 1},
            ),
            "replay",
            "statistics-fixture",
        )
        assert e.rule == "STAT-BYTES-001"
        assert "30 same-service" in e.evidence[-1]


def test_invalid_normalized_batch_no_partial_persistence(auth):
    row = observation().model_dump(mode="json")
    bad = {
        **row,
        "first_seen": "2026-01-02T00:00:00Z",
        "last_seen": "2026-01-01T00:00:00Z",
    }
    r = auth.post(
        "/api/events/import",
        files={"file": ("invalid.json", json.dumps([row, bad]), "application/json")},
    )
    assert r.status_code == 422 and auth.get("/api/traffic").json()["total"] == 0


def test_corrupt_model_does_not_disable_rules(auth, monkeypatch, tmp_path):
    from backend import ml

    path = tmp_path / "corrupt.joblib"
    path.write_bytes(b"not a model")
    monkeypatch.setenv("MODEL_PATH", str(path))
    assert ml.load() is None
    assert (
        auth.post(
            "/api/events",
            json=observation(features={"failed_auth": 10}).model_dump(mode="json"),
        ).json()["rule"]
        == "AUTH-001"
    )


def test_concurrent_simulated_block_is_idempotent(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.db import Base, Setting, Block
    from backend.firewall import create_block

    monkeypatch.setenv("FIREWALL_ADAPTER", "simulated")
    engine = create_engine(
        "sqlite:///" + str(tmp_path / "concurrent.db").replace("\\", "/")
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            Setting(
                key="enforcement",
                value={"mode": "manual", "threshold": 85, "duration_minutes": 5},
            )
        )
        db.commit()

    def create(_):
        with sessions() as db:
            return create_block(db, "192.0.2.44", "Owned concurrent test", 5, "test").id

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(create, range(2)))
    assert ids[0] == ids[1]
    with sessions() as db:
        assert len(list(db.scalars(select(Block)))) == 1
    engine.dispose()


def test_migration_preserves_legacy_evidence(tmp_path):
    import os, subprocess, sys, sqlite3

    dbpath = tmp_path / "legacy.db"
    env = {**os.environ, "DATABASE_URL": "sqlite:///" + str(dbpath).replace("\\", "/")}
    for revision in ["0002", "head"]:
        run = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", revision],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert run.returncode == 0, run.stderr
        if revision == "0002":
            with sqlite3.connect(dbpath) as db:
                db.execute(
                    "INSERT INTO events (id,timestamp,src_ip,dst_ip,protocol,category,origin,detection_source,rule,severity,risk,evidence,features,action,status) VALUES (1,'2026-01-01','192.0.2.1','10.10.1.10','TCP','connection','replay','legacy','baseline','low',0,'[\"original evidence\"]','{}','observed','open')"
                )
    with sqlite3.connect(dbpath) as db:
        assert db.execute(
            "SELECT evidence,flow_id FROM events WHERE id=1"
        ).fetchone() == ('["original evidence"]', None)


def test_collector_partial_lines_checkpoint_restart_and_dedup(
    auth, monkeypatch, tmp_path
):
    import asyncio
    import backend.main as main
    from tests.conftest import original_worker
    from backend.db import Setting

    raw = {
        "timestamp": now().isoformat(),
        "flow_id": 17,
        "event_type": "flow",
        "src_ip": "192.0.2.44",
        "dest_ip": "10.10.1.10",
        "proto": "TCP",
    }
    line = json.dumps(raw) + "\n"
    log = tmp_path / "eve.json"
    log.write_bytes((line + line + '{"partial":').encode("utf-8"))
    monkeypatch.setenv("SURICATA_EVE_PATH", str(log))
    monkeypatch.setenv("SURICATA_LIVE_CONFIRMED", "true")
    main.monitor.update(running=True, mode="live", last_live=None, error=None)
    main.collector.update(offset=0, inode=None, discarding=False)

    async def stop(_):
        raise asyncio.CancelledError()

    monkeypatch.setattr(main.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(original_worker())
    assert auth.get("/api/events?origin=live").json()["total"] == 1
    with SessionLocal() as db:
        saved = db.get(Setting, "collector_checkpoint").value
    assert saved["offset"] == len((line + line).encode())
    main.collector.update(offset=0, inode=None)
    assert (
        auth.post("/api/monitor", json={"running": True, "mode": "live"}).status_code
        == 200
    )
    assert main.collector["offset"] == saved["offset"]
    assert main.collector["backlog_bytes"] > 0
    main.monitor.update(running=False, mode="simulation", last_live=None, error=None)


@pytest.mark.parametrize("value", ["180", True])
def test_sensor_counter_types_are_not_concatenated(value):
    raw = {
        "timestamp": now().isoformat(),
        "src_ip": "192.0.2.1",
        "dest_ip": "10.10.1.10",
        "flow": {"bytes_toserver": value, "bytes_toclient": 20},
    }
    with pytest.raises(ValueError):
        from_eve(raw)


def test_retention_dryrun_preserves_alerts_and_live(auth):
    from backend.maintenance import retain

    stamp = now() - timedelta(days=2)
    with SessionLocal() as db:
        normal = ingest(db, observation(timestamp=stamp), "replay", "retention-test")
        alert = ingest(
            db,
            observation(timestamp=stamp, features={"failed_auth": 10}),
            "replay",
            "retention-test",
        )
        assert retain(db, now(), "replay")["eligible_events"] == 1
        assert db.get(Event, normal.id)
        retain(db, now(), "replay", True)
        db.expire_all()
        assert db.get(Event, normal.id) is None and db.get(Event, alert.id)
        with pytest.raises(ValueError):
            retain(db, now(), "live", True)


def test_hop_cutoff_is_explicit_and_reachability_remains_complete(client):
    from backend.db import Device, Connection, AccessRule
    from backend.twin import analyze

    with SessionLocal() as db:
        for i in range(11):
            db.add(
                Device(
                    id=f"n{i}",
                    name=f"Node {i}",
                    kind="server",
                    ip=f"10.20.0.{i + 1}",
                    criticality=5 if i == 10 else 1,
                    vulnerability=1,
                    x=i * 100,
                    y=0,
                )
            )
        db.flush()
        for i in range(10):
            edge = Connection(source=f"n{i}", target=f"n{i + 1}")
            db.add(edge)
            db.flush()
            db.add(AccessRule(connection_id=edge.id, allowed=True))
        db.commit()
        result = analyze(db, "n0")
        assert (
            "n10" in result["reachable"]
            and result["truncated"]
            and result["path_count"] == 0
        )
        assert result["enumeration_steps"] <= 20000


@pytest.mark.parametrize(
    ("features", "rule"),
    [
        ({"failed_auth": 5}, "AUTH-001"),
        ({"frequency": 100}, "RATE-001"),
        ({"bytes": 10000001, "duration": 9}, "BURST-001"),
        ({"bytes": 10000000, "duration": 9}, "flow-baseline"),
        ({"bytes": 10000001, "duration": 10}, "flow-baseline"),
        ({"bytes": 10000001}, "flow-baseline"),
    ],
)
def test_rule_boundaries_and_unknown_duration(features, rule):
    assert classify(observation(features=features), [])[2] == rule


def test_capture_packet_budget():
    import struct

    data = Path("samples/cn-demo.pcap").read_bytes()
    size = struct.unpack_from("<I", data, 32)[0]
    too_many = data[:24] + data[24 : 40 + size] * 10001
    with pytest.raises(ValueError, match="10,000"):
        parse_capture(too_many)


def test_real_action_requires_threshold_evidence(auth, monkeypatch):
    import backend.firewall as fw
    from backend.db import Setting

    with SessionLocal() as db:
        db.add(
            Setting(
                key="enforcement",
                value={"mode": "manual", "threshold": 85, "duration_minutes": 5},
            )
        )
        db.commit()
        e = ingest(db, observation(), "live", "suricata")
        monkeypatch.setenv("FIREWALL_ADAPTER", "nftables")
        monkeypatch.setattr(fw.NftablesAdapter, "ready", lambda self: True)
        with pytest.raises(HTTPException, match="threshold") as error:
            fw.create_block(db, e.src_ip, "Reviewed lab signal", 5, "test", e)
        assert error.value.status_code == 409


def test_capture_bytes_exclude_ethernet_padding():
    import struct

    source = Path("samples/cn-demo.pcap").read_bytes()
    size = struct.unpack_from("<I", source, 32)[0]
    frame = source[40 : 40 + size] + b"\x00" * 6
    padded = (
        source[:24]
        + struct.pack("<IIII", 1767225600, 0, len(frame), len(frame))
        + frame
    )
    result = parse_capture(padded)
    assert result["observations"][0]["features"]["bytes"] == 40
