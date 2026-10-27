import json
from datetime import timedelta
from pathlib import Path
from sqlalchemy import select
from backend.db import AccessRule, Connection, Device, Event, SessionLocal, now
from backend.detection import ingest
from backend.schemas import EventInput

DEVICES = [
    ("router", "Edge router", "Router", "10.10.0.1", 3, 2, 0, 120),
    ("firewall", "Perimeter firewall", "Firewall", "10.10.0.2", 4, 1, 230, 120),
    ("web", "Public web server", "Web server", "10.10.1.10", 3, 8, 460, 0),
    ("app", "Application server", "Application server", "10.10.2.10", 4, 6, 710, 0),
    ("db", "Research database", "Database", "10.10.3.10", 5, 9, 960, 120),
    ("user", "User workstation", "Workstation", "10.10.4.20", 2, 7, 460, 240),
    ("admin", "Admin workstation", "Admin", "10.10.0.10", 5, 2, 710, 240),
    ("dns", "Internal DNS", "DNS", "10.10.2.53", 3, 3, 710, 440),
    ("sensor", "Monitoring sensor", "Sensor", "10.10.0.30", 2, 1, 230, 440),
]
LINKS = [
    ("router", "firewall"),
    ("firewall", "web"),
    ("firewall", "user"),
    ("web", "app"),
    ("web", "db"),
    ("app", "db"),
    ("user", "app"),
    ("user", "admin"),
    ("admin", "db"),
    ("user", "dns"),
    ("firewall", "sensor"),
]


def seed_topology(db):
    if db.scalar(select(Device)):
        return
    for id, name, kind, ip, criticality, vulnerability, x, y in DEVICES:
        db.add(
            Device(
                id=id,
                name=name,
                kind=kind,
                ip=ip,
                criticality=criticality,
                vulnerability=vulnerability,
                x=x,
                y=y,
            )
        )
    db.flush()
    for source, target in LINKS:
        edge = Connection(source=source, target=target)
        db.add(edge)
        db.flush()
        db.add(AccessRule(connection_id=edge.id, allowed=True))
    db.commit()


def sample_events(count=48):
    events = []
    for i in range(count):
        kind = i % 12
        events.append(
            EventInput(
                src_ip=["192.0.2.44", "198.51.100.23", "203.0.113.82", "192.0.2.108"][
                    i % 4
                ],
                dst_ip=["10.10.1.10", "10.10.2.10", "10.10.3.10"][i % 3],
                timestamp=now() - timedelta(minutes=count - i),
                src_port=40000 + i,
                dst_port=[443, 22, 5432, 80][i % 4],
                protocol="TCP",
                category="authentication" if kind < 3 else "connection",
                features={
                    "duration": i * 1.4,
                    "packets": 30 + i * 4,
                    "bytes": 1000 + i * 300,
                    "frequency": 130 if kind == 4 else 2 + i % 10,
                    "failed_auth": 18 if kind < 3 else 0,
                    "criticality": 3,
                },
                signature="LAB policy: suspicious service connection"
                if kind == 7
                else None,
                signature_severity=2,
            )
        )
    return events


def seed_events(db):
    for item in sample_events():
        ingest(db, item, "simulation", "generated")


if __name__ == "__main__":
    with SessionLocal() as db:
        seed_topology(db)
        if not db.scalar(select(Event)):
            seed_events(db)
    Path("samples").mkdir(exist_ok=True)
    Path("samples/events.json").write_text(
        json.dumps([e.model_dump(mode="json") for e in sample_events(12)], indent=2),
        encoding="utf-8",
    )
    print("Seeded labeled simulation and virtual topology.")
