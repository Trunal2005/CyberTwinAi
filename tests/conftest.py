import asyncio
import os
import secrets
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

os.environ["MODEL_PATH"] = "./data/test-unavailable.joblib"
os.environ["FIREWALL_ADAPTER"] = "simulated"
os.environ["REAL_ENFORCEMENT"] = "false"

from backend.db import Base, SessionLocal, User
from backend.main import app
from backend.main import worker as original_worker
from backend.security import limiter, password_hash


@pytest.fixture
def client(monkeypatch, tmp_path):
    import backend.main as main

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    SessionLocal.configure(bind=engine)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "missing.joblib"))
    monkeypatch.setenv("PROTECTED_CIDRS", "10.10.0.0/24")
    monkeypatch.setenv("ALLOWLIST", "198.51.100.99")
    monkeypatch.setenv("FIREWALL_ADAPTER", "simulated")
    monkeypatch.setenv("REAL_ENFORCEMENT", "false")

    async def idle():
        await asyncio.Event().wait()

    monkeypatch.setattr(main, "worker", idle)
    main.monitor.update(running=False, mode="simulation", error=None, last_live=None)
    limiter.entries.clear()
    password = secrets.token_urlsafe(20)
    with SessionLocal() as db:
        db.add(
            User(username="tester", password_hash=password_hash(password), role="admin")
        )
        db.commit()
    with TestClient(app) as c:
        c.test_password = password
        yield c
    engine.dispose()


@pytest.fixture
def auth(client):
    response = client.post(
        "/api/auth/login", json={"username": "tester", "password": client.test_password}
    )
    assert response.status_code == 200
    return client
