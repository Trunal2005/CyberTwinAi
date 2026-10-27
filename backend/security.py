import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyCookie
from sqlalchemy import select

from backend.db import Session, SessionLocal, User, aware, now


def password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 600_000
    ).hex()
    return f"{salt}${digest}"


def password_ok(password, stored):
    salt, digest = stored.split("$")
    return hmac.compare_digest(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600_000).hex(),
        digest,
    )


def db_session():
    with SessionLocal() as db:
        yield db


session_cookie = APIKeyCookie(name="ct_session", auto_error=False)


def admin(
    request: Request,
    token: str | None = Depends(session_cookie),
    db=Depends(db_session),
):
    token = token or ""
    session = db.get(Session, hashlib.sha256(token.encode()).hexdigest())
    if not session or aware(session.expires) <= now():
        raise HTTPException(401, "Administrator login required")
    user = db.get(User, session.user_id)
    if not user or user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    request.state.actor = user.username
    return user


class Limiter:
    def __init__(self):
        self.entries = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key, limit=20, seconds=60):
        with self.lock:
            q = self.entries[key]
            t = time.monotonic()
            while q and q[0] < t - seconds:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(429, "Rate limit reached; retry later")
            q.append(t)
            if len(self.entries) > 10000:
                self.entries = defaultdict(
                    deque,
                    {
                        k: v
                        for k, v in self.entries.items()
                        if v and v[-1] > t - seconds
                    },
                )


limiter = Limiter()


def validate_block_ip(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(422, "Invalid IPv4 or IPv6 address")
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_reserved
    ):
        raise HTTPException(422, "Protected or non-unicast address")
    protected = (
        "127.0.0.0/8,::1/128,"
        + os.getenv("PROTECTED_CIDRS", "10.10.0.0/24")
        + ","
        + os.getenv("ALLOWLIST", "")
    )
    for item in protected.split(","):
        if item.strip() and addr in ipaddress.ip_network(item.strip(), strict=False):
            raise HTTPException(422, "Address is allowlisted or protected")
    try:
        local = {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)}
    except socket.gaierror:
        if os.getenv("FIREWALL_ADAPTER") == "nftables":
            raise HTTPException(
                409, "Cannot resolve host interfaces; refusing real enforcement"
            )
        local = set()
    if str(addr) in local:
        raise HTTPException(422, "Host management interface is protected")
    return str(addr)
