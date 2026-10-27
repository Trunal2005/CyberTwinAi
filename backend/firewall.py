"""Narrow adapters. nftables sets must be provisioned out of band by a lab admin."""

import ipaddress
import json
import os
import platform
import shutil
import subprocess
import threading
from functools import wraps
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select

from backend.db import Block, Event, audit, aware, config, now
from backend.security import validate_block_ip

_lock = threading.RLock()


def serialized(fn):
    @wraps(fn)
    def locked(*args, **kwargs):
        with _lock:
            return fn(*args, **kwargs)

    return locked


class SimulatedAdapter:
    name = "simulated"

    def ready(self):
        return True

    def block(self, ip, seconds):
        return True

    def unblock(self, ip):
        return True


class NftablesAdapter:
    name = "nftables"

    def run(self, *args):
        binary = shutil.which("nft")
        if not binary:
            raise RuntimeError("nft binary unavailable")
        result = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=5, shell=False
        )
        if result.returncode:
            raise RuntimeError(
                "nftables operation failed; check lab permissions and set configuration"
            )
        return result.stdout

    def set_name(self, ip):
        return "blocked4" if ipaddress.ip_address(ip).version == 4 else "blocked6"

    def ready(self):
        if (
            platform.system() != "Linux"
            or os.getenv("REAL_ENFORCEMENT") != "true"
            or not os.getenv("PROTECTED_CIDRS")
        ):
            return False
        try:
            for name in ["blocked4", "blocked6"]:
                self.run("-j", "list", "set", "inet", "cybertwin", name)
            # Only directly hooked filter chains with the required source-set drop
            # expressions count. An unused chain must never enable the IPS label.
            objects = json.loads(self.run("-j", "list", "table", "inet", "cybertwin"))[
                "nftables"
            ]
            chains = {o["chain"]["name"]: o["chain"] for o in objects if "chain" in o}
            verified = set()
            for obj in objects:
                rule = obj.get("rule", {})
                chain = chains.get(rule.get("chain"), {})
                if chain.get("type") != "filter" or chain.get("hook") not in (
                    "input",
                    "forward",
                ):
                    continue
                expressions = rule.get("expr", [])
                if not any("drop" in expr for expr in expressions):
                    continue
                for expr in expressions:
                    match = expr.get("match", {})
                    payload = (
                        match.get("left", {}).get("payload", {})
                        if isinstance(match.get("left", {}), dict)
                        else {}
                    )
                    for version, protocol in [(4, "ip"), (6, "ip6")]:
                        if (
                            match.get("op") == "=="
                            and match.get("right") == f"@blocked{version}"
                            and payload == {"protocol": protocol, "field": "saddr"}
                        ):
                            verified.add((chain["hook"], version))
            return all(
                (hook, version) in verified
                for hook in ("input", "forward")
                for version in (4, 6)
            )
        except (
            RuntimeError,
            subprocess.SubprocessError,
            ValueError,
            KeyError,
            TypeError,
        ):
            return False

    def block(self, ip, seconds):
        self.run(
            "add",
            "element",
            "inet",
            "cybertwin",
            self.set_name(ip),
            "{",
            ip,
            "timeout",
            f"{seconds}s",
            "}",
        )
        contents = self.run("-j", "list", "set", "inet", "cybertwin", self.set_name(ip))

        # nft JSON represents timeout elements as {elem:{val:..., expires:...}}.
        def contains(value):
            if isinstance(value, str):
                return value == ip
            if isinstance(value, dict):
                return any(contains(v) for v in value.values())
            if isinstance(value, list):
                return any(contains(v) for v in value)
            return False

        return contains(json.loads(contents))

    def unblock(self, ip):
        # An expired timeout element is already absent. Check first for idempotency.
        contents = self.run("-j", "list", "set", "inet", "cybertwin", self.set_name(ip))
        if f'"{ip}"' in contents:
            self.run(
                "delete",
                "element",
                "inet",
                "cybertwin",
                self.set_name(ip),
                "{",
                ip,
                "}",
            )
        return f'"{ip}"' not in self.run(
            "-j", "list", "set", "inet", "cybertwin", self.set_name(ip)
        )


def adapter():
    return (
        NftablesAdapter()
        if os.getenv("FIREWALL_ADAPTER") == "nftables"
        else SimulatedAdapter()
    )


def expire_blocks(db):
    for block in db.scalars(select(Block).where(Block.state == "active")):
        if aware(block.expires) <= now():
            # nft set timeout expires in-kernel; records must not claim a still-active block.
            block.state = "expired"
            audit(db, "scheduler", "block_expired", ip=block.ip, adapter=block.adapter)
    db.commit()


@serialized
def create_block(db, ip, reason, minutes, actor, event=None):
    ip = validate_block_ip(str(ip))
    cfg = config(db)
    if cfg["mode"] == "detection":
        raise HTTPException(
            409, "Detection-only mode; enable manual approval in Settings first"
        )
    target = adapter()
    if target.name != "simulated":
        if not target.ready():
            raise HTTPException(409, "Real enforcement unavailable or unverified")
        # Real actions must be anchored to a recent, collector-owned live event.
        if event is None:
            event = db.scalar(
                select(Event)
                .where(Event.src_ip == ip, Event.origin == "live")
                .order_by(Event.timestamp.desc())
            )
        if (
            not event
            or event.origin != "live"
            or aware(event.timestamp) < now() - timedelta(minutes=10)
        ):
            raise HTTPException(
                409, "Real enforcement requires a recent verified live observation"
            )
    expire_blocks(db)
    uncertain = db.scalar(
        select(Block).where(
            Block.ip == ip,
            Block.adapter == target.name,
            Block.state.in_(["pending", "error"]),
        )
    )
    if uncertain:
        raise HTTPException(
            409,
            "Reconcile the existing pending/error action before retrying this source",
        )
    existing = db.scalar(
        select(Block).where(
            Block.ip == ip, Block.state == "active", Block.adapter == target.name
        )
    )
    if existing:
        return existing
    block = Block(
        ip=ip,
        reason=reason,
        expires=now() + timedelta(minutes=minutes),
        adapter=target.name,
    )
    db.add(block)
    # Persist intent before an external side effect for crash recovery.
    block.state = "pending"
    audit(db, actor, "block_requested", ip=ip, adapter=target.name)
    db.commit()
    try:
        verified = target.block(ip, minutes * 60)
        if not verified:
            # Roll back uncertain action; retain error for operator reconciliation.
            target.unblock(ip)
            raise RuntimeError("Action could not be verified; rollback attempted")
        block.state = "active"
        block.verified = target.name != "simulated"
        audit(
            db,
            actor,
            "block_applied",
            ip=ip,
            adapter=target.name,
            verified=block.verified,
        )
    except (RuntimeError, subprocess.SubprocessError) as exc:
        block.state = "error"
        audit(db, actor, "block_failed", ip=ip, error=str(exc))
        db.commit()
        raise HTTPException(
            502, "Firewall action failed; review audit and reconcile adapter state"
        )
    db.commit()
    return block


@serialized
def remove_block(db, block, actor):
    target = NftablesAdapter() if block.adapter == "nftables" else SimulatedAdapter()
    try:
        if not target.unblock(block.ip):
            raise RuntimeError("Removal not verified")
        block.state = "removed"
        audit(db, actor, "block_removed", ip=block.ip, adapter=block.adapter)
    except (RuntimeError, subprocess.SubprocessError):
        audit(db, actor, "unblock_failed", ip=block.ip, adapter=block.adapter)
        db.commit()
        raise HTTPException(502, "Removal failed; block retained for recovery")
    db.commit()
