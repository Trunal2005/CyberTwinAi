"""Offline Scapy reader. No sniff/send/interface access. Whole-file limits are atomic."""

import io
import hashlib
import struct
import time
from datetime import datetime, timezone
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether, CookedLinux
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from backend.schemas import EventInput

MAX_BYTES = 2_000_000
MAX_PACKETS = 10_000
MAX_FLOWS = 1000


def validate_container(data):
    if not 24 <= len(data) <= MAX_BYTES:
        raise ValueError("Capture must be 24 bytes to 2 MB")
    magic = data[:4]
    if magic in (
        b"\xd4\xc3\xb2\xa1",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\xa1\xb2\x3c\x4d",
    ):
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        at = 24
        count = 0
        while at < len(data):
            if len(data) - at < 16:
                raise ValueError("Truncated PCAP packet header")
            size = struct.unpack_from(endian + "I", data, at + 8)[0]
            at += 16 + size
            count += 1
            if at > len(data):
                raise ValueError("Truncated PCAP packet data")
            if count > MAX_PACKETS:
                raise ValueError("Capture exceeds 10,000 packets")
    elif magic == b"\x0a\x0d\x0d\x0a":
        at = 0
        endian = None
        while at < len(data):
            if len(data) - at < 12:
                raise ValueError("Truncated PCAPNG block")
            if data[at : at + 4] == magic:
                bom = data[at + 8 : at + 12]
                endian = (
                    "<"
                    if bom == b"\x4d\x3c\x2b\x1a"
                    else ">"
                    if bom == b"\x1a\x2b\x3c\x4d"
                    else None
                )
            if not endian:
                raise ValueError("Invalid PCAPNG byte order")
            size = struct.unpack_from(endian + "I", data, at + 4)[0]
            if (
                size < 12
                or size % 4
                or at + size > len(data)
                or struct.unpack_from(endian + "I", data, at + size - 4)[0] != size
            ):
                raise ValueError("Invalid PCAPNG block length")
            at += size
    else:
        raise ValueError("Only uncompressed PCAP and PCAPNG are supported")


def parse_capture(data):
    validate_container(data)
    started = time.monotonic()
    capture = hashlib.sha256(data).hexdigest()
    groups = {}
    skipped = 0
    count = 0
    reader = RawPcapReader(io.BytesIO(data))
    try:
        for buf, meta in reader:
            count += 1
            if count > MAX_PACKETS or time.monotonic() - started > 6:
                raise ValueError("Capture packet/time budget exceeded")
            link = getattr(meta, "linktype", getattr(reader, "linktype", None))
            decoder = {
                1: Ether,
                101: lambda b: IPv6(b) if b[0] >> 4 == 6 else IP(b),
                228: IP,
                229: IPv6,
                113: CookedLinux,
            }.get(link)
            if decoder is None:
                raise ValueError(f"Unsupported capture link type {link}")
            packet = decoder(buf)
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None:
                skipped += 1
                continue
            # No reassembly; do not treat fragmented payload bytes as complete TCP/UDP metadata.
            fragmented = isinstance(ip, IP) and (ip.frag != 0 or bool(ip.flags.MF))
            tcp = packet.getlayer(TCP) if not fragmented else None
            udp = packet.getlayer(UDP) if not fragmented else None
            proto = (
                "TCP"
                if tcp
                else "UDP"
                if udp
                else "ICMP"
                if (packet.haslayer(ICMP) or getattr(ip, "nh", None) == 58)
                else "OTHER"
            )
            transport = tcp or udp
            sp = int(transport.sport) if transport else None
            dp = int(transport.dport) if transport else None
            if hasattr(meta, "sec"):
                stamp = meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
            else:
                if meta.tshigh is None or meta.tslow is None:
                    raise ValueError("PCAPNG record lacks a packet timestamp")
                stamp = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol
            ts = datetime.fromtimestamp(stamp, timezone.utc)
            endpoints = sorted([(ip.src, sp or 0), (ip.dst, dp or 0)])
            key = (str(endpoints), proto, int(stamp // 60))
            if key not in groups:
                if len(groups) >= MAX_FLOWS:
                    raise ValueError("Capture exceeds 1,000 conversations per upload")
                groups[key] = {
                    "timestamp": ts,
                    "first_seen": ts,
                    "last_seen": ts,
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "src_port": sp,
                    "dst_port": dp,
                    "protocol": proto,
                    "category": "pcap-conversation",
                    "sensor": "pcap:" + capture[:16],
                    "sensor_flow_id": str(len(groups)),
                    "features": {"packets": 0, "bytes": 0, "duration": 0},
                    "bytes_src": 0,
                    "bytes_dst": 0,
                    "limitations": [
                        "Offline replay; no packets transmitted",
                        "Direction follows first observed packet, not guaranteed initiator",
                        "Captured IP bytes only; payloads are not retained; no stream/fragment reassembly; 60-second conversation windows",
                    ],
                    "raw_record": {
                        "capture_sha256": capture,
                        "link_type": link,
                        "packet_headers": [],
                        "byte_semantics": "captured IP bytes",
                    },
                }
            g = groups[key]
            g["first_seen"] = min(g["first_seen"], ts)
            g["last_seen"] = max(g["last_seen"], ts)
            captured_ip = len(bytes(ip))
            declared_ip = int(ip.len) if isinstance(ip, IP) else 40 + int(ip.plen)
            if declared_ip < (int(ip.ihl) * 4 if isinstance(ip, IP) else 40):
                raise ValueError("Invalid IP declared length")
            size = min(captured_ip, declared_ip)  # Exclude Ethernet padding.
            if declared_ip > captured_ip or getattr(meta, "wirelen", len(buf)) > len(
                buf
            ):
                warning = (
                    "Capture truncation observed; counters include captured bytes only"
                )
                if warning not in g["limitations"]:
                    g["limitations"].append(warning)
                g["raw_record"]["truncated_packets"] = (
                    g["raw_record"].get("truncated_packets", 0) + 1
                )
            g["features"]["packets"] += 1
            g["features"]["bytes"] += size
            g[
                "bytes_src"
                if ip.src == g["src_ip"] and sp == g["src_port"]
                else "bytes_dst"
            ] += size
            g["features"]["duration"] = (
                g["last_seen"] - g["first_seen"]
            ).total_seconds()
            flags = str(tcp.flags) if tcp else None
            if flags:
                g["tcp_flags"] = "".join(
                    sorted(set((g.get("tcp_flags") or "") + flags))
                )
            if packet.haslayer(DNS):
                g["app_protocol"] = "dns"
            if len(g["raw_record"]["packet_headers"]) < 24:
                g["raw_record"]["packet_headers"].append(
                    {
                        "timestamp": ts.isoformat(),
                        "src": ip.src,
                        "dst": ip.dst,
                        "src_port": sp,
                        "dst_port": dp,
                        "ip_bytes": size,
                        "tcp_flags": flags,
                    }
                )
    finally:
        reader.close()
    if not groups:
        raise ValueError("No supported IP observations in capture")
    return {
        "observations": [
            EventInput.model_validate(g).model_dump(mode="json", exclude_unset=True)
            for g in groups.values()
        ],
        "packets": count,
        "non_ip_packets": skipped,
        "capture_sha256": capture,
    }
