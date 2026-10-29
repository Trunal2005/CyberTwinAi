"""Disposable bounded parser subprocess; communicate only JSON and input bytes."""

import json
import sys
from backend.pcap import parse_capture, MAX_BYTES

if __name__ == "__main__":
    try:
        result = parse_capture(sys.stdin.buffer.read(MAX_BYTES + 1))
        print(json.dumps(result))
    except Exception as exc:
        print(json.dumps({"error": str(exc)[:180]}))
        sys.exit(1)
