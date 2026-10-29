"""Generate owned, deterministic test headers locally. Does not send any packets."""

from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap, PcapNgWriter


def packets():
    result = [
        Ether()
        / IP(src="10.10.4.20", dst="10.10.1.10")
        / TCP(sport=45000, dport=443, flags="S"),
        Ether()
        / IP(src="10.10.1.10", dst="10.10.4.20")
        / TCP(sport=443, dport=45000, flags="SA"),
        Ether()
        / IP(src="10.10.4.20", dst="10.10.1.10")
        / TCP(sport=45000, dport=443, flags="A"),
        Ether()
        / IP(src="10.10.4.20", dst="10.10.2.53")
        / UDP(sport=45001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="lab.example")),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
    ]
    result += [
        Ether()
        / IP(src="192.0.2.44", dst="10.10.1.10")
        / TCP(sport=46000 + i, dport=20 + i, flags="S")
        for i in range(8)
    ]
    for i, p in enumerate(result):
        p.time = 1767225600 + i
        p.src = "02:00:00:00:00:01"
        p.dst = "02:00:00:00:00:02"
    return result


if __name__ == "__main__":
    Path("samples").mkdir(exist_ok=True)
    wrpcap("samples/cn-demo.pcap", packets())
    with PcapNgWriter("samples/cn-demo.pcapng") as writer:
        for p in packets():
            writer.write(p)
    print(
        "Generated samples/cn-demo.pcap and .pcapng with fictional documentation addresses; no traffic sent."
    )
