# CyberTwin AI Computer Networks Practical

## What the project demonstrates

CyberTwin AI turns network observations into explainable flows, IDS findings, controlled prevention decisions and a virtual network model. Computer Networks is the core: endpoints, IP versions, protocols, ports, conversations, counters, directed access and reachability. Machine learning supports classification; Data Science summarizes observations and evaluates models.

A packet is a unit of transmitted network data with headers and, often, a payload. A flow groups related packets between endpoints using transport protocol and source/destination IPs and ports. ICMP does not use TCP/UDP service ports. IPv4 and IPv6 identify Layer 3 endpoints; TCP and UDP operate at transport. DNS is an application protocol that may be identified from decoded headers. OSI layers are a teaching abstraction; a port alone does not prove application identity.

## Actual observations and parsing

The authenticated PCAP and Traffic Analysis page accepts small PCAP/PCAPNG files offline. Maintained Scapy 2.8.0 reads headers without sniffing, packet injection, Npcap, administrative privileges or external services. IPv4/IPv6, TCP, UDP, ICMP and decoded DNS are supported. Ethernet, raw IP and Linux cooked v1 link types are accepted. Unsupported link types, malformed container lengths, absent PCAPNG timestamps and non-IP-only captures are rejected. PCAPNG simple packet blocks without timestamps are unsupported. There is no payload inspection, stream/fragment reassembly or proof that a full conversation was captured.

Limits are 2 MB, 10,000 packets, 1,000 conversations, a six-second parsing budget and a twelve-second subprocess deadline. The entire parser completes before persistence. Input and stored header samples are bounded; the process is killed on deadline. OS memory quotas are not imposed on Windows; file/packet/block limits bound allocations. Capture payload bytes are discarded. Each conversation preserves up to 24 packet-header samples plus capture SHA256, exact aggregates and limitations. Obtain and keep the original capture yourself for full independent packet-level examination.

Conversations are bidirectional within fixed UTC 60-second windows. Direction follows the first observed packet, not a claimed initiator. Captured IP-byte counts exclude Ethernet; truncation or missing capture data limits conclusions. PCAP flows do not invent connection state, authentication failures or sensor-reported rate values. TCP flags are aggregated observed flags, not a reconstructed handshake verdict.

EVE preserves the complete bounded original JSON and maps flow ID, signature metadata/action, protocol, ports, counters, optional start/end/state and app_proto. Zeek JSON conn.log supports documented uid, addresses, transport ports, state, duration, packet and IP-byte counters. Zeek orig_bytes/resp_bytes are payload bytes and are not silently substituted for IP bytes. No installed Zeek sensor is required to replay JSON. There is no live Zeek collector in this build.

Sources → parser → EventInput validation → persistent normalized Flow → target-aware IDS → Event evidence → PreventionDecision → optional authorized adapter → map, investigation and reports. IDs connect these records directly. Existing v1/v2 Event records are preserved by migration 0003; they are not retroactively converted into measured flows because their missing-feature defaults are ambiguous. Replay original source files to create the new normalized records.

## Identity and correlation

Flow identity hashes provenance, sensor, the directional 5-tuple, window and a sensor ID when provided. Sensor-ID windows are one hour; records lacking an ID use 60 seconds. A reused tuple without an independent connection identifier cannot establish distinct TCP connections within that window. Repeated cumulative EVE counters update by maximum, never addition. Records are deduplicated by normalized observation and original evidence, scoped to sensor and provenance. Collector retries deduplicate across a transition from fresh live to stale replay. Imports from distinct sensors/origins may observe the same real packets and are intentionally not merged.

The IDS counts distinct flow identities in the preceding inclusive 60-second event-time window, with source, origin and sensor isolation. SCAN-001 requires eight destination ports on the same target and transport. RATE-001 uses at least 100 distinct observations or an explicitly supplied connection-rate feature. AUTH-001 requires at least five explicitly supplied authentication failures; TCP failures are not password failures. BURST-001 uses more than 10 MB and duration under ten seconds only when both are supplied. ENGINE-SIGNATURE retains source-reported severity and signature.

CONN-REJECT-001 requires five distinct Zeek-style rejected/incomplete connection states to one target. STAT-BYTES-001 requires at least 30 preceding same-service counters, nonzero sample standard deviation and a byte count over mean + four standard deviations. This is a contextual statistical indicator, not proof of attack. ACCESS-001 checks future observations against explicitly saved destination-port/source-CIDR policy. Normal browsing/DNS and counter-only records are not automatically malicious.

Queries are capped at the latest 1,000 source records. Batches sort by timestamp. Late observations use their own preceding event-time window and do not rewrite existing alerts or retrospectively enforce future observations. This is a declared bounded streaming limitation, rather than an assertion of globally order-invariant correlation. Detection evidence includes linked event and flow IDs, decision time, rule reasoning and investigation advice.

## IDS and IPS

IDS identifies indicators. IPS separately evaluates policy and authorization. Detection-only records findings without blocking. Manual mode produces approval-required decisions above threshold. An administrator may inspect a flow, preview a qualifying temporary action and explicitly confirm it. Automatic mode needs a confirmed policy, threshold, action budget and the same exclusions. Rule risk and ML probability are different values; ML never independently triggers enforcement.

The journey displays detection → policy/threshold → approval/safeguard result → adapter → block state and expiry. Simulated actions always mean **SIMULATED — NO REAL PACKETS WERE BLOCKED**. Requested intent is persisted before adapter side effects. Pending/error/uncertain actions prohibit repeat requests until reconciliation/removal. Active blocks are idempotent under a process-local action lock. Expiration and removal preserve history. Read-only reconciliation checks current kernel set membership and records its evidence.

The real adapter is optional Linux nftables integration. It only modifies IP elements in preconfigured dedicated timeout sets using fixed argument arrays. Readiness checks hooked input/forward filter rules. Membership/removal uses structured JSON and canonical IP equality, including IPv6. Set membership verification is narrower than observing a dropped packet. See LAB.md for namespace-isolated packet-counter validation; it remains **NOT VERIFIED on Windows**. Consuming Suricata EVE does not make Suricata inline IPS.

Loopback, non-unicast, local management interfaces, protected CIDRs and allowlists are excluded. Real actions also require recent collector-owned matching live source evidence. Startup never changes firewall rules. The user must review every management interface because hostname resolution is not exhaustive interface enumeration. Only one backend worker is supported.

## Visual network and digital twin

The virtual model includes router, firewall, servers, workstations, DNS and sensor; `python -m backend.seed --extend-network` explicitly adds an external boundary and switch without overwriting existing assets. Segment is user-configured, never auto-discovered. Positions can be dragged/saved in Observed traffic. The original device/connection CRUD, isolation/patching and before/after scenarios remain available.

Observed traffic uses straight, directional endpoint edges with protocol, service, bytes and risk. Unmatched IPs remain external/unmatched nodes. Cyan = observed low-risk; red = IDS alert flow; violet = associated simulated or real set-membership prevention, distinguished by text. Gray dashed edges are modeled access. Replay/pause/speed/scrub/reduced-motion operate on up to 500 stored observations, not invented animation. Click an observed edge/node or Inspect selected flow for the same evidence and actions.

MODELED PATH uses directed NetworkX reachability and configured access/service permissions. It does not prove a switch or router actually forwarded packets. Select route endpoints under service permissions to query a shortest permitted modeled route. The original attack-path analysis compares critical assets and modeled risk before/after defenses; path enumeration has eight hops, 500 paths and 20,000 exploration steps. A truncated count is a lower bound. Reachability remains complete for the modeled graph. Risk formula remains `100 * sum(reachable criticality * vulnerability) / sum(all criticality * 10)`; patched pivots stop onward compromise except the initial device. This is a simplified graph model, not measured protection efficacy.

## Analytics and AI support

Traffic filters include endpoints, protocol, destination port, provenance, sensor, severity and time. Pandas groups protocols, services, source/destination addresses, conversations and UTC minute buckets. Null counters remain unavailable; coverage counts show how many rows supplied them. Packets/bytes sum known counters of the latest 5,000 matching normalized conversations. Minute attribution uses flow first_seen; it is not a precise per-packet timeline for long flows. Capture-span average rate is `8 * known bytes / (last timestamp - first timestamp)`, available only for nonzero time span. Directional bytes follow observed first-packet orientation, not automatically Internet inbound/outbound. No packet loss, RTT, retransmission, congestion or link utilization is inferred.

The reproducible synthetic Random Forest uses the existing seed42, 1,800/600 split and majority baseline. No synthetic accuracy is a real-network performance claim. Versioned feature metadata and training-only mean imputation make missing features explicit. Selected-flow predictions report used values and imputed fields separately; means are not recorded as observed authentication events. The configurable user-supplied research pipeline compares majority, scaled logistic regression and Random Forest on group-disjoint data. See RESEARCH_DATA.md. No real dataset was downloaded or evaluated here.

## Shortest professor demonstration

1. **Overview** — explain SIMULATION/REPLAY/LIVE and detection-only safety. Counts are stored records, not a live network claim.
2. **PCAP and Traffic Analysis** — upload `samples/cn-demo.pcap` (generated owned headers only). Show 13 packets in 11 conversations, TCP/UDP/ICMP, an IPv6 pair and DNS. Filter UDP. Explain IPs and ports, source/return bytes and unavailable metrics.
3. **Threat Detection / flow journey** — inspect source `192.0.2.44`, destination port 27. SCAN-001 is explained by seven earlier related flows plus the eighth port. Normal handshake/DNS examples stay low risk.
4. **Settings** — preview and confirm manual approval with threshold70 in the simulation lab. Return to the scan flow, Preview prevention and Confirm temporary block. Show persisted expiry and the explicit no-real-packets statement. Remove the simulated block in Blocklist.
5. **Network Digital Twin** — Observed traffic, replay/pause, scrub, click endpoints and inspect the MODELED PATH distinction. Show unmatched source. Save a virtual position. Under Scenario, run web baseline; restrict web→db and patch app; rerun and compare. Results are modeled, not measured defenses.
6. **AI Insights** — show dataset, exact confusion matrix, baseline and missing-feature warnings; request a prediction. Explain why ML does not decide IPS alone.
7. **Traffic Analysis / Reports** — export the same flow IDs and counters as JSON/CSV; export the evidence report PDF. Show dated test results and real lab limitations.

Use the generated sample only on the local app; no third-party traffic, scanning or capture is necessary for any of these demonstrations.

## Retention and operational limits

One backend worker is required. Monitor state, action mutex and rate limiter are process-local. SQLite is indexed for source/origin/sensor/event-time correlation; queries and graph exploration are bounded. Large imports still perform per-event commits so external action intent can be persisted before side effects; this is a laptop demo, not an unbounded ingestion service. Parser execution is offloaded to a bounded subprocess, but general JSON imports and graph analysis are synchronous and can add latency. Do not claim multi-worker or high-throughput sensor support.

No automatic data deletion runs. Optional local retention defaults to dry-run, at most 1,000 old open low-risk simulation/replay events per invocation; alerts, reviewed records, nontrivial prevention decisions and live data are excluded. Back up first. Example: `python -m backend.maintenance --origin simulation --before 2026-01-01T00:00:00Z`. Add `--confirm` only after reviewing the eligible count. The tool preserves audit history and removes orphaned eligible flows.

Parser and dataset references: [Scapy reader API](https://scapy.readthedocs.io/en/stable/api/scapy.utils.html), [Zeek connection fields](https://docs.zeek.org/en/lts/reference/logs/conn.html), [CICIDS2017 publisher](https://www.unb.ca/cic/datasets/ids-2017.html).
