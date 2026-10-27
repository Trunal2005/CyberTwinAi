# Authorized isolated Linux lab

Use disposable VMs and an internal virtual switch with no route to third-party networks. Keep a console session and a VM snapshot available. Do not run a privileged API on your workstation or expose it publicly. CyberTwin never runs a scan, exploit, sensor installation, or firewall setup command for you.

## Suricata EVE integration

Install Suricata following your Linux distribution's official packages and the [Suricata documentation](https://docs.suricata.io/en/suricata-8.0.6/). Select a lab-only interface, configure HOME_NET to your owned subnets, enable `eve-log` with alert/flow records in Suricata's YAML, and select authorized lab rules. The monitoring administrator controls capture privileges. Run Suricata independently of the unprivileged web service. Use an OS group to grant the service read access to EVE, without granting it sensor configuration access.

Set `SURICATA_EVE_PATH=/var/log/suricata/eve.json` and `SURICATA_LIVE_CONFIRMED=true` only after manually confirming the sensor process is capturing the correct interface and its clock is synchronized. Restart CyberTwin, start the Suricata source in the monitoring dialog, then generate an ordinary authorized connection inside the lab. The collector starts at EOF. A newly appended valid connection record within 90 seconds enables LIVE MONITORING. No fresh record means disconnected/waiting; malformed or inaccessible records show an error. Uploaded EVE always stays replay. Tail offset is process-memory only; restart skips existing contents, rotation may ingest prior contents as replay.

Suricata signatures become evidence with engine severity. Suricata's EVE `alert.action=blocked` alone is not treated as proof that CyberTwin blocked anything; packet verdict/action meanings depend on Suricata's deployment. CyberTwin's real adapter is independently audited. Suricata native NFQUEUE/AF_PACKET IPS configuration is external and not automatically managed here. See [EVE format and verdict semantics](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html).

## nftables adapter (Linux only)

This adapter adds/removes IP elements in dedicated timeout sets. It never creates rules, flushes a firewall, selects chains from a request or executes a shell. The checked-in `scripts/lab.nft` is a reference that an authorized administrator must review and apply out of band inside the disposable VM. It creates only `inet cybertwin`, with IPv4/IPv6 timeout sets and hooked input/forward drop rules. Existing host policies remain under your administration.

Before applying any reference configuration, inspect your current ruleset and keep a rollback snapshot and out-of-band console. Populate `PROTECTED_CIDRS` with **all** management/interface/trusted networks, not only the defaults, and add any exact trusted addresses or CIDRs to `ALLOWLIST`. Hostname resolution additionally protects local host addresses, and failure to resolve refuses real actions. IPv4-mapped IPv6 addresses are normalized to prevent loopback/allowlist bypasses. Do not block your own console path.

Only after lab rules and exclusions have been reviewed, set these values in the service environment:

```dotenv
FIREWALL_ADAPTER=nftables
REAL_ENFORCEMENT=true
PROTECTED_CIDRS=127.0.0.0/8,::1/128,10.10.0.0/24
```

The addresses above are illustrative; replace them with your actual lab management networks. `nft` must exist and the service must have permission to read/write the dedicated table. Granting CAP_NET_ADMIN to a web process is a material privilege risk; prefer a narrow privileged helper/service for a production implementation. This direct adapter is intended only for disposable authorized VMs. Never put the web app in an unrestricted sudoers rule, never run it publicly as root, and never reuse this lab setup on a third-party network.

After restart, Settings must report a connected adapter. Policy is detection-only until explicitly changed by an authenticated admin. Preview/confirm manual approval. A real block requires a matching collector-owned live event from the previous ten minutes; generated/imported evidence cannot satisfy this. Preview a short block for an owned lab source and confirm. Verify its set membership and test packet handling independently from a second lab VM. CyberTwin verifies kernel-set membership, not whether a particular flow encountered the rule.

## Expiry, rollback and recovery

Every real element has a kernel timeout. DB records expire every three seconds; TTL continues if the application crashes. Manual remove checks set state, removes the element if present, verifies absence and preserves history. nftables outages leave the block record and audit intact.

If a process crashes after committing intent but before recording success, inspect `pending`/`error` records and the actual dedicated sets. Do not assume the request failed to affect the firewall. Use the application's confirmed removal to reconcile; if the app is unavailable, a lab admin can inspect/remove only the specific element with native nft tools from the console. Audit any manual recovery separately. Restoring connectivity may require removing the dedicated lab table or restoring your reviewed VM snapshot; do not flush unrelated tables or copy an arbitrary ruleset over active production policies.

Switching to detection-only stops new actions but retains existing blocks. Disable the explicit environment flag and revert the adapter to simulated before leaving the lab. Reconcile active elements first. Keep the privileged configuration off your normal workstation.

## Optional Zeek

Zeek is not implemented in this version. Its status stays unconfigured. A future adapter should parse authenticated, server-owned conn/auth logs, preserve missing fields and UTC timestamps, use a separate detection_source, enforce freshness for real observations, and never turn imported historical logs into live traffic.
