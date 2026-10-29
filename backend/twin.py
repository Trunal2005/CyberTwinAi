import networkx as nx
from sqlalchemy import select
from backend.db import AccessRule, Connection, Device


def topology(db):
    devices = list(db.scalars(select(Device)))
    edges = list(db.scalars(select(Connection)))
    return devices, edges


def permits(rule, protocol=None, port=None):
    return not rule or (
        rule.allowed
        and (protocol is None or not rule.protocol or rule.protocol == protocol)
        and (
            rule.allowed_ports is None
            or (
                port in rule.allowed_ports
                if port is not None
                else bool(rule.allowed_ports)
            )
        )
    )


def analyze(db, initial, blocked=(), patched=(), isolated=(), protocol=None, port=None):
    devices, edges = topology(db)
    graph = nx.DiGraph()
    graph.add_nodes_from(d.id for d in devices)
    for edge in edges:
        rule = db.get(AccessRule, edge.id)
        if (
            edge.id not in blocked
            and edge.source not in isolated
            and edge.target not in isolated
            and permits(rule, protocol, port)
        ):
            # Model assumes a patched pivot prevents onward compromise. This is a declared simplification.
            if edge.source not in patched or edge.source == initial:
                graph.add_edge(edge.source, edge.target)
    if initial not in graph:
        raise ValueError("Initial device does not exist")
    reachable = nx.descendants(graph, initial)
    critical = [d for d in devices if d.criticality >= 4 and d.id in reachable]
    paths = []
    truncated = False
    # Bounded DFS also limits work in dense graphs before the first terminal path.
    targets = {d.id for d in critical}
    stack = [(initial, [initial])]
    steps = 0
    while stack and steps < 20000 and len(paths) < 500:
        node, path = stack.pop()
        steps += 1
        if node in targets:
            paths.append(path)
        if len(path) - 1 >= 8:
            if any(n not in path for n in graph.successors(node)):
                truncated = True
            continue
        for neighbor in graph.successors(node):
            if neighbor not in path:
                stack.append((neighbor, path + [neighbor]))
    truncated = truncated or bool(stack)
    denominator = sum(d.criticality * 10 for d in devices) or 1
    numerator = sum(
        d.criticality * (0 if d.id in patched else d.vulnerability)
        for d in devices
        if d.id in reachable
    )
    return {
        "reachable": sorted(reachable),
        "critical_assets": [d.name for d in critical],
        "critical_ids": [d.id for d in critical],
        "paths": paths,
        "path_count": len(paths),
        "truncated": truncated,
        "enumeration_steps": steps,
        "path_label": "MODELED PATHS; count is a lower bound when hop, path or work budget reached",
        "service_filter": {"protocol": protocol, "destination_port": port},
        "reachable_services": [
            {
                "source": e.source,
                "target": e.target,
                "protocol": db.get(AccessRule, e.id).protocol
                if db.get(AccessRule, e.id)
                else None,
                "ports": db.get(AccessRule, e.id).allowed_ports
                if db.get(AccessRule, e.id)
                else None,
            }
            for e in edges
            if graph.has_edge(e.source, e.target) and e.source in reachable | {initial}
        ],
        "risk": round(100 * numerator / denominator, 1),
        "components": nx.number_weakly_connected_components(graph),
        "mode": "simulation",
        "formula": "100 × sum(reachable asset criticality × vulnerability) / sum(all asset criticality × 10). Patched vulnerability = 0; patched pivots stop onward compromise except the initial device. Paths capped at 500 and 8 hops.",
        "operational_cost": {
            "restricted_links": len(blocked),
            "patched_devices": len(patched),
            "isolated_devices": len(isolated),
            "units": "counts only; no measured downtime or monetary cost",
        },
    }
