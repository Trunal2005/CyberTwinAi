import networkx as nx
from sqlalchemy import select
from backend.db import AccessRule, Connection, Device


def topology(db):
    devices = list(db.scalars(select(Device)))
    edges = list(db.scalars(select(Connection)))
    return devices, edges


def analyze(db, initial, blocked=(), patched=(), isolated=()):
    devices, edges = topology(db)
    graph = nx.DiGraph()
    graph.add_nodes_from(d.id for d in devices)
    for edge in edges:
        rule = db.get(AccessRule, edge.id)
        if (
            edge.id not in blocked
            and edge.source not in isolated
            and edge.target not in isolated
            and (not rule or rule.allowed)
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
    for device in critical:
        for path in nx.all_simple_paths(
            graph, initial, device.id, cutoff=min(8, len(devices))
        ):
            if len(paths) >= 500:
                truncated = True
                break
            paths.append(path)
        if truncated:
            break
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
