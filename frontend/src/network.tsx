import React, { useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, Controls, MarkerType } from "@xyflow/react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { api, send } from "./api";

type Notify = (text: string, bad?: boolean) => void;
const shown = (v: any) =>
  v === null || v === undefined
    ? "Unavailable"
    : typeof v === "number"
      ? v.toLocaleString()
      : String(v);
function useLoad(path: string, refresh: number = 0) {
  const [data, setData] = useState<any>(null),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setError("");
    api(path)
      .then((d) => {
        if (active) setData(d);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [path, refresh]);
  return { data, error };
}

export function FlowEvidence({ id }: { id: string }) {
  const { data, error } = useLoad(`/flows/${id}/journey`);
  if (error) return <p role="alert">{error}</p>;
  if (!data) return <p>Loading linked flow evidence…</p>;
  const f = data.flow;
  return (
    <>
      <p className="notice">
        Flow {f.id.slice(0, 16)} · {f.origin} · {f.sensor}. {data.path_label}
      </p>
      <div className="detail-grid">
        {[
          ["IP version", f.ip_version],
          ["Application", f.app_protocol],
          ["Packets", f.packets],
          ["Captured/sensor bytes", f.total_bytes],
          ["Source bytes", f.bytes_src],
          ["Destination bytes", f.bytes_dst],
          ["Duration seconds", f.duration],
          ["Connection state", f.state],
          ["TCP flags", f.tcp_flags],
          ["First seen", f.first_seen],
          ["Last seen", f.last_seen],
          ["Ingested at", f.ingested_at],
        ].map(([k, v]) => (
          <div key={k}>
            <small>{k}</small>
            <strong>{shown(v)}</strong>
          </div>
        ))}
      </div>
      <h3>Observed endpoints and modeled journey</h3>
      <p>
        {f.src_ip}:{f.src_port ?? "—"} → {f.dst_ip}:{f.dst_port ?? "—"} (
        {f.protocol})
      </p>
      <p>
        Source asset: {data.source_device?.name || "Unmatched endpoint"} ·
        Destination asset:{" "}
        {data.destination_device?.name || "Unmatched endpoint"}
      </p>
      <p>
        MODELED PATH:{" "}
        {data.modeled_path.length
          ? data.modeled_path.join(" → ")
          : "No permitted modeled route or unmatched endpoints"}
      </p>
      <p>
        IPs identify Layer 3 endpoints. TCP/UDP ports identify endpoint
        services. ICMP has no TCP/UDP ports. Transit hops were not captured.
      </p>
      <h3>IDS and IPS action timeline</h3>
      {data.decisions.map((d: any) => (
        <div className="flow-decision" key={d.id}>
          <strong>
            {d.outcome} · {new Date(d.timestamp).toLocaleString()}
          </strong>
          <ol>
            {d.steps.map((s: any, i: number) => (
              <li key={i}>
                <b>{s.stage}:</b> {s.result}
              </li>
            ))}
          </ol>
          {d.block && (
            <p>
              Block #{d.block.id} · {d.block.adapter} · {d.block.state} ·
              expires {d.block.expires}
              <br />
              {d.block.adapter === "simulated"
                ? "SIMULATED — NO REAL PACKETS WERE BLOCKED"
                : "Verification supports set membership only; packet dropping NOT VERIFIED"}
            </p>
          )}
        </div>
      ))}
      <h3>Supporting model result</h3>
      <p>{data.ml?.explanation || "Unavailable"}</p>
      {data.ml?.available && (
        <p>
          ML score {data.ml.score}/100 · {data.ml.model_version} · missing:{" "}
          {data.ml.missing_features.join(", ") || "none"} · imputation:{" "}
          {data.ml.imputation || "none"}
        </p>
      )}
      <details>
        <summary>
          Features, limitations and original header/log evidence
        </summary>
        <pre>
          {JSON.stringify(
            {
              availability: f.availability,
              limitations: f.limitations,
              events: data.events.map((e: any) => ({
                id: e.id,
                detection: e.detection,
                observation: e.observation,
                features: e.features,
              })),
              model: data.ml,
            },
            null,
            2,
          )}
        </pre>
      </details>
    </>
  );
}

function JourneyDialog({
  id,
  onClose,
  notify,
}: {
  id: string;
  onClose: () => void;
  notify: Notify;
}) {
  const { data, error } = useLoad(`/flows/${id}/journey`);
  const [preview, setPreview] = useState<any>(null),
    [busy, setBusy] = useState(false),
    [version, setVersion] = useState(0);
  const [reason, setReason] = useState(
    "Reviewed flow evidence in authorized simulation lab",
  );
  const [minutes, setMinutes] = useState(5);
  useEffect(() => {
    const cb = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", cb);
    return () => document.removeEventListener("keydown", cb);
  }, [onClose]);
  const event = data?.events?.reduce(
    (best: any, e: any) => (!best || e.risk > best.risk ? e : best),
    null,
  );
  const payload = {
    ip: data?.flow.src_ip,
    event_id: event?.id,
    reason,
    minutes,
  };
  return (
    <div className="modal-backdrop">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="Network flow journey"
        tabIndex={-1}
      >
        <div className="modal-heading">
          <h2>Network flow journey</h2>
          <button autoFocus onClick={onClose}>
            Close
          </button>
        </div>
        {error && <p role="alert">{error}</p>}
        <FlowEvidence key={version} id={id} />
        {data && (
          <button
            onClick={() => {
              onClose();
              window.dispatchEvent(
                new CustomEvent("flow-investigation", {
                  detail: data.flow.src_ip,
                }),
              );
            }}
          >
            Investigate observed source
          </button>
        )}
        {event && event.risk >= 70 && (
          <section>
            <h3>Request prevention for alert #{event.id}</h3>
            <p>
              Policy and safeguards are checked by the backend. Enable manual
              approval in Settings first. This action requires explicit
              confirmation.
            </p>
            <label>
              Block reason
              <input
                value={reason}
                onChange={(e) => {
                  setReason(e.target.value);
                  setPreview(null);
                }}
              />
            </label>
            <label>
              Temporary duration minutes
              <input
                type="number"
                min={1}
                max={1440}
                value={minutes}
                onChange={(e) => {
                  setMinutes(Number(e.target.value));
                  setPreview(null);
                }}
              />
            </label>
            {!preview ? (
              <button
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    setPreview(await send("/blocks/preview", payload));
                  } catch (e: any) {
                    notify(e.message, true);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Preview prevention
              </button>
            ) : (
              <>
                <p className="notice">
                  {preview.adapter} · {preview.duration_minutes} minutes ·{" "}
                  {preview.reason} · {preview.effect}
                </p>
                <button
                  disabled={busy || !preview.permitted_mode}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      await send("/blocks", { ...payload, confirmed: true });
                      setVersion((v) => v + 1);
                      setPreview(null);
                      notify("Prevention outcome recorded");
                    } catch (e: any) {
                      notify(e.message, true);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  Confirm temporary block
                </button>
                {!preview.permitted_mode && (
                  <p>
                    Detection-only policy prevents blocks. Change it explicitly
                    in Settings.
                  </p>
                )}
              </>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

export function TrafficAnalysis({
  refresh,
  notify,
  reload,
}: {
  refresh: number;
  notify: Notify;
  reload: () => void;
}) {
  const { data: status } = useLoad("/status", refresh);
  const [filters, setFilters] = useState<Record<string, string>>({}),
    [page, setPage] = useState(1),
    [selected, setSelected] = useState(""),
    [busy, setBusy] = useState(false);
  const params = new URLSearchParams({
    ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)),
    page: String(page),
  });
  const { data, error } = useLoad("/traffic?" + params, refresh);
  const set = (key: string, value: string) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  };
  const importFile = async (file: File) => {
    setBusy(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const r = await api(
        /\.pcap(ng)?$/i.test(file.name) ? "/traffic/pcap" : "/events/import",
        { method: "POST", body: form },
      );
      notify(
        `Offline replay stored: ${r.new_events ?? r.count} new observations`,
      );
      reload();
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setBusy(false);
    }
  };
  const a = data?.analytics;
  return (
    <>
      <div className="notice">
        COMPUTER NETWORKS · Observed endpoints, IP transport and service ports.
        Uploaded captures/logs are OFFLINE REPLAY. Missing measurements remain
        unavailable.
      </div>
      {status && (
        <p className="notice">
          Source status: {status.mode} · monitoring{" "}
          {status.monitoring ? "running" : "stopped"} · parser errors{" "}
          {status.collector?.parse_errors ?? 0} · unread backlog{" "}
          {status.collector?.backlog_bytes ?? 0} bytes ·{" "}
          {status.error || "No current source error"}
        </p>
      )}
      <section className="panel cn-panel">
        <div className="panel-head">
          <div>
            <h2>PCAP and traffic analysis</h2>
            <p>
              2 MB · up to 10,000 packets and 1,000 conversations · no packets
              sent · PCAP, PCAPNG, JSON, CSV, EVE and Zeek JSON
            </p>
          </div>
        </div>
        <label className="upload-label">
          {busy ? "Analyzing capture…" : "Upload capture or supported logs"}
          <input
            aria-label="Upload capture or logs"
            type="file"
            accept=".pcap,.pcapng,.json,.jsonl,.csv"
            disabled={busy}
            onChange={(e) => {
              if (e.target.files?.[0]) void importFile(e.target.files[0]);
              e.target.value = "";
            }}
          />
        </label>
        <div className="traffic-filters">
          {[
            ["src", "Source IP"],
            ["dst", "Destination IP"],
            ["port", "Destination port"],
            ["sensor", "Sensor"],
          ].map(([k, l]) => (
            <label key={k}>
              {l}
              <input
                type={k === "port" ? "number" : "text"}
                value={filters[k] || ""}
                onChange={(e) => set(k, e.target.value)}
              />
            </label>
          ))}
          {(
            [
              ["protocol", ["", "TCP", "UDP", "ICMP", "OTHER"]],
              ["origin", ["", "simulation", "replay", "live"]],
              ["severity", ["", "low", "medium", "high", "critical"]],
            ] as [string, string[]][]
          ).map(([k, values]) => (
            <label key={k}>
              {k}
              <select
                aria-label={k}
                value={filters[k] || ""}
                onChange={(e) => set(k, e.target.value)}
              >
                {values.map((v) => (
                  <option key={v} value={v}>
                    {v || "All"}
                  </option>
                ))}
              </select>
            </label>
          ))}
          {["since", "until"].map((k) => (
            <label key={k}>
              {k} UTC
              <input
                type="datetime-local"
                onChange={(e) =>
                  set(
                    k,
                    e.target.value
                      ? new Date(e.target.value + "Z").toISOString()
                      : "",
                  )
                }
              />
            </label>
          ))}
          <button
            onClick={() => {
              setFilters({});
              setPage(1);
            }}
          >
            Reset filters
          </button>
        </div>
        {error && <p role="alert">{error}</p>}
        {!data && !error && <p>Loading flow analysis…</p>}
        {a && (
          <>
            <div className="traffic-metrics">
              {[
                ["Matching flows", data.total],
                ["Known packets", a.packets],
                ["Known bytes", a.bytes],
                ["Capture-span rate bit/s", a.rate_bps],
                ["Normal / suspicious", `${a.normal} / ${a.suspicious}`],
                ["Mean duration seconds", a.duration_mean],
                [
                  "Source / return bytes",
                  `${shown(a.directional_bytes.source)} / ${shown(a.directional_bytes.destination)}`,
                ],
              ].map(([k, v]) => (
                <div key={k}>
                  <small>{k}</small>
                  <strong>{shown(v)}</strong>
                </div>
              ))}
            </div>
            <p>
              {a.packet_coverage} packet-count and {a.byte_coverage} byte-count
              measurements available in {a.flows} analyzed flows. {a.scope}{" "}
              {data.truncated ? "ANALYTICS TRUNCATED" : ""}
            </p>
            <div className="traffic-chart">
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={a.timeline}>
                  <CartesianGrid stroke="#27384b" />
                  <XAxis dataKey="time" hide />
                  <YAxis />
                  <Tooltip />
                  <Area
                    dataKey="bytes"
                    stroke="#39d5c9"
                    fill="#163947"
                    dot={{ r: 4 }}
                    connectNulls={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <p className="subtle">
              {a.formula} No RTT, packet loss, retransmission or link
              utilization is inferred.
            </p>
            <div className="traffic-distributions">
              {[
                ["Protocol distribution", "protocols"],
                ["Top sources", "sources"],
                ["Top destinations", "destinations"],
                ["Destination services", "ports"],
              ].map(([title, key]) => (
                <div key={key}>
                  <h3>{title}</h3>
                  {a[key].map((r: any) => (
                    <p key={r.name}>
                      <span className="mono">{r.name}</span> <b>{r.count}</b>
                    </p>
                  ))}
                </div>
              ))}
            </div>
            <h3>Top conversations</h3>
            {a.conversations.map((c: any, i: number) => (
              <p key={i}>
                {c.src} → {c.dst} · {c.protocol} · {c.flows} flow(s) ·{" "}
                {shown(c.bytes)} bytes
              </p>
            ))}
            <details>
              <summary>Latest prevention decisions for matching flows</summary>
              {data.latest_decisions?.length ? (
                data.latest_decisions.map((d: any) => (
                  <p key={d.id}>
                    {d.timestamp} · event #{d.event_id} · {d.policy} ·{" "}
                    {d.outcome} · block {d.block_id ?? "none"}
                  </p>
                ))
              ) : (
                <p>No prevention decisions in this selection.</p>
              )}
            </details>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    {[
                      "Origin / sensor",
                      "Source",
                      "Destination",
                      "Protocol / app",
                      "Packets",
                      "Bytes",
                      "Rule risk",
                      "Evidence",
                    ].map((h) => (
                      <th key={h}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((f: any) => (
                    <tr key={f.id}>
                      <td>
                        {f.origin}
                        <small>{f.sensor}</small>
                      </td>
                      <td className="mono">
                        {f.src_ip}:{f.src_port ?? "—"}
                      </td>
                      <td className="mono">
                        {f.dst_ip}:{f.dst_port ?? "—"}
                      </td>
                      <td>
                        {f.protocol}
                        <small>{f.app_protocol || "Unidentified"}</small>
                      </td>
                      <td>{shown(f.packets)}</td>
                      <td>{shown(f.total_bytes)}</td>
                      <td>{f.risk}</td>
                      <td>
                        <button onClick={() => setSelected(f.id)}>
                          Inspect flow
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!data.total && (
              <p>
                No matching observations. Upload samples/cn-demo.pcap or
                generate it with scripts/generate_cn_capture.py.
              </p>
            )}
            <div className="flex-row">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </button>
              <span>Page {page}</span>
              <button
                disabled={page * 25 >= data.total}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
              {["json", "csv"].map((format) => (
                <a
                  key={format}
                  className="button"
                  href={`/api/traffic/export?format=${format}&origin=${filters.origin || ""}`}
                >
                  Export {format.toUpperCase()} · selected origin
                </a>
              ))}
            </div>
          </>
        )}
      </section>
      {selected && (
        <JourneyDialog
          id={selected}
          onClose={() => setSelected("")}
          notify={notify}
        />
      )}
    </>
  );
}

export function ObservedNetwork({
  topology,
  refresh,
  notify,
}: {
  topology: any;
  refresh: number;
  notify: Notify;
}) {
  const [positions, setPositions] = useState<
    Record<string, { x: number; y: number }>
  >({});
  const [origin, setOrigin] = useState(""),
    [cursor, setCursor] = useState(0),
    [playing, setPlaying] = useState(false),
    [speed, setSpeed] = useState(1),
    [selected, setSelected] = useState(""),
    [reduced, setReduced] = useState(
      () =>
        window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ??
        false,
    );
  const { data, error } = useLoad(
    "/network/observations?origin=" + origin,
    refresh,
  );
  const flows = useMemo(
    () =>
      [...(data?.flows || [])].sort((a: any, b: any) =>
        a.first_seen.localeCompare(b.first_seen),
      ),
    [data],
  );
  useEffect(() => {
    setCursor(Math.max(0, flows.length - 1));
    setPlaying(false);
  }, [flows]);
  useEffect(() => {
    if (!playing) return;
    const timer = setInterval(
      () =>
        setCursor((c) => {
          if (c >= flows.length - 1) {
            setPlaying(false);
            return c;
          }
          return c + 1;
        }),
      1000 / speed,
    );
    return () => clearInterval(timer);
  }, [playing, speed, flows.length]);
  const visible = flows.slice(0, cursor + 1),
    current = flows[cursor];
  const nodes = useMemo(() => {
    const result = topology.devices.map((d: any) => ({
      id: d.id,
      position: positions[d.id] || { x: d.x, y: d.y },
      data: {
        label: (
          <>
            <b>{d.name}</b>
            <br />
            {d.kind} · {d.ip}
            <br />
            Segment: {d.segment || "Not configured"}
            <br />
            Modeled vulnerability {d.vulnerability}/10 · criticality{" "}
            {d.criticality}
            <br />
            {
              visible.filter(
                (f: any) => f.source_node === d.id || f.target_node === d.id,
              ).length
            }{" "}
            observed flows ·{" "}
            {
              visible.filter(
                (f: any) =>
                  (f.source_node === d.id || f.target_node === d.id) &&
                  f.risk >= 40,
              ).length
            }{" "}
            alert flows
          </>
        ),
      },
      style: {
        background: "#15283d",
        color: "#e2f4ff",
        border: "1px solid #2a647a",
        width: 225,
        fontSize: 11,
      },
      draggable: true,
    }));
    const external = new Map<string, string>();
    for (const f of visible) {
      if (!f.source_node) external.set("external:" + f.src_ip, f.src_ip);
      if (!f.target_node) external.set("external:" + f.dst_ip, f.dst_ip);
    }
    [...external].slice(0, 40).forEach(([id, ip], i) =>
      result.push({
        id,
        position: { x: -300 + (i % 2) * 230, y: Math.floor(i / 2) * 100 },
        data: {
          label: (
            <>
              Unmatched endpoint
              <br />
              {ip}
            </>
          ),
        },
        style: {
          background: "#24223c",
          color: "#ddd6ff",
          border: "1px dashed #9a89ff",
          width: 210,
          fontSize: 11,
        },
        draggable: false,
      }),
    );
    return result;
  }, [topology, visible, positions]);
  const edges = [
    ...topology.connections.map((e: any) => ({
      id: "model:" + e.id,
      source: e.source,
      target: e.target,
      label: e.allowed ? "MODELED ACCESS" : "RESTRICTED",
      style: { stroke: "#42546c", strokeDasharray: "5 5" },
      markerEnd: { type: MarkerType.ArrowClosed },
    })),
    ...visible.map((f: any) => ({
      id: "observed:" + f.id,
      source: f.source_node || "external:" + f.src_ip,
      target: f.target_node || "external:" + f.dst_ip,
      label: `${f.protocol}:${f.dst_port ?? "—"} · ${shown(f.total_bytes)} B · ${f.block ? (f.block.adapter === "simulated" ? "SIMULATED PREVENTION" : "SET VERIFIED") : f.risk >= 40 ? "IDS ALERT" : "OBSERVED"}`,
      animated: playing && !reduced && current?.id === f.id,
      style: {
        stroke: f.block ? "#9a89ff" : f.risk >= 40 ? "#fb657a" : "#39d5c9",
        strokeWidth: current?.id === f.id ? 4 : 2,
      },
      markerEnd: { type: MarkerType.ArrowClosed },
    })),
  ];
  return (
    <section className="panel cn-panel">
      <div className="panel-head">
        <div>
          <h2>Observed traffic on the virtual topology</h2>
          <p>
            Solid lines connect observed endpoints. Dashed paths show modeled
            access. Neither establishes physical forwarding hops.
          </p>
        </div>
      </div>
      <div className="flex-row">
        <label>
          Provenance
          <select value={origin} onChange={(e) => setOrigin(e.target.value)}>
            {["", "simulation", "replay", "live"].map((o) => (
              <option key={o} value={o}>
                {o || "All origins"}
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={!flows.length}
          onClick={() => {
            if (cursor >= flows.length - 1) setCursor(0);
            setPlaying((v) => !v);
          }}
        >
          {playing ? "Pause" : "Play"}
        </button>
        <button
          disabled={!flows.length}
          onClick={() => {
            setCursor(0);
            setPlaying(true);
          }}
        >
          Replay stored observations
        </button>
        <label>
          Speed
          <select
            aria-label="Speed"
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
          >
            {[0.5, 1, 2, 4].map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={reduced}
            onChange={(e) => setReduced(e.target.checked)}
          />
          Reduced motion
        </label>
        <button disabled={!current} onClick={() => setSelected(current.id)}>
          Inspect selected flow
        </button>
      </div>
      <label>
        Timeline
        <input
          aria-label="Flow replay timeline"
          type="range"
          min={0}
          max={Math.max(0, flows.length - 1)}
          value={cursor}
          onChange={(e) => {
            setPlaying(false);
            setCursor(Number(e.target.value));
          }}
        />
      </label>
      <p>
        {current
          ? `${cursor + 1}/${flows.length} · ${current.first_seen} · ${current.origin} · ${current.src_ip} → ${current.dst_ip}`
          : "No observed flows; import the CN sample capture first."}
      </p>
      {error && <p role="alert">{error}</p>}
      <div className="network-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          minZoom={0.1}
          onNodesChange={(changes) => {
            for (const c of changes)
              if (c.type === "position" && c.position) {
                const point = c.position;
                setPositions((v) => ({ ...v, [c.id]: point }));
              }
          }}
          onEdgeClick={(_, edge) => {
            if (edge.id.startsWith("observed:")) setSelected(edge.id.slice(9));
          }}
          onNodeClick={(_, node) => {
            const f = [...visible]
              .reverse()
              .find(
                (f: any) =>
                  f.source_node === node.id || f.target_node === node.id,
              );
            if (f) setSelected(f.id);
          }}
          onNodeDragStop={async (_, node) => {
            const device = topology.devices.find((d: any) => d.id === node.id);
            if (!device) return;
            try {
              await send(
                "/network/devices/" + node.id,
                { ...device, ...node.position },
                "PUT",
              );
              notify("Virtual device position saved");
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          <Background color="#27384b" />
          <Controls />
        </ReactFlow>
      </div>
      <p className="subtle">
        Click an observed edge or matched asset for its flow, original evidence,
        IDS and IPS timeline. Unmatched endpoints are limited to 40.{" "}
        {data?.scope} Simulated prevention never drops real packets.
      </p>
      <ServicePolicyEditor topology={topology} notify={notify} />
      {selected && (
        <JourneyDialog
          id={selected}
          onClose={() => setSelected("")}
          notify={notify}
        />
      )}
    </section>
  );
}

function ServicePolicyEditor({
  topology,
  notify,
}: {
  topology: any;
  notify: Notify;
}) {
  const [source, setSource] = useState("user"),
    [target, setTarget] = useState("db"),
    [route, setRoute] = useState("");
  const [edge, setEdge] = useState(String(topology.connections[0]?.id || "")),
    [ports, setPorts] = useState(""),
    [protocol, setProtocol] = useState(""),
    [allowed, setAllowed] = useState(true),
    [confirm, setConfirm] = useState(false);
  const [dest, setDest] = useState("10.10.1.10"),
    [port, setPort] = useState(443),
    [sources, setSources] = useState("10.10.0.0/24"),
    [policy, setPolicy] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    const e = topology.connections.find((r: any) => String(r.id) === edge);
    setPorts(e?.allowed_ports?.join(", ") || "");
    setProtocol(e?.protocol || "");
    setAllowed(e?.allowed ?? true);
    setConfirm(false);
  }, [edge, topology]);
  return (
    <details>
      <summary>Modeled service permissions and observed access policy</summary>
      <p>
        Modeled permissions affect virtual reachability only. Observation policy
        flags future matching traffic without altering routers or firewall
        rules.
      </p>
      <div className="traffic-filters">
        <label>
          Route source
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            {topology.devices.map((d: any) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Route destination
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            {topology.devices.map((d: any) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={async () => {
            try {
              const r = await api(
                `/network/route?source=${encodeURIComponent(source)}&target=${encodeURIComponent(target)}`,
              );
              setRoute(
                r.label + ": " + (r.path.join(" → ") || "No permitted route"),
              );
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Analyze modeled route
        </button>
      </div>
      {route && <p>{route}</p>}
      <div className="traffic-filters">
        <label>
          Modeled connection
          <select value={edge} onChange={(e) => setEdge(e.target.value)}>
            {topology.connections.map((r: any) => (
              <option key={r.id} value={r.id}>
                {r.source} → {r.target}
              </option>
            ))}
          </select>
        </label>
        <label>
          Permitted transport
          <select
            value={protocol}
            onChange={(e) => {
              setProtocol(e.target.value);
              setConfirm(false);
            }}
          >
            {["", "TCP", "UDP", "ICMP", "OTHER"].map((p) => (
              <option key={p} value={p}>
                {p || "Any"}
              </option>
            ))}
          </select>
        </label>
        <label>
          Permitted ports comma separated
          <input
            value={ports}
            placeholder="Blank means any service"
            onChange={(e) => {
              setPorts(e.target.value);
              setConfirm(false);
            }}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={allowed}
            onChange={(e) => {
              setAllowed(e.target.checked);
              setConfirm(false);
            }}
          />
          Modeled connection allowed
        </label>
        <button
          disabled={!edge || busy}
          onClick={async () => {
            if (!confirm) {
              setConfirm(true);
              return;
            }
            setBusy(true);
            try {
              await send(
                "/network/connections/" + edge,
                {
                  allowed,
                  protocol: protocol || null,
                  allowed_ports: ports.trim()
                    ? ports.split(",").map((p) => Number(p.trim()))
                    : null,
                },
                "PATCH",
              );
              notify("Virtual service permissions saved");
              setConfirm(false);
            } catch (e: any) {
              notify(e.message, true);
            } finally {
              setBusy(false);
            }
          }}
        >
          {confirm
            ? "Confirm virtual service policy"
            : "Preview virtual service policy"}
        </button>
      </div>
      {confirm && (
        <p>
          Change {edge}: {allowed ? "allow" : "deny"} ·{" "}
          {protocol || "any transport"} · ports {ports || "any"}. No real
          networking configuration will change.
        </p>
      )}
      <h3>Protected service observation policy</h3>
      <div className="traffic-filters">
        <label>
          Destination IP
          <input
            value={dest}
            onChange={(e) => {
              setDest(e.target.value);
              setPolicy("");
            }}
          />
        </label>
        <label>
          Service port
          <input
            type="number"
            min={0}
            max={65535}
            value={port}
            onChange={(e) => {
              setPort(Number(e.target.value));
              setPolicy("");
            }}
          />
        </label>
        <label>
          Allowed source CIDRs
          <input
            value={sources}
            onChange={(e) => {
              setSources(e.target.value);
              setPolicy("");
            }}
          />
        </label>
        <button
          disabled={busy}
          onClick={async () => {
            if (!policy) {
              setPolicy(
                `Replace the observation policy with ${dest}:${port}, allowed sources ${sources}. Other sources will generate ACCESS-001 evidence.`,
              );
              return;
            }
            setBusy(true);
            try {
              await send(
                "/network/policy",
                {
                  confirmed: true,
                  restrictions: [
                    {
                      destination: dest,
                      port,
                      allowed_sources: sources
                        .split(",")
                        .map((v) => v.trim())
                        .filter(Boolean),
                    },
                  ],
                },
                "PUT",
              );
              notify("Observation access policy saved");
              setPolicy("");
            } catch (e: any) {
              notify(e.message, true);
            } finally {
              setBusy(false);
            }
          }}
        >
          {policy ? "Confirm observation policy" : "Preview observation policy"}
        </button>
      </div>
      {policy && <p>{policy}</p>}
    </details>
  );
}
