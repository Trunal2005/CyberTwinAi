import React, { useState, useEffect, useCallback, useMemo } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Shield,
  ShieldCheck,
  ShieldAlert,
  LayoutDashboard,
  Radio,
  Search,
  Ban,
  Network,
  BrainCircuit,
  FileChartColumn,
  Settings,
  ChevronRight,
  ArrowUpRight,
  Download,
  Play,
  Square,
  Plus,
  X,
  Check,
  Menu,
  LogOut,
  RefreshCw,
  Upload,
  Bell,
  ArrowRight,
  LockKeyhole,
  Server,
  Database,
  Router,
  Laptop,
  Layers,
  SlidersHorizontal,
  CircleHelp,
  Trash2,
  Pencil,
  Eye,
  GitBranch,
  CheckCircle2,
  Zap,
  CircleDot,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from "recharts";
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, send, download, type SecurityEvent } from "./api";
import "./style.css";

const NAV = [
  ["Overview", LayoutDashboard],
  ["Live Monitoring", Radio],
  ["Threat Detection", ShieldAlert],
  ["IP Investigation", Search],
  ["Blocklist", Ban],
  ["Network Digital Twin", Network],
  ["AI Insights", BrainCircuit],
  ["Reports", FileChartColumn],
  ["Settings", Settings],
] as const;
const COLORS = ["#fb657a", "#f3ab59", "#9a89ff", "#39d5c9"];
const time = (v: string) =>
  new Date(v).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
const date = (v: string) => new Date(v).toLocaleString();
const num = (v: number) => (v || 0).toLocaleString();
type Notify = (text: string, bad?: boolean) => void;
function Badge({
  children,
  tone = "cyan",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return (
    <span className={`badge ${tone}`}>
      <i />
      {children}
    </span>
  );
}
function Empty({
  text = "No observations yet. Load simulation events or import a replay to begin.",
}: {
  text?: string;
}) {
  return (
    <div className="empty">
      <ShieldCheck size={30} />
      <h3>Nothing to display yet</h3>
      <p>{text}</p>
    </div>
  );
}
function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    ref.current?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {
        const nodes = ref.current?.querySelectorAll<HTMLElement>(
          "button,input,select,textarea,a[href]",
        );
        if (!nodes?.length) return;
        const first = nodes[0],
          last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        tabIndex={-1}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
function useData<T = any>(path: string, refresh = 0, poll = false) {
  const [data, setData] = useState<T | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const run = () =>
      api<T>(path)
        .then((d) => {
          if (active) {
            setData(d);
            setError("");
          }
        })
        .catch((e) => {
          if (active) setError(e.message);
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    setLoading(true);
    run();
    const timer = poll ? setInterval(run, 5000) : undefined;
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [path, refresh, poll]);
  return { data, error, loading };
}
function DataState({ error, loading }: { error: string; loading: boolean }) {
  return error ? (
    <div className="error" role="alert">
      {error}
    </div>
  ) : loading ? (
    <div className="loading">
      <RefreshCw size={18} /> Loading observations…
    </div>
  ) : null;
}

export function Login({ onLogin }: { onLogin: (user: any) => void }) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <div className="login-page">
      <div className="login-art">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={28} />
          </div>
          <span>
            CyberTwin<span className="accent"> AI</span>
          </span>
        </div>
        <Badge>RESEARCH SECURITY PLATFORM</Badge>
        <h1>
          Understand the threat.
          <br />
          <span>Shape the defense.</span>
        </h1>
        <p>
          One workspace for intrusion detection, threat investigation, and a
          safer network through simulation.
        </p>
        <div className="login-network">
          <div>
            <Router />
            Observe
          </div>
          <span>······</span>
          <div>
            <BrainCircuit />
            Understand
          </div>
          <span>······</span>
          <div>
            <ShieldCheck />
            Defend
          </div>
        </div>
        <small>
          Local-first research environment · No host firewall changes by default
        </small>
      </div>
      <form
        className="login-card"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          try {
            onLogin(await send("/auth/login", { username, password }));
          } catch (e: any) {
            setError(e.message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="square-icon">
          <LockKeyhole />
        </div>
        <h2>Welcome to your command center</h2>
        <p>Sign in with your administrator account.</p>
        <label>
          Username
          <input
            autoFocus
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <button className="primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in securely"}
          <ArrowRight size={17} />
        </button>
        <div className="notice">
          <Shield size={18} />
          <span>
            Administrator access only. Create your account using the setup
            commands in the README.
          </span>
        </div>
      </form>
    </div>
  );
}

function EventTable({
  events,
  onEvent,
  onIP,
  compact = false,
}: {
  events: SecurityEvent[];
  onEvent: (e: SecurityEvent) => void;
  onIP: (ip: string) => void;
  compact?: boolean;
}) {
  if (!events.length) return <Empty />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Event / time</th>
            <th>Observed source</th>
            <th>Target service</th>
            <th>Severity</th>
            <th>Rule risk</th>
            {!compact && <th>Action</th>}
            <th>Provenance</th>
            <th aria-label="Details" />
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td>
                <button
                  className="text-button event-title"
                  onClick={() => onEvent(e)}
                >
                  {e.rule === "flow-baseline"
                    ? "Network connection"
                    : e.rule === "AUTH-001"
                      ? "Failed authentication"
                      : e.rule === "ENGINE-SIGNATURE"
                        ? "Signature alert"
                        : e.rule === "SCAN-001"
                          ? "Port scan indicator"
                          : "Connection anomaly"}
                </button>
                <small>
                  #{String(e.id).padStart(4, "0")} · {time(e.timestamp)}
                </small>
              </td>
              <td>
                <button
                  className="mono text-button"
                  onClick={() => onIP(e.src_ip)}
                >
                  {e.src_ip}
                  <ArrowUpRight size={12} />
                </button>
              </td>
              <td>
                <span className="mono">{e.dst_ip}</span>
                <small>
                  {e.protocol} / {e.dst_port ?? "—"}
                </small>
              </td>
              <td>
                <Badge tone={e.severity}>{e.severity}</Badge>
              </td>
              <td>
                <div className="risk-cell">
                  <span>{e.risk}</span>
                  <div>
                    <i
                      style={{
                        width: `${e.risk}%`,
                        background: e.risk >= 70 ? "#fb657a" : "#40cfc2",
                      }}
                    />
                  </div>
                </div>
              </td>
              {!compact && <td>{e.action}</td>}
              <td>
                <span className="origin">{e.origin}</span>
              </td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`View event ${e.id}`}
                  onClick={() => onEvent(e)}
                >
                  <ChevronRight size={16} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Overview({
  refresh,
  onEvent,
  onIP,
  navigate,
  notify,
  reload,
}: {
  refresh: number;
  onEvent: (e: SecurityEvent) => void;
  onIP: (ip: string) => void;
  navigate: (p: string) => void;
  notify: Notify;
  reload: () => void;
}) {
  const { data: d, error, loading } = useData("/overview", refresh, true);
  if (!d) return <DataState error={error} loading={loading} />;
  const cards = [
    [
      "Total events observed",
      d.total,
      Activity,
      "cyan",
      `${d.origins.simulation} simulated · ${d.origins.replay} replayed`,
    ],
    [
      "Suspicious events",
      d.suspicious,
      ShieldAlert,
      "orange",
      "Rule-based detections",
    ],
    ["High & critical alerts", d.high, Zap, "red", "Review and investigate"],
    [
      "Active blocks",
      d.blocks,
      ShieldCheck,
      "green",
      d.status.adapter === "simulated"
        ? "Simulated enforcement only"
        : "Configured adapter records",
    ],
  ] as const;
  return (
    <>
      <div className="overview-banner">
        <div>
          <span className="eyebrow">YOUR NETWORK. IN FOCUS.</span>
          <h2>Clarity at every connection.</h2>
          <p>
            Observe threats, investigate signals, and test your next defense.
          </p>
        </div>
        <div className="banner-shield">
          <ShieldCheck size={64} />
        </div>
        <div className="banner-status">
          <Badge tone="green">Workspace operational</Badge>
          <span>Network health: unmeasured</span>
          <small>Virtual topology · Research environment</small>
        </div>
      </div>
      <div className="metrics-grid">
        {cards.map(([title, value, Icon, tone, caption]) => (
          <div className="metric" key={title}>
            <div className="metric-label">
              {title}
              <span className={`metric-icon ${tone}`}>
                <Icon size={18} />
              </span>
            </div>
            <strong>{num(value)}</strong>
            <p>
              <span className={`dot ${tone}`} />
              {caption}
            </p>
          </div>
        ))}
      </div>
      <div className="chart-grid">
        <Panel
          title="Security activity"
          subtitle="Observed event volume · 5-minute buckets · UTC"
          action={<span className="subtle">Latest observations</span>}
        >
          <div className="chart-legend">
            <span>
              <i className="dot cyan" />
              All events
            </span>
            <span>
              <i className="dot violet" />
              Suspicious events
            </span>
          </div>
          <div className="chart">
            {d.timeline.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={d.timeline}>
                  <defs>
                    <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
                      <stop
                        offset="0%"
                        stopColor="#32c5d2"
                        stopOpacity={0.25}
                      />
                      <stop offset="100%" stopColor="#32c5d2" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    strokeDasharray="3 6"
                    vertical={false}
                    stroke="#233044"
                  />
                  <XAxis
                    dataKey="label"
                    stroke="#75869b"
                    tickLine={false}
                    axisLine={false}
                    minTickGap={25}
                  />
                  <YAxis
                    stroke="#75869b"
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                    width={32}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#142034",
                      border: "1px solid #314158",
                      borderRadius: 8,
                    }}
                  />
                  <Area
                    name="All events"
                    type="monotone"
                    dataKey="events"
                    stroke="#39d4df"
                    strokeWidth={2}
                    fill="url(#eventsFill)"
                  />
                  <Area
                    name="Suspicious"
                    type="monotone"
                    dataKey="threats"
                    stroke="#9b88ff"
                    strokeWidth={2}
                    fill="transparent"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <Empty />
            )}
          </div>
          <div className="chart-footer">
            <span>
              <CircleDot size={13} /> Actual stored observations
            </span>
            <span>{d.total} total events</span>
          </div>
        </Panel>
        <Panel
          title="Threat distribution"
          subtitle="Rule-based severity across stored events"
        >
          <div className="donut-wrap">
            <div className="donut">
              {d.total > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={d.severity}
                      dataKey="value"
                      innerRadius={64}
                      outerRadius={83}
                      stroke="none"
                      paddingAngle={4}
                    >
                      {d.severity.map((s: any, i: number) => (
                        <Cell key={s.name} fill={COLORS[i]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#142034",
                        border: "1px solid #314158",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : null}
              <div className="donut-center">
                <strong>{num(d.total)}</strong>
                <small>Total events</small>
              </div>
            </div>
            <div className="severity-legend">
              {d.severity.map((s: any, i: number) => (
                <div key={s.name}>
                  <span>
                    <i style={{ background: COLORS[i] }} />
                    {s.name}
                  </span>
                  <strong>{s.value}</strong>
                </div>
              ))}
            </div>
          </div>
          <div className="insight-strip">
            <Shield size={15} /> {d.high} events need a closer look
          </div>
        </Panel>
      </div>
      <Panel
        title="Recent security events"
        subtitle="The latest signals from your environment"
        action={
          <button
            className="text-button accent"
            onClick={() => navigate("Threat Detection")}
          >
            View all events <ArrowRight size={15} />
          </button>
        }
      >
        <EventTable events={d.recent} compact onEvent={onEvent} onIP={onIP} />
      </Panel>
      <div className="bottom-grid">
        <Panel
          title="Frequently observed sources"
          subtitle="Latest 10,000 observations"
        >
          {d.sources.length ? (
            d.sources.map((s: any, i: number) => (
              <button
                className="source-row"
                key={s.ip}
                onClick={() => onIP(s.ip)}
              >
                <span className="source-rank">0{i + 1}</span>
                <span className="mono">{s.ip}</span>
                <div className="source-bar">
                  <i
                    style={{
                      width: `${(100 * s.count) / (d.sources[0]?.count || 1)}%`,
                    }}
                  />
                </div>
                <span>{s.count} events</span>
                <ArrowUpRight size={15} />
              </button>
            ))
          ) : (
            <Empty />
          )}
        </Panel>
        <Panel
          title="Network risk trend"
          subtitle="Mean rule risk by observed time bucket"
        >
          <div className="chart short">
            {d.timeline.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={d.timeline}>
                  <XAxis
                    dataKey="label"
                    stroke="#75869b"
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="#75869b"
                    width={28}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#142034",
                      border: "1px solid #314158",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="risk"
                    stroke="#9b88ff"
                    fill="#9b88ff18"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <Empty />
            )}
          </div>
        </Panel>
        <div className="twin-promo">
          <span className="square-icon violet">
            <Network size={23} />
          </span>
          <Badge tone="violet">CYBERTWIN LAB</Badge>
          <h2>
            Test the defense.
            <br />
            Before you deploy.
          </h2>
          <p>
            Explore modeled attack paths and compare your next security change.
          </p>
          <button onClick={() => navigate("Network Digital Twin")}>
            Open digital twin <ArrowUpRight size={16} />
          </button>
        </div>
      </div>
      {!d.total && (
        <button
          className="primary"
          onClick={async () => {
            try {
              await send("/events/sample", {});
              notify("48 simulation events loaded");
              reload();
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Load simulation events
        </button>
      )}
      <DataState error={error} loading={false} />
    </>
  );
}

function EventsPage({
  threats,
  refresh,
  onEvent,
  onIP,
  notify,
  reload,
}: {
  threats: boolean;
  refresh: number;
  onEvent: (e: SecurityEvent) => void;
  onIP: (ip: string) => void;
  notify: Notify;
  reload: () => void;
}) {
  const [q, setQ] = useState(""),
    [severity, setSeverity] = useState(""),
    [origin, setOrigin] = useState(""),
    [page, setPage] = useState(1),
    [sort, setSort] = useState("timestamp"),
    [direction, setDirection] = useState("desc"),
    [importing, setImporting] = useState(false);
  const path = `/events?${new URLSearchParams({ q, severity, origin, page: String(page), suspicious: String(threats), sort, direction })}`;
  const { data, error, loading } = useData(path, refresh, true);
  const upload = async (file: File) => {
    setImporting(true);
    const body = new FormData();
    body.append("file", file);
    try {
      const r = await api("/events/import", { method: "POST", body });
      notify(`${r.count} replay events imported`);
      reload();
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setImporting(false);
    }
  };
  return (
    <>
      <div className="notice">
        <Radio size={19} />
        <span>
          {threats
            ? "Rule-based alerts identify signals that need review; they do not confirm a successful attack."
            : "This feed includes explicitly labeled simulation, replay, and configured live observations. Start monitoring to generate a simulation stream."}
        </span>
      </div>
      <div className="toolbar">
        <div className="search-input">
          <Search size={16} />
          <input
            aria-label="Search events"
            placeholder="Search IP, rule, or category…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <select
          aria-label="Filter severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          aria-label="Filter provenance"
          value={origin}
          onChange={(e) => {
            setOrigin(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All origins</option>
          {["simulation", "replay", "live"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          aria-label="Sort events"
          value={sort}
          onChange={(e) => setSort(e.target.value)}
        >
          <option value="timestamp">Time</option>
          <option value="risk">Risk score</option>
        </select>
        <button
          onClick={() => setDirection(direction === "desc" ? "asc" : "desc")}
        >
          {direction === "desc" ? "Descending" : "Ascending"}
        </button>
        <label className="button upload">
          <Upload size={16} />
          {importing ? "Importing…" : "Import replay"}
          <input
            disabled={importing}
            type="file"
            accept=".json,.jsonl,.csv"
            onChange={(e) => {
              if (e.target.files?.[0]) void upload(e.target.files[0]);
              e.target.value = "";
            }}
          />
        </label>
        <button onClick={() => download("csv")}>
          <Download size={16} />
          Export CSV
        </button>
      </div>
      <Panel
        title={threats ? "Detected threats" : "Event stream"}
        subtitle={`${data?.total ?? 0} matching observations`}
        action={
          <button
            onClick={async () => {
              try {
                await send("/events/sample", {});
                reload();
                notify("48 simulation events added");
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <Plus size={15} />
            Load sample
          </button>
        }
      >
        <DataState error={error} loading={loading} />
        {data && (
          <>
            <EventTable events={data.items} onEvent={onEvent} onIP={onIP} />
            <div className="pagination">
              <span>
                Page {page} of {Math.max(1, Math.ceil(data.total / 15))} · 15
                per page
              </span>
              <div>
                <button disabled={page === 1} onClick={() => setPage(page - 1)}>
                  Previous
                </button>
                <button
                  disabled={page * 15 >= data.total}
                  onClick={() => setPage(page + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Panel>
      <p className="footnote">
        Imports: JSON arrays, JSONL, Suricata EVE JSON, or flat CSV. Maximum 2
        MB / 1,000 records. Imported data is always REPLAY.
      </p>
    </>
  );
}

function EventDetail({
  event,
  onClose,
  onIP,
  notify,
  reload,
}: {
  event: SecurityEvent;
  onClose: () => void;
  onIP: (ip: string) => void;
  notify: Notify;
  reload: () => void;
}) {
  const [review, setReview] = useState(event.status);
  return (
    <Modal title={`Event #${event.id}`} onClose={onClose}>
      <div className="flex-row">
        <Badge tone={event.severity}>{event.severity}</Badge>
        <Badge>{event.origin}</Badge>
        <span className="mono">{event.rule}</span>
      </div>
      <div className="detail-grid">
        {[
          ["Observed source", `${event.src_ip}:${event.src_port ?? "—"}`],
          ["Target service", `${event.dst_ip}:${event.dst_port ?? "—"}`],
          ["Timestamp", date(event.timestamp)],
          ["Protocol", event.protocol],
          ["Rule risk", `${event.risk}/100`],
          [
            "ML score",
            event.ml_score === null
              ? "No prediction at ingestion"
              : `${event.ml_score}/100 (synthetic model)`,
          ],
          [
            "Model confidence",
            event.confidence === null
              ? "Unavailable"
              : `${Math.round(event.confidence * 100)}% (uncalibrated)`,
          ],
          ["Detection source", event.detection_source],
          ["Action", event.action],
        ].map(([k, v]) => (
          <div key={k}>
            <small>{k}</small>
            <strong>{v}</strong>
          </div>
        ))}
      </div>
      <h3>Detection evidence</h3>
      <ul className="evidence">
        {event.evidence.map((v, i) => (
          <li key={i}>{v}</li>
        ))}
      </ul>
      <details>
        <summary>Available flow features</summary>
        <pre>{JSON.stringify(event.features, null, 2)}</pre>
      </details>
      <label>
        Investigation status
        <select value={review} onChange={(e) => setReview(e.target.value)}>
          {["open", "investigating", "resolved", "false_positive"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>
      <div className="modal-actions">
        <button
          onClick={() => {
            onIP(event.src_ip);
            onClose();
          }}
        >
          Investigate source <ArrowUpRight size={15} />
        </button>
        <button
          className="primary"
          onClick={async () => {
            try {
              await send(`/events/${event.id}`, { status: review }, "PATCH");
              reload();
              notify("Investigation status saved");
              onClose();
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          Save review
        </button>
      </div>
    </Modal>
  );
}

export function BlockForm({
  ip = "",
  onClose,
  notify,
  reload,
}: {
  ip?: string;
  onClose: () => void;
  notify: Notify;
  reload: () => void;
}) {
  const [value, setValue] = useState(ip),
    [reason, setReason] = useState(""),
    [minutes, setMinutes] = useState(30),
    [preview, setPreview] = useState<any>(null),
    [busy, setBusy] = useState(false);
  return (
    <Modal title="Temporary source block" onClose={onClose}>
      <p className="subtle">
        Protected addresses and allowlists are checked before every action.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            const body = { ip: value, reason, minutes };
            if (!preview) {
              setPreview(await send("/blocks/preview", body));
            } else {
              await send("/blocks", { ...body, confirmed: true });
              notify(`Block recorded using ${preview.adapter} adapter`);
              reload();
              onClose();
            }
          } catch (e: any) {
            notify(e.message, true);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Source IP
          <input
            required
            value={value}
            disabled={!!preview}
            onChange={(e) => setValue(e.target.value)}
            placeholder="192.0.2.44"
          />
        </label>
        <label>
          Investigation reason
          <textarea
            required
            minLength={5}
            maxLength={500}
            disabled={!!preview}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
        <label>
          Duration (minutes)
          <input
            type="number"
            min={1}
            max={1440}
            required
            disabled={!!preview}
            value={minutes}
            onChange={(e) => setMinutes(Number(e.target.value))}
          />
        </label>
        {preview && (
          <div className="notice">
            <ShieldAlert />
            <div>
              <strong>
                {preview.adapter.toUpperCase()} · {preview.duration_minutes}{" "}
                minutes
              </strong>
              <p>{preview.effect}</p>
              {!preview.permitted_mode && (
                <p>
                  Detection-only is enabled. Change the mode in Settings before
                  applying.
                </p>
              )}
            </div>
          </div>
        )}
        <div className="modal-actions">
          {preview && (
            <button type="button" onClick={() => setPreview(null)}>
              Edit preview
            </button>
          )}
          <button
            className="primary"
            disabled={busy || (!!preview && !preview.permitted_mode)}
          >
            {busy
              ? "Working…"
              : preview
                ? "Confirm temporary block"
                : "Preview block"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function Investigation({
  initial,
  refresh,
  onEvent,
  notify,
  reload,
}: {
  initial: string;
  refresh: number;
  onEvent: (e: SecurityEvent) => void;
  notify: Notify;
  reload: () => void;
}) {
  const [input, setInput] = useState(initial),
    [ip, setIP] = useState(initial),
    [note, setNote] = useState(""),
    [blocking, setBlocking] = useState(false);
  useEffect(() => {
    setInput(initial);
    setIP(initial);
  }, [initial]);
  const {
    data: d,
    error,
    loading,
  } = useData(
    ip ? `/investigate/${encodeURIComponent(ip)}` : "/health",
    refresh,
  );
  return (
    <>
      <form
        className="investigation-search"
        onSubmit={(e) => {
          e.preventDefault();
          setIP(input);
        }}
      >
        <div className="search-input">
          <Search size={19} />
          <input
            aria-label="IP to investigate"
            placeholder="Enter an observed IPv4 or IPv6 address"
            required
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        </div>
        <button className="primary">
          Investigate IP <ArrowRight size={16} />
        </button>
      </form>
      <div className="notice">
        <CircleHelp size={20} />
        <span>
          An observed IP is not a person's identity. NAT, VPNs, proxies, shared
          addresses, and spoofing can affect attribution.
        </span>
      </div>
      {ip ? (
        <>
          <DataState error={error} loading={loading} />
          {d?.ip && (
            <>
              <Panel
                title={d.ip}
                subtitle="Observed source investigation"
                action={
                  <div className="flex-row">
                    <button onClick={() => download("json", d.ip)}>
                      <Download size={15} />
                      Export
                    </button>
                    <button
                      className="danger"
                      onClick={() => setBlocking(true)}
                    >
                      <Ban size={15} />
                      Block source
                    </button>
                  </div>
                }
              >
                <div className="detail-grid">
                  {[
                    ["Associated events", d.count],
                    ["Highest rule risk", `${d.risk}/100`],
                    [
                      "First seen",
                      d.first_seen ? date(d.first_seen) : "Not observed",
                    ],
                    [
                      "Last seen",
                      d.last_seen ? date(d.last_seen) : "Not observed",
                    ],
                    ["Protocols", d.protocols.join(", ") || "—"],
                    ["Ports", d.ports.join(", ") || "—"],
                    [
                      "Block status",
                      d.blocks.some((b: any) => b.state === "active")
                        ? "Active record (see Blocklist)"
                        : "No active block",
                    ],
                    [
                      "Related devices",
                      d.devices.map((v: any) => v.name).join(", ") ||
                        "No virtual asset match",
                    ],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <small>{k}</small>
                      <strong>{v}</strong>
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel
                title="Source event history"
                subtitle="Most recent 1,000 matching observations"
              >
                <EventTable
                  events={d.events}
                  onEvent={onEvent}
                  onIP={(v) => {
                    setInput(v);
                    setIP(v);
                  }}
                />
              </Panel>
              <div className="two-col">
                <Panel title="Investigation notes">
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      try {
                        await send(
                          `/investigate/${encodeURIComponent(ip)}/notes`,
                          { text: note },
                        );
                        setNote("");
                        reload();
                        notify("Note saved");
                      } catch (e: any) {
                        notify(e.message, true);
                      }
                    }}
                  >
                    <label>
                      Evidence and context
                      <textarea
                        required
                        maxLength={4000}
                        value={note}
                        onChange={(e) => setNote(e.target.value)}
                      />
                    </label>
                    <button className="primary">Save note</button>
                  </form>
                  {d.notes.map((n: any) => (
                    <div className="note" key={n.id}>
                      <small>
                        {n.author} · {date(n.timestamp)}
                      </small>
                      <p>{n.text}</p>
                    </div>
                  ))}
                </Panel>
                <Panel title="Recommended next steps">
                  {d.recommendations.map((r: string, i: number) => (
                    <div className="step" key={r}>
                      <span>0{i + 1}</span>
                      {r}
                    </div>
                  ))}
                </Panel>
              </div>
              {blocking && (
                <BlockForm
                  ip={ip}
                  onClose={() => setBlocking(false)}
                  notify={notify}
                  reload={reload}
                />
              )}
            </>
          )}
        </>
      ) : (
        <Empty text="Search a source IP or select an event to review evidence, targets, notes, and associated activity." />
      )}
    </>
  );
}

function Blocklist({
  refresh,
  notify,
  reload,
}: {
  refresh: number;
  notify: Notify;
  reload: () => void;
}) {
  const [q, setQ] = useState(""),
    [state, setState] = useState(""),
    [adding, setAdding] = useState(false),
    [remove, setRemove] = useState<any>(null);
  const { data, error, loading } = useData(
    `/blocks?${new URLSearchParams({ q, state })}`,
    refresh,
    true,
  );
  return (
    <>
      <div className="notice">
        <ShieldCheck />
        <span>
          Simulation blocks are database records and do not change packet
          handling. Expiry is automatic. Existing blocks remain when switching
          to detection-only.
        </span>
      </div>
      <div className="toolbar">
        <div className="search-input">
          <Search size={16} />
          <input
            placeholder="Search blocked IPs…"
            aria-label="Search blocklist"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <select
          aria-label="Block state"
          value={state}
          onChange={(e) => setState(e.target.value)}
        >
          <option value="">All states</option>
          {["active", "expired", "removed", "error", "pending"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <button className="primary" onClick={() => setAdding(true)}>
          <Plus size={16} />
          New temporary block
        </button>
      </div>
      <Panel
        title="Block records & history"
        subtitle="Latest 1,000 records · Adapter and verification are recorded for every action"
      >
        <DataState error={error} loading={loading} />
        {data?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Reason</th>
                  <th>Adapter</th>
                  <th>Status</th>
                  <th>Expires</th>
                  <th>Verification</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.map((b: any) => (
                  <tr key={b.id}>
                    <td className="mono">{b.ip}</td>
                    <td>
                      {b.reason}
                      <small>{date(b.created)}</small>
                    </td>
                    <td>{b.adapter}</td>
                    <td>
                      <Badge tone={b.state === "active" ? "high" : "cyan"}>
                        {b.state}
                      </Badge>
                    </td>
                    <td>{date(b.expires)}</td>
                    <td>
                      {b.verified
                        ? "Verified real action"
                        : "Simulation / unverified"}
                    </td>
                    <td>
                      {["active", "pending", "error"].includes(b.state) && (
                        <button onClick={() => setRemove(b)}>Remove</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          !loading && (
            <Empty text="No block records. Enable manual approval in Settings, then preview a simulated block." />
          )
        )}
      </Panel>
      {adding && (
        <BlockForm
          onClose={() => setAdding(false)}
          notify={notify}
          reload={reload}
        />
      )}
      {remove && (
        <Modal title="Remove source block?" onClose={() => setRemove(null)}>
          <p>
            Remove the {remove.adapter} block for <strong>{remove.ip}</strong>?
            The audit history will be retained.
          </p>
          <div className="modal-actions">
            <button onClick={() => setRemove(null)}>Cancel</button>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await api(`/blocks/${remove.id}?confirmed=true`, {
                    method: "DELETE",
                  });
                  notify("Block removed");
                  setRemove(null);
                  reload();
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Confirm removal
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function DeviceNode({ data }: NodeProps) {
  const d = data as any;
  const Icon =
    d.kind === "Database"
      ? Database
      : d.kind === "Router"
        ? Router
        : d.kind?.includes("orkstation") || d.kind === "Admin"
          ? Laptop
          : Server;
  return (
    <div
      className={`device-node ${d.exposed ? "exposed" : ""} ${d.initial ? "initial" : ""}`}
    >
      <Handle type="target" position={Position.Left} />
      <div className="device-icon">
        <Icon size={20} />
      </div>
      <div>
        <strong>{d.name}</strong>
        <small>{d.ip}</small>
      </div>
      {d.criticality >= 4 && <span className="critical-dot" />}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const nodeTypes = { device: DeviceNode };
function DeviceForm({
  device,
  onClose,
  notify,
  reload,
}: {
  device: any;
  onClose: () => void;
  notify: Notify;
  reload: () => void;
}) {
  const existing = !!device?.id;
  const [form, setForm] = useState(
    device || {
      id: "",
      name: "",
      kind: "Workstation",
      ip: "",
      criticality: 2,
      vulnerability: 3,
      x: 400,
      y: 100,
    },
  );
  return (
    <Modal
      title={existing ? "Edit virtual device" : "Add virtual device"}
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            await send(
              existing ? `/network/devices/${device.id}` : "/network/devices",
              form,
              existing ? "PUT" : "POST",
            );
            notify("Virtual device saved");
            reload();
            onClose();
          } catch (e: any) {
            notify(e.message, true);
          }
        }}
      >
        <div className="form-grid">
          {["id", "name", "kind", "ip"].map((k) => (
            <label key={k}>
              {k === "ip" ? "IP address" : k}
              <input
                required
                disabled={k === "id" && existing}
                value={form[k]}
                onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              />
            </label>
          ))}
          {["criticality", "vulnerability"].map((k) => (
            <label key={k}>
              {k} ({k === "criticality" ? "1–5" : "0–10"})
              <input
                required
                type="number"
                min={k === "criticality" ? 1 : 0}
                max={k === "criticality" ? 5 : 10}
                value={form[k]}
                onChange={(e) =>
                  setForm({ ...form, [k]: Number(e.target.value) })
                }
              />
            </label>
          ))}
        </div>
        <p className="subtle">
          This edits a virtual asset; no real device is contacted.
        </p>
        <div className="modal-actions">
          <button className="primary">Save device</button>
        </div>
      </form>
    </Modal>
  );
}

function Twin({
  refresh,
  notify,
  reload,
}: {
  refresh: number;
  notify: Notify;
  reload: () => void;
}) {
  const { data, error, loading } = useData("/network", refresh),
    { data: history } = useData("/twin/scenarios", refresh);
  const [initial, setInitial] = useState("web"),
    [blocked, setBlocked] = useState<number[]>([]),
    [patched, setPatched] = useState<string[]>([]),
    [isolated, setIsolated] = useState<string[]>([]),
    [result, setResult] = useState<any>(null),
    [device, setDevice] = useState<any>(null),
    [adding, setAdding] = useState(false),
    [selected, setSelected] = useState<any>(null),
    [remove, setRemove] = useState<any>(null),
    [source, setSource] = useState("web"),
    [target, setTarget] = useState("db"),
    [tab, setTab] = useState("Scenario"),
    [busy, setBusy] = useState(false);
  const toggle = <T,>(array: T[], value: T) =>
    array.includes(value)
      ? array.filter((x) => x !== value)
      : [...array, value];
  // Any topology or scenario edit invalidates displayed results until rerun.
  useEffect(() => {
    setResult(null);
  }, [refresh, initial, blocked, patched, isolated]);
  const nodes = useMemo(
    () =>
      data?.devices.map((d: any) => ({
        id: d.id,
        type: "device",
        position: { x: d.x, y: d.y },
        data: {
          ...d,
          initial: d.id === initial,
          exposed: result?.modified.critical_ids.includes(d.id),
        },
        draggable: false,
      })) || [],
    [data, initial, result],
  );
  const edges = useMemo(
    () =>
      data?.connections.map((e: any) => ({
        id: String(e.id),
        source: e.source,
        target: e.target,
        label: e.allowed && !blocked.includes(e.id) ? "" : "restricted",
        style: {
          stroke:
            !e.allowed || blocked.includes(e.id)
              ? "#fb657a"
              : result?.modified.paths.some((p: string[]) =>
                    p.some((v, i) => v === e.source && p[i + 1] === e.target),
                  )
                ? "#ad99ff"
                : "#3b637c",
          strokeWidth: 1.7,
          strokeDasharray:
            !e.allowed || blocked.includes(e.id) ? "4 5" : undefined,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#648fa7" },
      })) || [],
    [data, blocked, result],
  );
  if (!data) return <DataState error={error} loading={loading} />;
  const run = async () => {
    setBusy(true);
    try {
      setResult(
        await send("/twin/analyze", {
          initial,
          blocked_connections: blocked,
          patched,
          isolated,
        }),
      );
      notify("Simulated comparison calculated");
    } catch (e: any) {
      notify(e.message, true);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="notice violet-notice">
        <Network />
        <span>
          A virtual model of your network. Paths show modeled possibilities, not
          confirmed attacker movement. No scans or exploits are executed.
        </span>
      </div>
      <div className="twin-toolbar">
        <div className="segmented">
          {["Scenario", "Devices & connections", "Saved comparisons"].map(
            (t) => (
              <button
                className={tab === t ? "active" : ""}
                onClick={() => setTab(t)}
                key={t}
              >
                {t}
              </button>
            ),
          )}
        </div>
        <Badge tone="violet">SIMULATION ONLY</Badge>
      </div>
      {tab === "Saved comparisons" ? (
        <Panel title="Saved comparisons">
          {history?.length ? (
            history.map((h: any) => (
              <div className="history-row" key={h.id}>
                <div>
                  <strong>{h.name}</strong>
                  <small>
                    {date(h.timestamp)} · initial compromise:{" "}
                    {h.data.changes.initial}
                  </small>
                </div>
                <span>
                  {h.data.baseline.risk} → {h.data.modified.risk} modeled risk
                </span>
                <span>{h.data.modified.path_count} possible paths</span>
              </div>
            ))
          ) : (
            <Empty text="Run an analysis to save a baseline and modified scenario." />
          )}
        </Panel>
      ) : (
        <>
          <div className="twin-layout">
            <Panel
              title="Network topology"
              subtitle="Click an asset to inspect · Directed connections represent permitted access"
              action={
                <span className="subtle">
                  {data.devices.length} assets · {data.connections.length} links
                </span>
              }
            >
              <div className="network-canvas">
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  nodeTypes={nodeTypes}
                  fitView
                  fitViewOptions={{ padding: 0.18 }}
                  minZoom={0.2}
                  onNodeClick={(_, n) =>
                    setSelected(data.devices.find((d: any) => d.id === n.id))
                  }
                >
                  <Background color="#27384b" gap={22} />
                  <Controls showInteractive={false} />
                </ReactFlow>
              </div>
              <div className="chart-footer">
                <span>
                  <i className="dot violet" />
                  Initial compromise
                </span>
                <span>
                  <i className="dot red" />
                  Exposed critical asset after analysis
                </span>
              </div>
            </Panel>
            <Panel
              title="Defense workbench"
              subtitle="Design a what-if scenario"
            >
              <label>
                Simulated initial compromise
                <select
                  value={initial}
                  onChange={(e) => setInitial(e.target.value)}
                >
                  {data.devices.map((d: any) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
              </label>
              <h3>Patch vulnerabilities</h3>
              <div className="check-list">
                {data.devices
                  .filter((d: any) => d.vulnerability > 0)
                  .map((d: any) => (
                    <label className="check" key={d.id}>
                      <input
                        type="checkbox"
                        checked={patched.includes(d.id)}
                        onChange={() => setPatched(toggle(patched, d.id))}
                      />
                      <span>
                        {d.name}
                        <small>Vulnerability {d.vulnerability}/10</small>
                      </span>
                    </label>
                  ))}
              </div>
              <label>
                Isolate a virtual device
                <select
                  value={isolated[0] || ""}
                  onChange={(e) =>
                    setIsolated(e.target.value ? [e.target.value] : [])
                  }
                >
                  <option value="">No isolation</option>
                  {data.devices.map((d: any) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
              </label>
              <button className="primary full" onClick={run} disabled={busy}>
                <Play size={16} />
                {busy ? "Analyzing…" : "Run defense comparison"}
              </button>
            </Panel>
          </div>
          {tab === "Scenario" ? (
            <Panel
              title="Restrict access in this scenario"
              subtitle="Changes here affect only the modified scenario. Baseline topology is preserved."
            >
              <div className="connection-checks">
                {data.connections.map((c: any) => (
                  <label className="check" key={c.id}>
                    <input
                      type="checkbox"
                      checked={blocked.includes(c.id)}
                      onChange={() => setBlocked(toggle(blocked, c.id))}
                    />
                    <span>
                      {data.devices.find((d: any) => d.id === c.source)?.name}{" "}
                      <ArrowRight size={12} />{" "}
                      {data.devices.find((d: any) => d.id === c.target)?.name}
                      <small>
                        {c.allowed
                          ? "Baseline allows access"
                          : "Baseline already denies access"}
                      </small>
                    </span>
                  </label>
                ))}
              </div>
            </Panel>
          ) : (
            <>
              <Panel
                title="Virtual assets"
                action={
                  <button className="primary" onClick={() => setAdding(true)}>
                    <Plus size={15} />
                    Add device
                  </button>
                }
              >
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Device</th>
                        <th>IP address</th>
                        <th>Criticality</th>
                        <th>Vulnerability</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.devices.map((d: any) => (
                        <tr key={d.id}>
                          <td>
                            {d.name}
                            <small>{d.kind}</small>
                          </td>
                          <td className="mono">{d.ip}</td>
                          <td>{d.criticality}/5</td>
                          <td>{d.vulnerability}/10</td>
                          <td>
                            <div className="flex-row">
                              <button
                                onClick={() => setDevice(d)}
                                aria-label={`Edit ${d.name}`}
                              >
                                <Pencil size={14} />
                              </button>
                              <button
                                aria-label={`Delete ${d.name}`}
                                onClick={() =>
                                  setRemove({ type: "device", ...d })
                                }
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
              <Panel title="Connections & baseline access rules">
                <form
                  className="toolbar"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    try {
                      await send("/network/connections", {
                        source,
                        target,
                        allowed: true,
                      });
                      reload();
                      notify("Virtual connection created");
                    } catch (e: any) {
                      notify(e.message, true);
                    }
                  }}
                >
                  <select
                    aria-label="Connection source"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                  >
                    {data.devices.map((d: any) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <ArrowRight size={16} />
                  <select
                    aria-label="Connection target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  >
                    {data.devices.map((d: any) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <button>
                    <Plus size={15} />
                    Connect
                  </button>
                </form>
                {data.connections.map((c: any) => (
                  <div className="connection-row" key={c.id}>
                    <span>
                      {c.source} → {c.target}
                    </span>
                    <button
                      onClick={async () => {
                        try {
                          await send(
                            `/network/connections/${c.id}`,
                            { allowed: !c.allowed },
                            "PATCH",
                          );
                          reload();
                          notify("Virtual access rule updated");
                        } catch (e: any) {
                          notify(e.message, true);
                        }
                      }}
                    >
                      {c.allowed
                        ? "Allowed — click to deny"
                        : "Denied — click to allow"}
                    </button>
                    <button
                      aria-label={`Remove connection ${c.id}`}
                      onClick={() => setRemove({ type: "connection", ...c })}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </Panel>
            </>
          )}
          {result && (
            <>
              <Panel
                title="Baseline vs. proposed defense"
                subtitle="Calculated from this virtual graph · Scores are modeled, not measured improvements"
              >
                <div className="comparison">
                  <div className="chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={[
                          {
                            name: "Risk score",
                            Baseline: result.baseline.risk,
                            Modified: result.modified.risk,
                          },
                          {
                            name: "Critical assets",
                            Baseline: result.baseline.critical_assets.length,
                            Modified: result.modified.critical_assets.length,
                          },
                          {
                            name: "Possible paths",
                            Baseline: result.baseline.path_count,
                            Modified: result.modified.path_count,
                          },
                        ]}
                      >
                        <CartesianGrid stroke="#26354a" vertical={false} />
                        <XAxis dataKey="name" stroke="#8294ab" />
                        <YAxis stroke="#8294ab" />
                        <Tooltip
                          contentStyle={{
                            background: "#142034",
                            border: "1px solid #314158",
                          }}
                        />
                        <Legend />
                        <Bar
                          dataKey="Baseline"
                          fill="#9380f5"
                          radius={[4, 4, 0, 0]}
                        />
                        <Bar
                          dataKey="Modified"
                          fill="#3bd7cb"
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div>
                    <h3>Modeled changes</h3>
                    <p>
                      {blocked.length} restricted links · {patched.length}{" "}
                      patched assets · {isolated.length} isolated assets
                    </p>
                    <div className="risk-comparison">
                      <span>
                        {result.baseline.risk}
                        <small>Baseline risk</small>
                      </span>
                      <ArrowRight />
                      <span className="accent">
                        {result.modified.risk}
                        <small>Modified risk</small>
                      </span>
                    </div>
                    <p>
                      Reachable critical assets:{" "}
                      {result.modified.critical_assets.join(", ") || "None"}
                    </p>
                    <p className="subtle">
                      Operational cost: counts of modifications only. Downtime
                      and financial costs are not modeled.
                    </p>
                  </div>
                </div>
                <div className="formula">{result.modified.formula}</div>
              </Panel>
              <Panel
                title="Possible paths to critical assets"
                subtitle={
                  result.modified.truncated
                    ? "Results capped at 500 paths / 8 hops"
                    : "Directed reachability in the modified graph"
                }
              >
                {result.modified.paths.length ? (
                  result.modified.paths.map((p: string[], i: number) => (
                    <div className="path-row" key={i}>
                      <GitBranch size={16} />
                      {p.join(" → ")}
                    </div>
                  ))
                ) : (
                  <Empty text="No paths to critical assets within the bounded modeled graph." />
                )}
              </Panel>
            </>
          )}
        </>
      )}
      {(adding || device) && (
        <DeviceForm
          device={device}
          onClose={() => {
            setAdding(false);
            setDevice(null);
          }}
          notify={notify}
          reload={reload}
        />
      )}
      {selected && (
        <Modal title={selected.name} onClose={() => setSelected(null)}>
          <div className="detail-grid">
            {["kind", "ip", "criticality", "vulnerability"].map((k) => (
              <div key={k}>
                <small>{k}</small>
                <strong>{selected[k]}</strong>
              </div>
            ))}
          </div>
          <h3>Connected devices & access</h3>
          {data.connections
            .filter(
              (c: any) => c.source === selected.id || c.target === selected.id,
            )
            .map((c: any) => (
              <p key={c.id}>
                {c.source} → {c.target} · {c.allowed ? "allowed" : "denied"}
              </p>
            ))}
          <p className="notice">
            Virtual state:{" "}
            {isolated.includes(selected.id)
              ? "isolated"
              : patched.includes(selected.id)
                ? "patched"
                : "baseline"}{" "}
            · {selected.id === initial ? "initial compromise" : "modeled asset"}
          </p>
          <button
            onClick={() => {
              setDevice(selected);
              setSelected(null);
            }}
          >
            <Pencil size={15} />
            Edit virtual asset
          </button>
        </Modal>
      )}
      {remove && (
        <Modal
          title="Remove virtual topology item?"
          onClose={() => setRemove(null)}
        >
          <p>
            Remove {remove.name || `${remove.source} → ${remove.target}`}?
            Removing a device also removes its connections.
          </p>
          <div className="modal-actions">
            <button onClick={() => setRemove(null)}>Cancel</button>
            <button
              className="danger"
              onClick={async () => {
                try {
                  await api(
                    `/network/${remove.type === "device" ? "devices" : "connections"}/${remove.id}`,
                    { method: "DELETE" },
                  );
                  setRemove(null);
                  setBlocked([]);
                  setPatched([]);
                  setIsolated([]);
                  reload();
                  notify("Virtual topology item removed");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Remove
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function AIInsights({ refresh, notify }: { refresh: number; notify: Notify }) {
  const { data, error, loading } = useData("/ml/metrics", refresh);
  const [f, setF] = useState({
      duration: 12,
      packets: 400,
      bytes: 12000,
      frequency: 120,
      failed_auth: 8,
      criticality: 3,
      dst_port: 443,
    }),
    [prediction, setPrediction] = useState<any>(null);
  const m = data?.metrics,
    positive = m?.candidate?.["1"];
  return (
    <>
      <div className="notice violet-notice">
        <BrainCircuit />
        <span>
          Research model · Evaluated on a clearly identified synthetic flow
          dataset. Metrics describe this benchmark only and do not establish
          real-world detection accuracy.
        </span>
      </div>
      <DataState error={error} loading={loading} />
      {data && !data.available && (
        <div className="notice">
          <CircleHelp />
          <span>
            No trained model available. Rules remain functional. Run{" "}
            <code>python -m backend.ml</code> after migrations to train and
            persist the benchmark.
          </span>
        </div>
      )}
      {m && (
        <>
          <div className="metrics-grid">
            {[
              ["Precision", positive.precision],
              ["Recall", positive.recall],
              ["F1 score", positive["f1-score"]],
              ["False-positive rate", m.false_positive_rate],
            ].map(([label, value]) => (
              <div className="metric" key={label as string}>
                <div className="metric-label">{label}</div>
                <strong>
                  {((value as number) * 100).toFixed(1)}
                  <em>%</em>
                </strong>
                <p>Synthetic held-out test set</p>
              </div>
            ))}
          </div>
          <div className="two-col">
            <Panel
              title="Feature importance"
              subtitle="Global Random Forest impurity importance; not a per-event explanation"
            >
              <div className="chart">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={Object.entries(m.feature_importance).map(
                      ([name, value]) => ({ name, value }),
                    )}
                    layout="vertical"
                    margin={{ left: 35 }}
                  >
                    <XAxis type="number" stroke="#8294ab" />
                    <YAxis
                      type="category"
                      dataKey="name"
                      stroke="#8294ab"
                      width={85}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#142034",
                        border: "1px solid #314158",
                      }}
                    />
                    <Bar dataKey="value" fill="#a08cf7" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
            <Panel
              title="Confusion matrix"
              subtitle="Rows: actual class · Columns: predicted class"
            >
              <div className="matrix">
                <span />
                <span>Benign</span>
                <span>Suspicious</span>
                <span>Benign</span>
                <strong>
                  {m.confusion_matrix[0][0]}
                  <small>True negative</small>
                </strong>
                <strong className="wrong">
                  {m.confusion_matrix[0][1]}
                  <small>False positive</small>
                </strong>
                <span>Suspicious</span>
                <strong className="wrong">
                  {m.confusion_matrix[1][0]}
                  <small>False negative</small>
                </strong>
                <strong>
                  {m.confusion_matrix[1][1]}
                  <small>True positive</small>
                </strong>
              </div>
            </Panel>
          </div>
          <Panel title="Baseline comparison & evaluation design">
            <div className="detail-grid">
              <div>
                <small>Candidate weighted F1</small>
                <strong>
                  {m.candidate["weighted avg"]["f1-score"].toFixed(3)}
                </strong>
              </div>
              <div>
                <small>Majority-class baseline weighted F1</small>
                <strong>
                  {m.baseline["weighted avg"]["f1-score"].toFixed(3)}
                </strong>
              </div>
              <div>
                <small>Train / test rows</small>
                <strong>
                  {m.train_samples} / {m.test_samples}
                </strong>
              </div>
              <div>
                <small>Reproducible seed</small>
                <strong>{m.seed}</strong>
              </div>
            </div>
            <p className="subtle">
              {m.dataset}. {m.limitations}
            </p>
          </Panel>
        </>
      )}
      <Panel
        title="Try a flow prediction"
        subtitle="ML probability is separate from rule risk and the enforcement decision"
      >
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              const { dst_port, ...features } = f;
              setPrediction(await send("/ml/predict", { features, dst_port }));
            } catch (e: any) {
              notify(e.message, true);
            }
          }}
        >
          <div className="prediction-fields">
            {Object.entries(f).map(([key, value]) => (
              <label key={key}>
                {key.replaceAll("_", " ")}
                <input
                  type="number"
                  min={key === "criticality" ? 1 : 0}
                  step={key === "duration" ? "any" : "1"}
                  required
                  value={value}
                  onChange={(e) =>
                    setF({ ...f, [key]: Number(e.target.value) })
                  }
                />
              </label>
            ))}
          </div>
          <button className="primary">
            <BrainCircuit size={16} />
            Predict flow
          </button>
        </form>
        {prediction && (
          <div className="notice violet-notice">
            <BrainCircuit />
            <div>
              <strong>
                {prediction.available
                  ? `Synthetic model score: ${prediction.score}/100 · confidence ${(prediction.confidence * 100).toFixed(1)}%`
                  : "Model unavailable"}
              </strong>
              <p>{prediction.explanation}</p>
            </div>
          </div>
        )}
      </Panel>
    </>
  );
}

function Reports({ refresh, notify }: { refresh: number; notify: Notify }) {
  const { data, error, loading } = useData("/reports", refresh);
  return (
    <>
      <Panel
        title="Research security report"
        subtitle="Export a reproducible snapshot of observations, enforcement, modeling, and evaluation"
        action={<button onClick={() => window.print()}>Print report</button>}
      >
        <div className="report-options">
          {["json", "csv", "pdf"].map((format, i) => (
            <button
              key={format}
              className="report-option"
              onClick={() => download(format)}
            >
              <span className="square-icon">
                <FileChartColumn size={23} />
              </span>
              <strong>{format.toUpperCase()} report</strong>
              <span>
                {
                  [
                    "Full evidence, audit, ML and twin snapshot",
                    "Tabular event data with origin labels",
                    "Paginated research report with full evidence",
                  ][i]
                }
              </span>
              <span className="accent">
                Download <Download size={15} />
              </span>
            </button>
          ))}
        </div>
      </Panel>
      <DataState error={error} loading={loading} />
      {data && (
        <>
          <div className="metrics-grid">
            {[
              ["Events in report", data.summary.events],
              ["High-risk incidents", data.summary.high_risk],
              ["False-positive reviews", data.summary.false_positive_reviews],
              ["Enforcement records", data.blocks.length],
            ].map(([k, v]) => (
              <div className="metric" key={k}>
                <div className="metric-label">{k}</div>
                <strong>{num(v)}</strong>
                <p>Actual stored records</p>
              </div>
            ))}
          </div>
          <Panel title="Report scope & evidence">
            <div className="detail-grid">
              <div>
                <small>Generated at</small>
                <strong>{date(data.generated_at)}</strong>
              </div>
              <div>
                <small>Scope</small>
                <strong>{data.scope}</strong>
              </div>
              <div>
                <small>Latest twin comparison</small>
                <strong>
                  {data.twin
                    ? `${data.twin.data.baseline.risk} → ${data.twin.data.modified.risk} modeled risk`
                    : "No saved comparison"}
                </strong>
              </div>
              <div>
                <small>Model validation</small>
                <strong>
                  {typeof data.ml === "string"
                    ? "Unavailable"
                    : "Synthetic held-out evaluation"}
                </strong>
              </div>
            </div>
            <p className="notice">{data.limitations}</p>
            <details>
              <summary>Inspect report JSON</summary>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </details>
          </Panel>
        </>
      )}
    </>
  );
}

function SettingsPage({
  refresh,
  notify,
  reload,
  status,
}: {
  refresh: number;
  notify: Notify;
  reload: () => void;
  status: any;
}) {
  const { data: cfg, error, loading } = useData("/enforcement", refresh),
    { data: logs } = useData("/audit", refresh);
  const [form, setForm] = useState({
      mode: "detection",
      threshold: 85,
      duration_minutes: 30,
    }),
    [preview, setPreview] = useState<any>(null);
  useEffect(() => {
    if (cfg)
      setForm({
        mode: cfg.mode,
        threshold: cfg.threshold,
        duration_minutes: cfg.duration_minutes,
      });
  }, [cfg]);
  return (
    <>
      <div className="two-col">
        <Panel
          title="Integration status"
          subtitle="Connection states are checked by the backend"
        >
          {status &&
            Object.entries(status.integrations).map(([name, state]) => (
              <div className="integration-row" key={name}>
                <span className="square-icon">
                  {name === "ML model" ? (
                    <BrainCircuit size={19} />
                  ) : name === "Database" ? (
                    <Database size={19} />
                  ) : (
                    <Shield size={19} />
                  )}
                </span>
                <div>
                  <strong>{name}</strong>
                  <small>
                    {name === "Zeek"
                      ? "Optional integration; not implemented in this build"
                      : name === "Suricata"
                        ? "Server-owned EVE JSON tailer"
                        : name === "Firewall adapter"
                          ? status.adapter
                          : "Local research environment"}
                  </small>
                </div>
                <Badge
                  tone={
                    String(state).startsWith("connected")
                      ? "green"
                      : state === "error"
                        ? "critical"
                        : "neutral"
                  }
                >
                  {String(state)}
                </Badge>
              </div>
            ))}
        </Panel>
        <Panel
          title="Enforcement policy"
          subtitle="Consequential changes require a preview and explicit confirmation"
        >
          <DataState error={error} loading={loading} />
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                setPreview(await send("/enforcement/preview", form));
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <label>
              Operating mode
              <select
                value={form.mode}
                onChange={(e) => setForm({ ...form, mode: e.target.value })}
              >
                <option value="detection">Detection only (safe default)</option>
                <option value="manual">Manual approval</option>
                <option value="automatic">Automatic with safeguards</option>
              </select>
            </label>
            <div className="form-grid">
              <label>
                Automatic rule-risk threshold
                <input
                  type="number"
                  min={70}
                  max={100}
                  required
                  value={form.threshold}
                  onChange={(e) =>
                    setForm({ ...form, threshold: Number(e.target.value) })
                  }
                />
              </label>
              <label>
                Default block duration (minutes)
                <input
                  type="number"
                  min={1}
                  max={1440}
                  required
                  value={form.duration_minutes}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      duration_minutes: Number(e.target.value),
                    })
                  }
                />
              </label>
            </div>
            <button className="primary">
              <Eye size={15} />
              Preview policy change
            </button>
          </form>
          <p className="footnote">
            Rule risk drives enforcement. ML scores never independently trigger
            blocking. Automatic actions are capped at 10 per minute.
          </p>
        </Panel>
      </div>
      <Panel title="Protected addresses & deployment configuration">
        <div className="detail-grid">
          <div>
            <small>Protected networks</small>
            <strong className="mono">{cfg?.protected}</strong>
          </div>
          <div>
            <small>Additional allowlist</small>
            <strong className="mono">
              {cfg?.allowlist || "None configured"}
            </strong>
          </div>
          <div>
            <small>Adapter</small>
            <strong>{cfg?.adapter}</strong>
          </div>
          <div>
            <small>Live observation</small>
            <strong>
              {status?.live_configured
                ? "Configured; fresh records required"
                : "Not configured"}
            </strong>
          </div>
        </div>
        <div className="notice">
          <LockKeyhole />
          <span>
            Trusted networks, credentials, and real adapters are configured in
            the server environment. Real enforcement requires an explicitly
            enabled, verified Linux nftables lab and a recent live source event.
          </span>
        </div>
      </Panel>
      <Panel
        title="Audit trail"
        subtitle="Latest 200 authenticated, policy, enforcement, and investigation actions"
      >
        {logs?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Administrator</th>
                  <th>Action</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((l: any) => (
                  <tr key={l.id}>
                    <td>{date(l.timestamp)}</td>
                    <td>{l.actor}</td>
                    <td>{l.action}</td>
                    <td className="audit-detail">{JSON.stringify(l.detail)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty />
        )}
      </Panel>
      {preview && (
        <Modal
          title="Confirm enforcement policy"
          onClose={() => setPreview(null)}
        >
          <p>
            Adapter: <strong>{preview.adapter}</strong>
          </p>
          <div className="two-col">
            <div>
              <h3>Current policy</h3>
              <pre>{JSON.stringify(preview.before, null, 2)}</pre>
            </div>
            <div>
              <h3>Proposed policy</h3>
              <pre>{JSON.stringify(preview.after, null, 2)}</pre>
            </div>
          </div>
          <div className="notice">
            <ShieldAlert />
            <span>{preview.effect}</span>
          </div>
          <div className="modal-actions">
            <button onClick={() => setPreview(null)}>Cancel</button>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await send(
                    "/enforcement",
                    { ...preview.after, confirmed: true },
                    "PUT",
                  );
                  setPreview(null);
                  reload();
                  notify("Enforcement policy updated");
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              Confirm policy
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function App() {
  const [user, setUser] = useState<any>(null),
    [checking, setChecking] = useState(true),
    [page, setPage] = useState(
      () => decodeURIComponent(location.hash.slice(1)) || "Overview",
    ),
    [refresh, setRefresh] = useState(0),
    [ip, setIP] = useState(""),
    [event, setEvent] = useState<SecurityEvent | null>(null),
    [toast, setToast] = useState<{ text: string; bad: boolean } | null>(null),
    [sidebar, setSidebar] = useState(false),
    [monitorDialog, setMonitorDialog] = useState(false),
    [monitorMode, setMonitorMode] = useState("simulation");
  const notify: Notify = useCallback(
      (text, bad = false) => setToast({ text, bad }),
      [],
    ),
    reload = useCallback(() => setRefresh((x) => x + 1), []);
  const navigate = (p: string) => {
    setPage(p);
    location.hash = encodeURIComponent(p);
    setSidebar(false);
  };
  useEffect(() => {
    api("/auth/me")
      .then(setUser)
      .catch(() => {})
      .finally(() => setChecking(false));
    const expired = () => setUser(null);
    const hash = () =>
      setPage(decodeURIComponent(location.hash.slice(1)) || "Overview");
    window.addEventListener("session-expired", expired);
    window.addEventListener("hashchange", hash);
    return () => {
      window.removeEventListener("session-expired", expired);
      window.removeEventListener("hashchange", hash);
    };
  }, []);
  useEffect(() => {
    if (toast) {
      const id = setTimeout(() => setToast(null), 6000);
      return () => clearTimeout(id);
    }
  }, [toast]);
  const { data: status, error: statusError } = useData(
    user ? "/status" : "/health",
    refresh,
    !!user,
  );
  const onIP = (value: string) => {
    setIP(value);
    navigate("IP Investigation");
  };
  if (checking)
    return (
      <div className="app-loading">
        <Shield size={35} />
        <p>Opening CyberTwin AI…</p>
      </div>
    );
  if (!user)
    return (
      <Login
        onLogin={(u) => {
          setUser(u);
          reload();
        }}
      />
    );
  const subtitles: Record<string, string> = {
    Overview: "Your security posture, at a glance.",
    "Live Monitoring": "Every connection has a story. Follow the signal.",
    "Threat Detection": "Turn suspicious signals into informed decisions.",
    "IP Investigation": "Connect the evidence. Understand the source.",
    Blocklist: "Controlled prevention, with a complete audit trail.",
    "Network Digital Twin": "Explore the paths. Test a stronger defense.",
    "AI Insights": "Transparent intelligence, grounded in evaluation.",
    Reports: "Evidence you can review, reproduce, and share.",
    Settings: "Configure your research workspace with confidence.",
  };
  const common = { refresh, notify, reload };
  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebar ? "open" : ""}`}>
        <a
          href="#Overview"
          className="brand"
          onClick={() => navigate("Overview")}
        >
          <div className="brand-icon">
            <Shield size={25} />
          </div>
          <span>
            CyberTwin<span className="accent"> AI</span>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-avatar">
            <Layers size={19} />
          </span>
          <div>
            <strong>Research workspace</strong>
            <small>Local environment</small>
          </div>
          <ChevronRight size={14} />
        </div>
        <p className="nav-label">WORKSPACE</p>
        <nav>
          {NAV.map(([name, Icon]) => (
            <button
              key={name}
              className={page === name ? "active" : ""}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
              {page === name && <span className="nav-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="lab-card">
            <div>
              <span className="dot cyan" />
              Safe by design
            </div>
            <p>
              Explore with simulation.
              <br />
              Enforce with intention.
            </p>
            <Badge tone="neutral">LOCAL RESEARCH LAB</Badge>
          </div>
          <button
            className="profile"
            onClick={async () => {
              try {
                await send("/auth/logout", {});
                setUser(null);
              } catch (e: any) {
                notify(e.message, true);
              }
            }}
          >
            <span className="avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <span>
              <strong>{user.username}</strong>
              <small>Administrator · Sign out</small>
            </span>
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      {sidebar && (
        <button
          className="sidebar-scrim"
          aria-label="Close navigation"
          onClick={() => setSidebar(false)}
        />
      )}
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              onClick={() => setSidebar(true)}
            >
              <Menu size={21} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="topbar-right">
            <span className="connection">
              <span className={`dot ${statusError ? "red" : "green"}`} />
              {statusError ? "Connection error" : "API connected"}
            </span>
            <span className="top-divider" />
            <button
              className="icon-button"
              aria-label="Refresh workspace"
              title="Refresh workspace"
              onClick={reload}
            >
              <RefreshCw size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Open alert feed"
              onClick={() => navigate("Threat Detection")}
            >
              <Bell size={18} />
            </button>
            <span className="avatar small">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS</div>
              <h1>{page === "Overview" ? "Security overview" : page}</h1>
              <p>{subtitles[page]}</p>
            </div>
            <div className="page-actions">
              {page === "Overview" && (
                <button onClick={() => download("json")}>
                  <Download size={16} />
                  Export report
                </button>
              )}
              <button
                className={status?.monitoring ? "" : "primary"}
                onClick={() => {
                  setMonitorMode("simulation");
                  setMonitorDialog(true);
                }}
              >
                {status?.monitoring ? <Square size={15} /> : <Play size={15} />}
                {status?.monitoring ? "Stop monitoring" : "Start monitoring"}
              </button>
            </div>
          </div>
          <div className="mode-bar">
            <div>
              <Badge
                tone={status?.mode === "LIVE MONITORING" ? "green" : "cyan"}
              >
                {status?.mode || "CONNECTING"}
              </Badge>
              <span className="mode-detail">
                <i
                  className={`dot ${status?.monitoring ? "green" : "neutral"}`}
                />
                {status?.monitoring
                  ? "Monitoring active"
                  : "Monitoring stopped"}
              </span>
            </div>
            <span className="enforcement-label">
              <LockKeyhole size={13} />
              IPS ENFORCEMENT{" "}
              {status?.enforcement_enabled ? "ENABLED" : "DISABLED"}
              <span className="mode-detail">
                {status?.adapter === "simulated"
                  ? "Simulated adapter"
                  : status?.adapter}{" "}
                · {status?.enforcement?.mode || "detection"} mode
              </span>
            </span>
          </div>
          {statusError && (
            <div className="error" role="alert">
              {statusError}
            </div>
          )}
          {page === "Overview" ? (
            <Overview
              {...common}
              onEvent={setEvent}
              onIP={onIP}
              navigate={navigate}
            />
          ) : page === "Live Monitoring" || page === "Threat Detection" ? (
            <EventsPage
              {...common}
              threats={page === "Threat Detection"}
              onEvent={setEvent}
              onIP={onIP}
            />
          ) : page === "IP Investigation" ? (
            <Investigation {...common} initial={ip} onEvent={setEvent} />
          ) : page === "Blocklist" ? (
            <Blocklist {...common} />
          ) : page === "Network Digital Twin" ? (
            <Twin {...common} />
          ) : page === "AI Insights" ? (
            <AIInsights {...common} />
          ) : page === "Reports" ? (
            <Reports {...common} />
          ) : page === "Settings" ? (
            <SettingsPage {...common} status={status} />
          ) : (
            <Empty text="Use the sidebar to open a workspace page." />
          )}
          <footer>
            <span>
              <Shield size={13} /> CyberTwin AI{" "}
              <span className="subtle">
                / Intelligent defense through understanding
              </span>
            </span>
            <span>Research edition · Simulation-first</span>
          </footer>
        </main>
      </div>
      {event && (
        <EventDetail
          event={event}
          onClose={() => setEvent(null)}
          onIP={onIP}
          notify={notify}
          reload={reload}
        />
      )}
      {monitorDialog && (
        <Modal
          title={status?.monitoring ? "Stop monitoring?" : "Start monitoring"}
          onClose={() => setMonitorDialog(false)}
        >
          {status?.monitoring ? (
            <p>
              Stop collecting new events? Stored observations and blocks will be
              retained.
            </p>
          ) : (
            <>
              <label>
                Event source
                <select
                  value={monitorMode}
                  onChange={(e) => setMonitorMode(e.target.value)}
                >
                  <option value="simulation">
                    Simulation — generated local test events
                  </option>
                  <option value="live" disabled={!status?.live_configured}>
                    Suricata — explicitly configured live source
                  </option>
                </select>
              </label>
              <p className="notice">
                {monitorMode === "simulation"
                  ? "Generates labeled simulation events every 3 seconds. No real network traffic is captured."
                  : "Live status appears only after valid, fresh EVE records arrive from the configured source."}
              </p>
            </>
          )}
          <div className="modal-actions">
            <button onClick={() => setMonitorDialog(false)}>Cancel</button>
            <button
              className="primary"
              onClick={async () => {
                try {
                  await send("/monitor", {
                    running: !status?.monitoring,
                    mode: monitorMode,
                  });
                  setMonitorDialog(false);
                  reload();
                  notify(
                    status?.monitoring
                      ? "Monitoring stopped"
                      : "Monitoring started",
                  );
                } catch (e: any) {
                  notify(e.message, true);
                }
              }}
            >
              {status?.monitoring ? "Stop monitoring" : "Start monitoring"}
            </button>
          </div>
        </Modal>
      )}
      {toast && (
        <div
          className={`toast ${toast.bad ? "bad" : ""}`}
          role={toast.bad ? "alert" : "status"}
        >
          {toast.bad ? <ShieldAlert size={18} /> : <CheckCircle2 size={18} />}
          <span>{toast.text}</span>
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setToast(null)}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

const root = document.getElementById("root");
if (root) createRoot(root).render(<App />);
