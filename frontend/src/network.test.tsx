// @vitest-environment jsdom
import React from "react";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ api: vi.fn(), send: vi.fn() }));
vi.mock("./api", () => mocks);
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ children }: any) => <div>{children}</div>,
  Background: () => null,
  Controls: () => null,
  MarkerType: { ArrowClosed: "arrow" },
}));
vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  AreaChart: () => null,
  Area: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  CartesianGrid: () => null,
}));
import { TrafficAnalysis, FlowEvidence, ObservedNetwork } from "./network";
const analytics = {
  flows: 0,
  packets: null,
  bytes: null,
  packet_coverage: 0,
  byte_coverage: 0,
  rate_bps: null,
  normal: 0,
  suspicious: 0,
  duration_mean: null,
  directional_bytes: { source: null, destination: null },
  timeline: [],
  protocols: [],
  sources: [],
  destinations: [],
  ports: [],
  conversations: [],
};
afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.api.mockImplementation(async (path: string) =>
    path === "/status"
      ? {
          mode: "REPLAY",
          monitoring: false,
          collector: { parse_errors: 0, backlog_bytes: 0 },
        }
      : { items: [], total: 0, analytics },
  );
});

it("shows honest unavailable values and sends capture to authenticated replay endpoint", async () => {
  const reload = vi.fn(),
    notify = vi.fn();
  render(<TrafficAnalysis refresh={0} notify={notify} reload={reload} />);
  await screen.findByText(/No matching observations/);
  expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(0);
  mocks.api.mockImplementation(async (path: string) =>
    path === "/traffic/pcap"
      ? { new_events: 11 }
      : path === "/status"
        ? {}
        : { items: [], total: 0, analytics },
  );
  const file = new File(["capture"], "owned.pcap", {
    type: "application/octet-stream",
  });
  fireEvent.change(screen.getByLabelText("Upload capture or logs"), {
    target: { files: [file] },
  });
  await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  expect(mocks.api).toHaveBeenCalledWith(
    "/traffic/pcap",
    expect.objectContaining({ method: "POST", body: expect.any(FormData) }),
  );
  expect(notify).toHaveBeenCalledWith(
    "Offline replay stored: 11 new observations",
  );
});

it("flow filters change the query and reports upload failures", async () => {
  const notify = vi.fn();
  render(<TrafficAnalysis refresh={0} notify={notify} reload={() => {}} />);
  await screen.findByText(/No matching observations/);
  fireEvent.change(screen.getByLabelText("protocol"), {
    target: { value: "UDP" },
  });
  await waitFor(() =>
    expect(mocks.api).toHaveBeenCalledWith(
      expect.stringContaining("protocol=UDP"),
    ),
  );
  mocks.api.mockRejectedValueOnce(new Error("Malformed capture"));
  fireEvent.change(screen.getByLabelText("Upload capture or logs"), {
    target: { files: [new File(["bad"], "bad.pcap")] },
  });
  await waitFor(() =>
    expect(notify).toHaveBeenCalledWith("Malformed capture", true),
  );
});

it("connects missing features, modeled hops and simulated IPS evidence without a real-drop claim", async () => {
  mocks.api.mockResolvedValue({
    flow: {
      id: "abc",
      origin: "replay",
      sensor: "pcap",
      src_ip: "192.0.2.1",
      dst_ip: "10.10.1.10",
      protocol: "TCP",
      availability: { packets: false },
      limitations: [],
    },
    modeled_path: ["user", "web"],
    path_label: "MODELED PATH — transit hops were not observed",
    events: [],
    decisions: [
      {
        id: 1,
        outcome: "simulated",
        timestamp: "2026-01-01",
        steps: [
          {
            stage: "Adapter",
            result: "SIMULATED — NO REAL PACKETS WERE BLOCKED",
          },
        ],
        block: {
          id: 1,
          adapter: "simulated",
          state: "active",
          expires: "2026-01-02",
        },
      },
    ],
    ml: {
      available: true,
      score: 52,
      model_version: "synthetic-v1",
      missing_features: ["failed_auth"],
      imputation: "Training-partition feature means",
      explanation: "Independent of IDS and IPS",
    },
  });
  render(<FlowEvidence id="abc" />);
  await screen.findByText(/user → web/);
  expect(screen.getByText(/missing: failed_auth/)).toBeTruthy();
  expect(
    screen.getAllByText(/NO REAL PACKETS WERE BLOCKED/).length,
  ).toBeGreaterThan(0);
});

it("empty observed map has usable pause, speed and reduced-motion controls", async () => {
  mocks.api.mockResolvedValue({ flows: [] });
  render(
    <ObservedNetwork
      topology={{ devices: [], connections: [] }}
      refresh={0}
      notify={() => {}}
    />,
  );
  await screen.findByText(/No observed flows/);
  expect(
    (screen.getByRole("button", { name: "Play" }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  fireEvent.change(screen.getByLabelText("Speed"), { target: { value: "2" } });
  expect((screen.getByLabelText("Speed") as HTMLSelectElement).value).toBe("2");
  fireEvent.click(screen.getByLabelText("Reduced motion"));
  expect(
    (screen.getByLabelText("Reduced motion") as HTMLInputElement).checked,
  ).toBe(true);
});
