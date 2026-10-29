// Isolated browser verification. Never uses the student's database or firewall.
import { createRequire } from "node:module";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const require = createRequire(path.join(root, "tools/video/package.json"));
const { chromium, expect, request } = require("@playwright/test");
const python =
  process.env.CYBERTWIN_PYTHON ||
  path.join(
    root,
    process.platform === "win32"
      ? ".venv/Scripts/python.exe"
      : ".venv/bin/python",
  );
const work = path.join(root, ".cache", "cn-e2e-" + Date.now());
fs.mkdirSync(work, { recursive: true });
const origin = "http://127.0.0.1:8004";
const password = crypto.randomBytes(24).toString("hex");
const env = {
  ...process.env,
  DATABASE_URL: "sqlite:///" + path.join(work, "demo.db").replaceAll("\\", "/"),
  MODEL_PATH: path.join(work, "model.joblib"),
  ADMIN_USERNAME: "browser_reviewer",
  ADMIN_PASSWORD: password,
  FIREWALL_ADAPTER: "simulated",
  REAL_ENFORCEMENT: "false",
  SURICATA_EVE_PATH: "",
  SURICATA_LIVE_CONFIRMED: "false",
  CORS_ORIGINS: origin,
};
function setup(args) {
  const r = spawnSync(python, args, {
    cwd: root,
    env,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120000,
  });
  if (r.status !== 0) throw Error(r.stderr || r.stdout || "Setup failed");
}
setup(["-m", "alembic", "upgrade", "head"]);
setup(["-m", "backend.manage", "create-admin"]);
setup([
  "-c",
  "from backend.db import SessionLocal; from backend.seed import seed_topology,extend_cn_topology; db=SessionLocal(); seed_topology(db); extend_cn_topology(db); db.close()",
]);
setup(["-m", "backend.ml"]);
const log = fs.openSync(path.join(work, "server.log"), "w");
const server = spawn(
  python,
  [
    "-m",
    "uvicorn",
    "backend.main:app",
    "--host",
    "127.0.0.1",
    "--port",
    "8004",
    "--no-access-log",
  ],
  { cwd: root, env, windowsHide: true, stdio: ["ignore", log, log] },
);
fs.closeSync(log);
let browser, client;
const errors = [];
const results = [];
try {
  for (let n = 0; n < 100; n++) {
    try {
      if ((await fetch(origin + "/api/health")).ok) break;
    } catch {}
    if (n === 99) throw Error("Test server unavailable");
    await new Promise((r) => setTimeout(r, 200));
  }
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const p = await context.newPage();
  p.on("pageerror", (e) => errors.push(e.message));
  await p.goto(origin);
  await p.getByLabel("Username").fill(env.ADMIN_USERNAME);
  await p.getByLabel("Password", { exact: true }).fill(password);
  await p
    .getByRole("button", { name: "Sign in securely", exact: true })
    .click();
  await expect(
    p.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  results.push("Browser login");
  const nav = async (name) => {
    await p.locator("nav").getByRole("button", { name, exact: true }).click();
    await expect(
      p.getByRole("heading", { name, exact: true }).first(),
    ).toBeVisible();
  };
  await nav("PCAP & Traffic Analysis");
  await p
    .getByLabel("Upload capture or logs")
    .setInputFiles(path.join(root, "samples/cn-demo.pcap"));
  await expect(
    p.getByText("Offline replay stored: 11 new observations"),
  ).toBeVisible({ timeout: 20000 });
  await expect(
    p.getByRole("row").filter({ hasText: "192.0.2.44:46007" }),
  ).toBeVisible();
  const alert = p.getByRole("row").filter({ hasText: "192.0.2.44:46007" });
  await alert.getByRole("button", { name: "Inspect flow" }).click();
  await expect(p.getByRole("dialog")).toBeVisible();
  await expect(p.getByText(/SCAN-001/).first()).toBeVisible();
  await expect(
    p
      .getByRole("dialog")
      .getByText(/detection_only/)
      .first(),
  ).toBeVisible();
  await p.screenshot({
    path: path.join(work, "traffic-journey.png"),
    fullPage: true,
  });
  await p.getByRole("button", { name: "Close", exact: true }).click();
  results.push("PCAP replay, exact evidence and detection-only decision");
  await p.getByLabel("protocol", { exact: true }).selectOption("UDP");
  await expect(
    p.getByRole("row").filter({ hasText: "10.10.2.53:53" }),
  ).toBeVisible();
  await p.getByRole("button", { name: "Reset filters" }).click();
  await p
    .getByLabel("Upload capture or logs")
    .setInputFiles(path.join(root, "samples/cn-demo.pcap"));
  await expect(
    p.getByText("Offline replay stored: 0 new observations"),
  ).toBeVisible({ timeout: 20000 });
  await p.screenshot({
    path: path.join(work, "traffic-analysis.png"),
    fullPage: true,
  });
  results.push("Protocol filter and duplicate replay");
  // Change policy only in this disposable DB through authenticated administrator API.
  client = await request.newContext({
    baseURL: origin,
    storageState: await context.storageState(),
  });
  let r = await client.put("/api/enforcement", {
    data: { mode: "manual", threshold: 70, confirmed: true },
  });
  expect(r.status()).toBe(200);
  await alert.getByRole("button", { name: "Inspect flow" }).click();
  await p.getByRole("button", { name: "Preview prevention" }).click();
  await p.getByRole("button", { name: "Confirm temporary block" }).click();
  await expect(
    p.getByText("Prevention outcome recorded", { exact: true }),
  ).toBeVisible();
  await expect(
    p
      .getByRole("dialog")
      .getByText(/NO REAL PACKETS WERE BLOCKED/)
      .first(),
  ).toBeVisible();
  await p.getByRole("button", { name: "Close", exact: true }).click();
  results.push("Explicit simulated alert approval and timeline");
  await nav("Network Digital Twin");
  await p
    .getByRole("button", { name: "Observed traffic", exact: true })
    .click();
  await expect(
    p.getByRole("heading", {
      name: "Observed traffic on the virtual topology",
    }),
  ).toBeVisible();
  await p.getByRole("button", { name: "Replay stored observations" }).click();
  await p.getByRole("button", { name: "Pause", exact: true }).click();
  await p.getByLabel("Speed", { exact: true }).selectOption("2");
  await p.getByLabel("Reduced motion", { exact: true }).check();
  await p.getByLabel("Flow replay timeline").focus();
  await p.getByLabel("Flow replay timeline").press("Home");
  await p.getByLabel("Flow replay timeline").press("ArrowRight");
  await p.getByLabel("Flow replay timeline").press("ArrowRight");
  await p.getByRole("button", { name: "Inspect selected flow" }).click();
  await expect(p.getByText(/MODELED PATH/).first()).toBeVisible();
  await p.getByRole("button", { name: "Close", exact: true }).click();
  await p.screenshot({
    path: path.join(work, "observed-network.png"),
    fullPage: true,
  });
  results.push("Observed map, playback, scrub, reduced motion and linked flow");

  // Verify a persisted position from actual pointer dragging, then a what-if comparison.
  const webNode = p.locator('.react-flow__node[data-id="web"]');
  await webNode.scrollIntoViewIfNeeded();
  const webBox = await webNode.boundingBox();
  if (!webBox) throw Error("Web node not visible");
  await p.mouse.move(webBox.x + webBox.width / 2, webBox.y + webBox.height / 2);
  await p.mouse.down();
  await p.mouse.move(
    webBox.x + webBox.width / 2 + 35,
    webBox.y + webBox.height / 2 + 20,
    { steps: 12 },
  );
  await p.mouse.up();
  await expect(
    p.getByText("Virtual device position saved", { exact: true }),
  ).toBeVisible();
  const savedTopology = await (await client.get("/api/network")).json();
  expect(savedTopology.devices.find((d) => d.id === "web").x).not.toBe(460);
  results.push("Pointer drag saves virtual device position");
  await p.getByRole("button", { name: "Scenario", exact: true }).click();
  await p
    .getByRole("checkbox", { name: /Application server.*Vulnerability/ })
    .check();
  await p
    .getByRole("checkbox", { name: /Public web server.*Research database/ })
    .check();
  await p.getByRole("button", { name: "Run defense comparison" }).click();
  await expect(
    p.getByRole("heading", { name: "Possible paths to critical assets" }),
  ).toBeVisible();
  const comparisons = await (await client.get("/api/twin/scenarios")).json();
  expect(comparisons[0].data.modified.risk).toBeLessThan(
    comparisons[0].data.baseline.risk,
  );
  results.push(
    "Browser defense comparison and persisted modeled-risk reduction",
  );
  await nav("PCAP & Traffic Analysis");
  await p
    .getByRole("row")
    .filter({ hasText: "192.0.2.44:46007" })
    .getByRole("button", { name: "Inspect flow" })
    .click();
  await p.getByRole("button", { name: "Investigate observed source" }).click();
  await expect(
    p.getByRole("heading", { name: "IP Investigation", exact: true }),
  ).toBeVisible();
  results.push("Flow-to-source investigation navigation");
  await nav("AI Insights");
  await p.getByRole("button", { name: "Predict flow", exact: true }).click();
  await expect(p.getByText(/Model score:/)).toBeVisible();
  results.push("Model evidence and actual prediction");
  const exportResult = await client.get("/api/traffic/export");
  expect(exportResult.status()).toBe(200);
  expect((await exportResult.json()).analytics.packets).toBe(13);
  const pdf = await client.get("/api/reports/export?format=pdf");
  expect(pdf.status()).toBe(200);
  expect((await pdf.body()).subarray(0, 4).toString()).toBe("%PDF");
  results.push("Same-observation JSON analytics and PDF report");
  await p.goto(origin + "/#Settings");
  await expect(
    p.getByRole("heading", { name: "Integration status", exact: true }),
  ).toBeVisible();
  await expect(p.getByLabel("Operating mode")).toHaveValue("manual");
  results.push("Direct Settings navigation survives initial health/status loading");
  await p.setViewportSize({ width: 390, height: 844 });
  await p.screenshot({ path: path.join(work, "mobile.png"), fullPage: true });
  expect(errors).toEqual([]);
  fs.writeFileSync(
    path.join(work, "results.json"),
    JSON.stringify(
      { results, pageErrors: errors, server: "isolated simulation only" },
      null,
      2,
    ),
  );
  console.log(
    JSON.stringify({ results, pageErrors: errors, artifacts: work }, null, 2),
  );
} finally {
  await client?.dispose();
  await browser?.close();
  server.kill();
}
