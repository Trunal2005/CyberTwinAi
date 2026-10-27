// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { api, send } from "./api";

afterEach(() => vi.restoreAllMocks());
it("sends credentials and explicit administrator confirmation", async () => {
  const mock = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue({
      ok: true,
      json: async () => ({ state: "active", adapter: "simulated" }),
    } as Response);
  const result = await send("/blocks", { ip: "192.0.2.44", confirmed: true });
  expect(result.adapter).toBe("simulated");
  expect(mock.mock.calls[0][1]?.credentials).toBe("include");
  expect(JSON.parse(mock.mock.calls[0][1]?.body as string).confirmed).toBe(
    true,
  );
});
it("surfaces validation and enforcement errors", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: false,
    status: 409,
    json: async () => ({ error: { message: "Detection-only mode" } }),
  } as Response);
  await expect(send("/blocks", {})).rejects.toThrow("Detection-only mode");
});
it("expires the application session on an authenticated endpoint rejection", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: false,
    status: 401,
    json: async () => ({}),
  } as Response);
  const expired = vi.fn();
  window.addEventListener("session-expired", expired);
  await expect(api("/events")).rejects.toThrow();
  expect(expired).toHaveBeenCalledOnce();
  window.removeEventListener("session-expired", expired);
});
