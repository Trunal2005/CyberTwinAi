// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BlockForm, Login, Modal } from "./main";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
it("signs in and reports the authenticated profile", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: true,
    json: async () => ({ username: "operator", role: "admin" }),
  } as Response);
  const onLogin = vi.fn(),
    user = userEvent.setup();
  render(<Login onLogin={onLogin} />);
  await user.type(screen.getByLabelText("Username"), "operator");
  await user.type(screen.getByLabelText("Password"), "local-test-passphrase");
  await user.click(screen.getByRole("button", { name: "Sign in securely" }));
  expect(onLogin).toHaveBeenCalledWith({ username: "operator", role: "admin" });
});
it("requires a successful preview before confirming a simulated block", async () => {
  const mock = vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(
      async (path) =>
        ({
          ok: true,
          json: async () =>
            String(path).endsWith("preview")
              ? {
                  adapter: "simulated",
                  duration_minutes: 30,
                  effect: "No packets affected",
                  permitted_mode: true,
                }
              : { state: "active" },
        }) as Response,
    );
  const close = vi.fn(),
    notify = vi.fn(),
    reload = vi.fn(),
    user = userEvent.setup();
  render(
    <BlockForm
      ip="192.0.2.44"
      onClose={close}
      notify={notify}
      reload={reload}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "Confirm temporary block" }),
  ).toBeNull();
  await user.type(
    screen.getByLabelText("Investigation reason"),
    "Reviewed lab signal",
  );
  await user.click(screen.getByRole("button", { name: "Preview block" }));
  expect(mock).toHaveBeenCalledTimes(1);
  expect(screen.getByText("No packets affected")).toBeTruthy();
  await user.click(
    screen.getByRole("button", { name: "Confirm temporary block" }),
  );
  expect(mock).toHaveBeenCalledTimes(2);
  expect(JSON.parse(mock.mock.calls[1][1]?.body as string).confirmed).toBe(
    true,
  );
  expect(close).toHaveBeenCalled();
  expect(reload).toHaveBeenCalled();
});
it("prevents confirmation in detection-only mode", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: true,
    json: async () => ({ adapter: "simulated", permitted_mode: false }),
  } as Response);
  const user = userEvent.setup();
  render(
    <BlockForm
      ip="192.0.2.44"
      onClose={() => {}}
      notify={() => {}}
      reload={() => {}}
    />,
  );
  await user.type(
    screen.getByLabelText("Investigation reason"),
    "Investigated sample",
  );
  await user.click(screen.getByRole("button", { name: "Preview block" }));
  expect(
    (
      screen.getByRole("button", {
        name: "Confirm temporary block",
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
});
it("closes the accessible dialog on Escape", async () => {
  const close = vi.fn(),
    user = userEvent.setup();
  render(
    <Modal title="Review evidence" onClose={close}>
      <button>Done</button>
    </Modal>,
  );
  expect(screen.getByRole("dialog", { name: "Review evidence" })).toBeTruthy();
  await user.keyboard("{Escape}");
  expect(close).toHaveBeenCalledOnce();
});
