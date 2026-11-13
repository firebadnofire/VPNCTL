import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { beforeEach, expect, it, vi } from "vitest";
import BlockingContent from "./BlockingContent.svelte";
import type { BlockingView } from "../remote-types";
const invoke = vi.hoisted(() => vi.fn());
const confirm = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ confirm }));
let view: BlockingView;
beforeEach(() => {
  invoke.mockReset(); confirm.mockReset(); confirm.mockResolvedValue(true);
  view = { scheduler_available: true, state: { policy: { revision: 0, enabled: false, schedule_enabled: true, interval_days: 7, sources: [] }, sources: [], last_attempt: null, last_success: null, dataset_version: null, applied_version: null, applied_at: null, error: null, pending_request: null } };
  invoke.mockResolvedValue(view);
});
const notify = vi.fn();
function mount(supported = true) {
  return render(BlockingContent, { hostId: "host", instanceId: "vpn", online: true, supported, busy: "", run: async (_label, action) => { try { return await action(); } catch { return undefined; } }, notify });
}
it("loads per-instance policy with a seven-day default and saves independently", async () => {
  mount(); await screen.findByRole("button", { name: "Add blocking source" });
  expect((screen.getByLabelText("Refresh automatically") as HTMLInputElement).checked).toBe(true);
  expect((screen.getByLabelText("Refresh interval (days)") as HTMLInputElement).value).toBe("7");
  await fireEvent.click(screen.getByRole("button", { name: "Add blocking source" }));
  await fireEvent.input(screen.getByLabelText("Source 1 name"), { target: { value: "Ads" } });
  await fireEvent.input(screen.getByLabelText("Source 1 URL"), { target: { value: "http://example.test/hosts" } });
  expect(screen.getByText(/HTTP sources are not authenticated/)).toBeTruthy();
  await fireEvent.click(screen.getByLabelText("Refresh automatically"));
  await fireEvent.submit(screen.getByRole("button", { name: "Save blocking settings" }).closest("form")!);
  await waitFor(() => expect(invoke.mock.calls).toHaveLength(2));
  expect(invoke.mock.calls[1]).toEqual(["remote_blocking", expect.objectContaining({ hostId: "host", instanceId: "vpn", action: expect.objectContaining({ action: "save", expected_revision: 0, policy: expect.objectContaining({ enabled: true, schedule_enabled: false, interval_days: 7 }) }) })]);
});
it("requires source removal confirmation and keeps edits until saved", async () => {
  view.state.policy.sources = [{ id: "source", name: "Ads", url: "https://example.test/list", enabled: true }];
  mount(); await screen.findByLabelText("Source 1 name");
  confirm.mockResolvedValueOnce(false);
  await fireEvent.click(screen.getByRole("button", { name: "Remove source" }));
  expect(screen.getByLabelText("Source 1 name")).toBeTruthy();
  await fireEvent.click(screen.getByRole("button", { name: "Remove source" }));
  await waitFor(() => expect(screen.queryByLabelText("Source 1 name")).toBeNull());
  expect(invoke.mock.calls).toHaveLength(1);
});
it("retries a lost refresh response with the same request and shows stale status", async () => {
  view.state.policy.enabled = true; view.state.policy.revision = 3;
  mount(); await screen.findByRole("button", { name: "Refresh now" });
  invoke.mockRejectedValueOnce({ message: "Lost response" });
  await fireEvent.click(screen.getByRole("button", { name: "Refresh now" }));
  const retry = await screen.findByRole("button", { name: "Retry blocking update" });
  view.state.error = "Unchanged source download failed; using stale data.";
  await fireEvent.click(retry);
  await screen.findByText(/Unchanged source download failed/);
  expect(invoke.mock.calls[1][1]).toEqual(invoke.mock.calls[2][1]);
});
it("explains missing helper support without issuing a request", () => {
  mount(false); expect(screen.getByText(/Reconnect to repair this server/)).toBeTruthy(); expect(invoke).not.toHaveBeenCalled();
});
