import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { backendOptions, client, summary } from "./test/fixtures";
import App from "./App.svelte";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn(), confirm: vi.fn() }));

describe("desktop application workflows", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case "app_info": return { name: "VPN Appliance Manager", version: "0.1.0", status: "ready", system_username: "tester" };
        case "list_hosts": return [{ id: "host-1", display_name: "Lab host", ssh: { hostname: "192.0.2.1", port: 22, username: "tester", private_key_path: "key" }, created_at: "2026-07-31T12:00:00Z", updated_at: "2026-07-31T12:00:00Z" }];
        case "list_instance_summaries": return [summary("xray")];
        case "backend_options": return backendOptions;
        case "activity_logs": return [];
        case "list_clients": return [client("xray")];
        case "list_dns_records": return [];
        case "list_dns_hostlists": return [{ id: "list-1", name: "Global blocklist", url: "https://example.com/hosts", coverage: "Ads" }];
        case "list_backup_views": return [];
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it("loads lazily and keeps all global screens backend-aware", async () => {
    render(App);
    await waitFor(() => expect(screen.getByText("Lab host")).toBeTruthy());
    expect(invoke).not.toHaveBeenCalledWith("list_clients", expect.anything());
    expect(invoke).not.toHaveBeenCalledWith("list_dns_hostlists", expect.anything());
    expect(invoke).not.toHaveBeenCalledWith("list_backup_views", expect.anything());

    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    expect(screen.getByText("Xray VLESS")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Manage" })).toBeTruthy();

    await fireEvent.click(screen.getByRole("button", { name: "Clients" }));
    await waitFor(() => expect(screen.getByText("Xray VLESS client")).toBeTruthy());
    expect(document.body.textContent).not.toContain("10.64.0.2");

    await fireEvent.click(screen.getByRole("button", { name: "DNS" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Private DNS is not applicable" })).toBeTruthy());
    expect(screen.getByText(/does not provide a routed private DNS zone/)).toBeTruthy();
    await fireEvent.click(screen.getByRole("tab", { name: "Hostlists" }));
    await waitFor(() => expect(screen.getByText("Global blocklist")).toBeTruthy());

    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "No backups yet" })).toBeTruthy());

    await fireEvent.click(screen.getByRole("button", { name: "Logs" }));
    expect(screen.getByRole("heading", { name: "No activity" })).toBeTruthy();
    expect(invoke.mock.calls.some(([command]) => command === "inspect_host_view")).toBe(false);
    expect(invoke.mock.calls.some(([command]) => command === "health_view")).toBe(false);
  });

  it("reviews identity and safety impact before restoring an exact backup", async () => {
    const startup = invoke.getMockImplementation()!;
    invoke.mockImplementation(async (command: string, args?: unknown) => {
      if (command === "list_backup_views") return [{
        instance_id: "instance-xray", instance_name: "Xray VLESS appliance", backend: "xray", backend_name: "Xray VLESS",
        name: "pre-upgrade-20260731", created_at: "2026-07-31T12:00:00Z", reason: "pre_upgrade",
        protects_identity: true, restore_warning: "Existing client exports may change.",
      }];
      if (command === "preview_backup_restore") return {
        instance_id: "instance-xray", backup_name: "pre-upgrade-20260731", reason: "pre_upgrade",
        affected_clients: 1, identity_impact: "Restoring may replace the server identity and invalidate client exports.",
        creates_safety_backup: true, expected_state_hash: "restore-hash",
      };
      return startup(command, args);
    });
    render(App);
    await waitFor(() => expect(screen.getByText("Lab host")).toBeTruthy());
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Review restore" }));
    expect(await screen.findByText("Restoring may replace the server identity and invalidate client exports.")).toBeTruthy();
    expect(screen.getByText("Created before restore")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Restore this backup" })).toBeTruthy();
    expect(invoke).toHaveBeenCalledWith("preview_backup_restore", expect.objectContaining({ backupName: "pre-upgrade-20260731" }));
  });

  it("surfaces a rejected create call inside the active wizard", async () => {
    const startup = invoke.getMockImplementation()!;
    invoke.mockImplementation(async (command: string, args?: unknown) => {
      if (command === "create_instance") throw {
        code: "validation",
        message: "The private IPv4 subnet overlaps an existing instance.",
        remediation: "Go back and choose a different private subnet.",
        remote_state_changed: false,
      };
      return startup(command, args);
    });
    render(App);
    await waitFor(() => expect(screen.getByText("Lab host")).toBeTruthy());
    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    await fireEvent.click(screen.getByRole("button", { name: "Create instance" }));
    await fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await fireEvent.input(screen.getByLabelText("Display name"), { target: { value: "Rejected instance" } });
    await fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await fireEvent.click(screen.getByRole("button", { name: "Create" }));

    const alert = await screen.findByRole("alert");
    expect(screen.getByText("Instance creation failed")).toBeTruthy();
    expect(screen.getByText("The private IPv4 subnet overlaps an existing instance.")).toBeTruthy();
    expect(screen.getByText("Go back and choose a different private subnet.")).toBeTruthy();
    expect(alert.closest('[role="dialog"]')).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(alert));
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });
});
