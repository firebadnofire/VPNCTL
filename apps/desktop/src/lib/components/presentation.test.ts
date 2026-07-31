import { fireEvent, render, screen } from "@testing-library/svelte";
import { describe, expect, it, vi } from "vitest";
import { backendOptions, client, instance, summary } from "../../test/fixtures";
import BackendBadge from "./BackendBadge.svelte";
import BackupsContent from "./BackupsContent.svelte";
import ClientsContent from "./ClientsContent.svelte";
import DeploymentImpactPanel from "./DeploymentImpactPanel.svelte";
import HostReadinessMatrix from "./HostReadinessMatrix.svelte";
import InstanceActions from "./InstanceActions.svelte";
import InstanceWorkspace from "./InstanceWorkspace.svelte";
import LogFilters from "./LogFilters.svelte";
import LogsContent from "./LogsContent.svelte";

describe("backend-aware presentation components", () => {
  it.each(backendOptions)("renders $display_name beside its text badge", (option) => {
    const { unmount } = render(BackendBadge, {
      backend: option.kind,
      options: backendOptions,
    });
    expect(screen.getByText(option.presentation.badge)).toBeTruthy();
    expect(screen.getByText(option.display_name)).toBeTruthy();
    unmount();
  });

  it.each([
    ["wireguard", true],
    ["amnezia_wg", true],
    ["openvpn", false],
    ["ikev2", false],
    ["xray", true],
  ] as const)("uses only advertised QR actions for %s", (backend, hasQr) => {
    const { unmount } = render(ClientsContent, {
      clients: [client(backend)],
      onaction: vi.fn(),
    });
    expect(Boolean(screen.queryByRole("button", { name: "Show QR" }))).toBe(hasQr);
    unmount();
  });

  it("does not invent an address or expose a UUID for an Xray client", () => {
    const xray = client("xray");
    render(ClientsContent, { clients: [xray], onaction: vi.fn() });
    expect(screen.queryByText("10.64.0.2")).toBeNull();
    expect(document.body.textContent).not.toContain(xray.id);
    expect(screen.getByText(xray.identity_summary)).toBeTruthy();
  });

  it("offers replacement rather than enable for a revoked certificate client", () => {
    const revoked = client("ikev2");
    revoked.enabled = false;
    revoked.state_label = "Revoked";
    revoked.actions = [
      { action: "replace_identity", label: "Replace identity", warning: "All prior credentials remain revoked.", destructive: false },
      { action: "remove", label: "Remove client", destructive: true },
    ];
    render(ClientsContent, { clients: [revoked], onaction: vi.fn() });
    expect(screen.getByRole("button", { name: "Replace identity" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Enable" })).toBeNull();
  });

  it("renders readiness outcomes for every backend", () => {
    render(HostReadinessMatrix, {
      view: {
        inspection: {} as never,
        ssh_trust: "Approved",
        connectivity: "Connected",
        docker_ready: true,
        backend_readiness: backendOptions.map((backend, index) => ({
          backend: backend.kind,
          display_name: backend.display_name,
          status: index === 1 ? ("ready_with_fallback" as const) : ("ready" as const),
          details: ["Requirements evaluated from one inspection"],
        })),
      },
    });
    expect(screen.getAllByText("Requirements evaluated from one inspection")).toHaveLength(5);
    expect(screen.getByText("Ready with fallback")).toBeTruthy();
  });

  it("presents restore metadata and empty activity without raw objects", () => {
    const onrestore = vi.fn();
    render(BackupsContent, {
      backups: [{
        instance_id: "instance-xray",
        instance_name: "Xray appliance",
        backend: "xray",
        backend_name: "Xray VLESS",
        name: "pre-upgrade-20260731",
        created_at: "2026-07-31T12:00:00Z",
        reason: "pre_upgrade",
        protects_identity: true,
        restore_warning: "Client identities may change.",
      }],
      onrestore,
    });
    fireEvent.click(screen.getByRole("button", { name: "Review restore" }));
    expect(onrestore).toHaveBeenCalledTimes(1);
    render(LogsContent, { props: { events: [] } });
    expect(screen.getByRole("heading", { name: "No activity" })).toBeTruthy();
  });

  it("shows typed reinstall impact and client consequences", () => {
    render(DeploymentImpactPanel, {
      preview: {
        id: "plan-1",
        instance_id: "instance-xray",
        operations: [],
        impact: "reinstall",
        creates_backup: true,
        server_identity_effect: "Server identity is replaced.",
        client_effect: "All clients must re-export.",
        affected_clients: 4,
        drift: "desired_changes",
        warnings: [],
        desired_state_hash: "hash",
      },
    });
    expect(screen.getByText("reinstall")).toBeTruthy();
    expect(screen.getByText("All clients must re-export.")).toBeTruthy();
    expect(screen.getByText("Review this disruptive change before applying it.")).toBeTruthy();
  });

  it("closes the secondary action menu with Escape and restores focus", async () => {
    render(InstanceActions, {
      instance: instance("xray"),
      onstart: vi.fn(), onstop: vi.fn(), onhealth: vi.fn(), onplan: vi.fn(), onbackup: vi.fn(), ondelete: vi.fn(),
    });
    const trigger = screen.getByText("More");
    await fireEvent.click(trigger);
    expect(trigger.closest("details")?.open).toBe(true);
    await fireEvent.keyDown(trigger, { key: "Escape" });
    expect(trigger.closest("details")?.open).toBe(false);
    expect(document.activeElement).toBe(trigger);
  });

  it("keeps Xray DNS unsupported while retaining global hostlists", () => {
    render(InstanceWorkspace, {
      summary: summary("xray"), options: backendOptions, tab: "DNS", devices: [], records: [],
      hostlists: [{ id: "list-1", name: "StevenBlack", url: "https://example.com/hosts", coverage: "Ads" }],
      backups: [], logs: [], onback: vi.fn(), ontabchange: vi.fn(), onhealth: vi.fn(), onplan: vi.fn(),
      onaddclient: vi.fn(), onclientaction: vi.fn(), onbackup: vi.fn(), onrestore: vi.fn(), oneditsettings: vi.fn(),
    });
    expect(screen.getByRole("heading", { name: "Managed private DNS is not supported" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Global hostlists" })).toBeTruthy();
    expect(screen.getByText("StevenBlack")).toBeTruthy();
  });

  it("moves instance tabs with the keyboard", async () => {
    const ontabchange = vi.fn();
    render(InstanceWorkspace, {
      summary: summary("wireguard"), options: backendOptions, tab: "Overview", devices: [], records: [], hostlists: [],
      backups: [], logs: [], onback: vi.fn(), ontabchange, onhealth: vi.fn(), onplan: vi.fn(),
      onaddclient: vi.fn(), onclientaction: vi.fn(), onbackup: vi.fn(), onrestore: vi.fn(), oneditsettings: vi.fn(),
    });
    await fireEvent.keyDown(screen.getByRole("tab", { name: "Overview" }), { key: "ArrowRight" });
    expect(ontabchange).toHaveBeenCalledWith("Clients");
  });

  it("emits typed log filters and renders readable event titles", async () => {
    const onchange = vi.fn();
    render(LogFilters, { value: {}, hosts: [], instances: [], onchange });
    await fireEvent.change(screen.getByLabelText("Operation"), { target: { value: "backup_restore" } });
    expect(onchange).toHaveBeenCalledWith({ operation: "backup_restore" });

    render(LogsContent, { props: { events: [{
      id: "event-1", sequence: 1, timestamp: "2026-07-31T12:00:00Z", severity: "warning",
      operation: "backup_restore", title: "Backup restore recovered", message: "The safety snapshot restored the prior state.",
      technical_detail: "redacted detail", instance_id: "instance-xray",
    }] } });
    expect(screen.getByText("Backup restore recovered")).toBeTruthy();
    expect(screen.getByText("The safety snapshot restored the prior state.")).toBeTruthy();
    expect(screen.getByText("Technical")).toBeTruthy();
  });
});
