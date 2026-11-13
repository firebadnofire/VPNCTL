import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import { summary } from "./test/fixtures";
import type { LegacyCandidate, Manifest, RemoteDraft, RemoteInventory } from "./lib/remote-types";

const invoke = vi.hoisted(() => vi.fn());
const confirm = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn(), confirm }));
const host = { id: "host-1", display_name: "Mainsrv", ssh: { hostname: "192.0.2.1", username: "tester", port: 22, private_key_path: "key" }, created_at: "2026-11-10T12:00:00Z", updated_at: "2026-11-10T12:00:00Z" };
function manifest(): Manifest {
  return { schema_version: 1, appliance_id: "appliance-1", revision: 4, request_id: "request-1", request_digest: "digest", saved_at: "2026-11-10T12:00:00Z", removed: false,
    configuration: { instance: { ...summary("wireguard").instance, display_name: "Remote WG", host_id: "appliance-1" }, users: [], peers: [], dns_records: [], dns_blocklist_domains: [] } };
}
function inventory(instances: Manifest[] = []): RemoteInventory {
  return { host_id: host.id, identity: { appliance_id: "appliance-1", machine_fingerprint: "machine-1", ssh_public_key: "approved", capabilities: ["instance_archives_v1"] }, synchronized_at: "2026-11-10T12:00:00Z", cached: false,
    discovery: { instances, errors: {}, deployments: {} } };
}
describe("remote-authoritative desktop workflows", () => {
  let current: RemoteInventory;
  let candidates: LegacyCandidate[];
  beforeEach(() => {
    invoke.mockReset(); confirm.mockReset(); confirm.mockResolvedValue(true);
    current = inventory(); candidates = [];
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case "app_info": return { system_username: "tester" };
        case "list_hosts": return [host];
        case "preview_local_factory_reset": return { host_ids: [host.id], reset_preferences: true };
        case "legacy_candidates": return candidates;
        case "discover_remote": return current;
        case "connected_hosts": return [host.id];
        case "cached_remote_inventory": case "load_remote_draft": case "save_remote_draft": case "discard_remote_draft": return null;
        case "remote_peer_availability": case "remote_history": return [];
        default: throw new Error("Unexpected command: " + command);
      }
    });
  });
  async function renderConnected() {
    const view = render(App);
    await fireEvent.click(await screen.findByRole("button", { name: /^Mainsrv/ }));
    return view;
  }
  async function enterDangerZone() {
    const button = screen.getByRole("button", { name: "Danger Zone" });
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(button);
    await screen.findByRole("heading", { name: "Danger Zone", level: 1 });
  }
  it("loads profiles without connecting until a host is clicked", async () => {
    render(App);
    await screen.findByText("Choose a host to connect");
    expect(invoke.mock.calls.some(([command]) => command === "discover_remote")).toBe(false);
    expect(invoke.mock.calls.some(([command]) => command === "connected_hosts")).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: /^Mainsrv/ }));
    await screen.findByText("No VPN instances configured on this server.");
    expect(invoke).toHaveBeenCalledWith("discover_remote", {hostId: host.id});
  });
  it("keeps multiple hosts connected and reuses state when switching", async () => {
    const other = { ...host, id: "host-2", display_name: "Backup" };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "list_hosts") return [host, other];
      if (command === "discover_remote") return { ...current, host_id: (args as {hostId: string}).hostId };
      if (command === "connected_hosts") return [host.id, other.id];
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await fireEvent.click(screen.getByRole("button", {name: /^Hosts/}));
    await fireEvent.click(screen.getByRole("button", {name: /^Backup.*tester@/}));
    await screen.findByRole("heading", {name: "Backup"});
    await fireEvent.click(screen.getByRole("button", {name: /^Mainsrv/}));
    await screen.findByRole("heading", {name: "Mainsrv"});
    expect(invoke.mock.calls.filter(([command]) => command === "discover_remote")).toHaveLength(2);
  });
  it("marks a lost socket offline without reconnecting in the background", async () => {
    const intervals = vi.spyOn(globalThis, "setInterval");
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "connected_hosts" ? [] : base(command, args));
    try {
      await renderConnected();
      await screen.findByText("No VPN instances configured on this server.");
      const poll = intervals.mock.calls.find(([, delay]) => delay === 5000)?.[0];
      expect(typeof poll).toBe("function");
      (poll as () => void)();
      await screen.findByText(/Offline · showing cached information/);
      expect(invoke.mock.calls.filter(([command]) => command === "discover_remote")).toHaveLength(1);
      expect((screen.getByRole("button", {name: "Create Instance"}) as HTMLButtonElement).disabled).toBe(true);
    } finally { intervals.mockRestore(); }
  });
  it("ignores a disconnected status reply that predates a successful reconnect", async () => {
    const intervals = vi.spyOn(globalThis, "setInterval");
    let deliver!: (hosts: string[]) => void;
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "connected_hosts"
      ? new Promise<string[]>(resolve => { deliver = resolve; }) : base(command, args));
    try {
      await renderConnected();
      await screen.findByText("No VPN instances configured on this server.");
      await fireEvent.click(screen.getByRole("button", {name: /^Hosts/}));
      const poll = intervals.mock.calls.find(([, delay]) => delay === 5000)?.[0] as () => Promise<void>;
      const pending = poll();
      await waitFor(() => expect(deliver).toBeTypeOf("function"));
      const reconnect = screen.getByRole("button", {name: "Reconnect"}) as HTMLButtonElement;
      await fireEvent.click(reconnect);
      await waitFor(() => {
        expect(invoke.mock.calls.filter(([command]) => command === "discover_remote")).toHaveLength(2);
        expect(reconnect.disabled).toBe(false);
      });
      deliver([]);
      await pending;
      expect(screen.queryByText(/Offline · showing cached information/)).toBeNull();
      expect(screen.getAllByText("Connected").length).toBeGreaterThan(0);
    } finally { intervals.mockRestore(); }
  });
  it("shows error diagnostics in a collapsed keyboard accessible disclosure", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "discover_remote" ? Promise.reject({
      code: "remote_exchange_failed", message: "A fixed remote operation failed.",
      remediation: "Expand the technical details and inspect the remote host.", technical_detail: "compose exited with status 1\nDNS readiness probe failed",
    }) : base(command, args));
    await renderConnected();
    const summary = await screen.findByText("Technical details");
    const details = summary.closest("details")!;
    expect(details.open).toBe(false);
    await fireEvent.click(summary);
    // jsdom does not implement native details activation; the native disclosure
    // keeps content in the DOM and browsers provide keyboard/touch behavior.
    expect(details.querySelector("pre")?.textContent).toContain("DNS readiness probe failed");
    expect(screen.getByText("A fixed remote operation failed.")).toBeTruthy();
  });
  it("discovers the selected server and distinguishes an empty inventory", async () => {
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    expect(screen.getByRole("navigation", { name: "Control plane" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create Instance" })).toBeTruthy();
    expect(screen.queryByText(/Migrate Instances/)).toBeNull();
    expect(invoke.mock.calls.some(([command]) => ["list_instances", "list_instance_summaries", "create_instance"].includes(command))).toBe(false);
  });
  it("routes prototype navigation through the selected server", async () => {
    current = inventory([manifest()]);
    await renderConnected();
    await screen.findByText("Remote WG");
    expect(screen.getByRole("heading", { name: "Overview", level: 1 })).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    expect(screen.getByRole("heading", { name: "Your instances" })).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    expect(screen.getByRole("heading", { name: "Remote WG" })).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    expect(screen.getByRole("heading", { name: "Devices", level: 1 })).toBeTruthy();
    expect(screen.getByLabelText("Instance")).toBeTruthy();
    expect(screen.queryByRole("tablist", { name: "Instance sections" })).toBeNull();
  });
  it("shows remote deployment history and backups in their navigation pages", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "remote_runtime_history") return [{ request_id: "operation-1", desired_revision: 4, operation: "deploy", succeeded: true, requires_recovery: false, deployed_revision: 4 }];
      if (command === "list_remote_backups") return [{ name: "snapshot-1", created_at: "2026-11-11T12:00:00Z" }];
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: "Logs" }));
    await screen.findByRole("heading", { name: "Deployment history" });
    await screen.findByText("deploy");
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await screen.findByRole("heading", { name: "Backup inventory" });
    await screen.findByText("snapshot-1");
    expect(invoke).toHaveBeenCalledWith("list_remote_backups", expect.objectContaining({ hostId: host.id }));
  });
  it("keeps fresh onboarding free of legacy UI", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "list_hosts" ? [] : base(command, args));
    render(App);
    await screen.findByText("Connect your first VPN server");
    expect(document.body.textContent).not.toMatch(/migrat|legacy|xray/i);
  });
  it("does not confuse an unreachable server with an empty one", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "discover_remote" ? Promise.reject({ code: "remote_exchange_failed", message: "Server unreachable" }) : base(command, args));
    await renderConnected();
    await screen.findByText("Server unreachable");
    expect(screen.queryByText("No VPN instances configured on this server.")).toBeNull();
    expect((screen.getByRole("button", { name: "Create Instance" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("shows a partial discovery error without calling the server empty", async () => {
    current = inventory();
    current.discovery.errors["broken-instance"] = "Manifest schema is newer than this client";
    await renderConnected();
    await screen.findByText("Some remote instance metadata could not be read. The server is not empty.");
    expect(screen.getByText("Manifest schema is newer than this client")).toBeTruthy();
    expect(screen.queryByText("No VPN instances configured on this server.")).toBeNull();
  });
  it("labels cached discovery and disables remote writes", async () => {
    current = { ...inventory([manifest()]), cached: true };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "discover_remote") return Promise.reject({ code: "remote_exchange_failed", message: "Server unreachable" });
      return command === "cached_remote_inventory" ? current : base(command, args);
    });
    await renderConnected();
    await screen.findByText(/Offline · showing cached information/);
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    expect((screen.getByRole("button", { name: "Save to Server" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("retains conflicting drafts and separates saving from deployment", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "save_remote_configuration" ? Promise.reject({ code: "revision_conflict", message: "Remote revision conflict" }) : base(command, args));
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "My draft" } });
    await screen.findByText(/Unsaved changes ·/);
    await fireEvent.click(screen.getByRole("button", { name: "Save to Server" }));
    await screen.findByText("Remote revision conflict");
    expect((screen.getByLabelText("Instance name") as HTMLInputElement).value).toBe("My draft");
    expect(invoke).toHaveBeenCalledWith("save_remote_configuration", expect.objectContaining({ input: expect.objectContaining({ expected_revision: 4 }) }));
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
  });
  it("does not save a discarded draft again while reloading from the server", async () => {
    const remote = manifest();
    current = inventory([remote]);
    const stale = structuredClone(remote.configuration);
    stale.instance.display_name = "Stale local draft";
    let local: RemoteDraft | null = { host_id: host.id, base_revision: 3, configuration: stale };
    const fresh = structuredClone(remote);
    fresh.revision = 5;
    fresh.configuration.instance.display_name = "Current server configuration";
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "load_remote_draft") return local;
      if (command === "read_remote") return fresh;
      if (command === "discard_remote_draft") { local = null; return null; }
      if (command === "save_remote_draft") { local = (args as { draft: RemoteDraft }).draft; return null; }
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await screen.findByText(/Unsaved changes · Save to Server/);
    await fireEvent.click(screen.getByRole("tab", { name: "Deployment" }));
    expect((screen.getByRole("button", { name: "Preview / Deploy" }) as HTMLButtonElement).disabled).toBe(true);
    await fireEvent.click(screen.getByRole("button", { name: "Reload from Server" }));
    await screen.findByRole("heading", { name: "Current server configuration" });
    expect(screen.queryByText(/Unsaved changes · Save to Server/)).toBeNull();
    expect(invoke.mock.calls.some(([command]) => command === "save_remote_draft")).toBe(false);
  });
  it("discards an unchanged old server copy while preserving genuine draft conflicts", async () => {
    const old = { ...manifest(), revision: 3 };
    const currentManifest = structuredClone(old); currentManifest.revision = 4;
    currentManifest.configuration.instance.display_name = "Updated server instance";
    current = inventory([currentManifest]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "load_remote_draft") return { host_id: host.id, base_revision: 3, configuration: old.configuration };
      if (command === "remote_history") return [old];
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Updated server instance");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("discard_remote_draft", { hostId: host.id, instanceId: old.configuration.instance.id }));
    await screen.findByLabelText("Device name");
    expect(screen.queryByText(/Unsaved changes ·/)).toBeNull();
    expect(screen.queryByText(/The server configuration has changed since/)).toBeNull();
  });
  it("does not restore the previous revision as a draft after creating a peer", async () => {
    const remote = manifest();
    current = inventory([remote]);
    const saved = structuredClone(remote);
    saved.revision = 5;
    saved.configuration.peers.push({ id: "peer-1", user_id: null, display_name: "Phone", ipv4_address: "10.64.0.2", ipv6_address: null,
      dns_name: null, enabled: true, created_at: "2026-11-10T12:00:00Z", identity: { backend: "wireguard", public_key: "public", preshared_key: "psk-1" } });
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "add_remote_peer") { current = inventory([saved]); return saved; }
      if (command === "preview_remote_deployment") return { desired_state_hash: "client-plan", warnings: [], operations: [] };
      if (command === "apply_remote_deployment") { current.discovery.deployments[saved.configuration.instance.id] = { deployed_revision: saved.revision, pending_operation: null }; return { status: "succeeded" }; }
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    await fireEvent.input(screen.getByLabelText("Device name"), { target: { value: "Phone" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    await screen.findByText("Device saved on the server");
    await screen.findByDisplayValue("Phone");
    await screen.findByText("Device added to the saved configuration. Deploy when you are ready to enable access.");
    expect(invoke.mock.calls.some(([command]) => command === "preview_remote_deployment" || command === "apply_remote_deployment")).toBe(false);
    expect(invoke.mock.calls.some(([command]) => command === "discard_remote_draft")).toBe(true);
    expect(screen.queryByText(/Unsaved changes ·/)).toBeNull();
    expect(invoke.mock.calls.some(([command]) => command === "save_remote_draft")).toBe(false);
  });
  it.each([
    { backend: "wireguard", custom: "", enabled: true, expectedName: "macbook" },
    { backend: "amnezia_wg", custom: "", enabled: true, expectedName: "macbook" },
    { backend: "wireguard", custom: "  travel-laptop  ", enabled: true, expectedName: "travel-laptop" },
    { backend: "wireguard", custom: "macbook.internal", enabled: true, expectedName: "macbook.internal" },
    { backend: "wireguard", custom: "   ", enabled: true, expectedName: "macbook" },
    { backend: "wireguard", custom: "", enabled: false, expectedName: null },
    { backend: "wireguard", custom: "custom", enabled: false, expectedName: null },
  ] as const)("enrolls a $backend device with DNS enabled=$enabled and custom '$custom'", async ({ backend, custom, enabled, expectedName }) => {
    const remote = manifest(); remote.configuration.instance.backend = backend;
    remote.configuration.instance.dns.zone = "internal";
    current = inventory([remote]);
    const saved = { ...remote, revision: remote.revision + 1 };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "add_remote_peer") { current = inventory([saved]); return saved; }
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    const name = await screen.findByLabelText("Device name");
    await waitFor(() => expect((name as HTMLInputElement).disabled).toBe(false));
    const checkbox = screen.getByRole("checkbox", { name: "Add DNS record" }) as HTMLInputElement;
    expect(checkbox.checked).toBe(true);
    expect(screen.getByText(/macbook becomes macbook.internal/)).toBeTruthy();
    await fireEvent.input(name, { target: { value: "  macbook  " } });
    if (custom) {
      await fireEvent.click(screen.getByText("Advanced (optional)"));
      await fireEvent.input(screen.getByLabelText("DNS name (optional)"), { target: { value: custom } });
    }
    if (!enabled) await fireEvent.click(checkbox);
    expect((screen.getByLabelText("DNS name (optional)") as HTMLInputElement).disabled).toBe(!enabled);
    await fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    await screen.findByText("Device added to the saved configuration. Deploy when you are ready to enable access.");
    expect(invoke).toHaveBeenCalledWith("add_remote_peer", expect.objectContaining({ expectedRevision: remote.revision, input: expect.objectContaining({ dns_name: expectedName, create_dns_record: enabled }) }));
    expect(invoke.mock.calls.filter(([command]) => command === "add_remote_peer")).toHaveLength(1);
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
    expect(checkbox.checked).toBe(true);
  });
  it("drains an in-flight draft write before saving a device", async () => {
    current = inventory([manifest()]);
    let local: RemoteDraft | null = null;
    let finishWrite!: () => void;
    const writeFinished = new Promise<void>((resolve) => { finishWrite = resolve; });
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation(async (command: string, args: unknown) => {
      if (command === "save_remote_draft") { await writeFinished; local = (args as { draft: RemoteDraft }).draft; return null; }
      if (command === "load_remote_draft") return local;
      if (command === "discard_remote_draft") { local = null; return null; }
      if (command === "add_remote_peer") { const saved = { ...manifest(), revision: 5 }; current = inventory([saved]); return saved; }
      if (command === "preview_remote_deployment") return { desired_state_hash: "plan", warnings: [], operations: [] };
      if (command === "apply_remote_deployment") return { status: "succeeded" };
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await screen.findByRole("tab", { name: "Settings" });
    await fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "Temporary edit" } });
    await waitFor(() => expect(invoke.mock.calls.some(([command]) => command === "save_remote_draft")).toBe(true));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "Remote WG" } });
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    await fireEvent.input(screen.getByLabelText("Device name"), { target: { value: "Phone" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    expect(invoke.mock.calls.some(([command]) => command === "add_remote_peer")).toBe(false);
    finishWrite();
    await screen.findByText("Device added to the saved configuration. Deploy when you are ready to enable access.");
    expect(local).toBeNull();
    expect(screen.queryByText(/Unsaved changes ·/)).toBeNull();
  });
  it("keeps device creation separate from a failed explicit deployment", async () => {
    current = inventory([manifest()]);
    const saved = { ...manifest(), revision: 5 };
    saved.configuration.peers = [{ id: "new-peer", display_name: "Phone", enabled: true, user_id: null, ipv4_address: null, ipv6_address: null, dns_name: null, created_at: saved.saved_at, identity: { backend: "wireguard", public_key: "public" } }];
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "add_remote_peer") { current = inventory([saved]); return saved; }
      if (command === "preview_remote_deployment") return { desired_state_hash: "plan", warnings: [], operations: [] };
      if (command === "apply_remote_deployment") return Promise.reject({ code: "deployment_failed", message: "Deployment failed safely" });
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    await screen.findByLabelText("Device name");
    await fireEvent.input(screen.getByLabelText("Device name"), { target: { value: "Phone" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    await screen.findByText("Device saved on the server");
    await waitFor(() => expect(invoke.mock.calls.filter(([command]) => command === "remote_peer_availability")).toHaveLength(2));
    await waitFor(() => expect((screen.getByRole("button", { name: "Review deployment" }) as HTMLButtonElement).disabled).toBe(false));
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Review deployment" }));
    await fireEvent.click(screen.getByRole("button", { name: "Preview / Deploy" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Apply saved revision 5" }));
    await screen.findByText("Deployment failed safely");
    expect(invoke.mock.calls.filter(([command]) => command === "add_remote_peer")).toHaveLength(1);
    expect(screen.getByRole("heading", { name: "Remote WG" })).toBeTruthy();
  });
  it("does not deploy when concurrent device creation is rejected", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "add_remote_peer" ? Promise.reject({ code: "revision_conflict", message: "Another client saved a new revision" }) : base(command, args));
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    await screen.findByLabelText("Device name");
    await fireEvent.input(screen.getByLabelText("Device name"), { target: { value: "Phone" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    await screen.findByText("Another client saved a new revision");
    expect((screen.getByRole("button", { name: "Add Device" }) as HTMLButtonElement).disabled).toBe(true);
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
  });
  it("shows private QR export and clears it on navigation", async () => {
    const remote = manifest();
    remote.configuration.peers = [{ id: "peer-1", user_id: null, display_name: "Phone", ipv4_address: "10.64.0.2", ipv6_address: null, dns_name: null, enabled: true, created_at: remote.saved_at, identity: { backend: "wireguard", public_key: "public" } }];
    current = inventory([remote]);
    current.discovery.deployments[remote.configuration.instance.id] = { deployed_revision: remote.revision, pending_operation: null };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "remote_peer_availability") return [{ peer_id: "peer-1", complete_export_available: true }];
      if (command === "remote_peer_qr_svg") return '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    await screen.findByLabelText("Device name");
    await waitFor(() => expect((screen.getByRole("button", { name: "Get Configuration" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Get Configuration" }));
    await fireEvent.click(screen.getByRole("button", { name: "Show QR code" }));
    expect(await screen.findByAltText("Private VPN client configuration QR code")).toBeTruthy();
    expect(screen.getByText(/contains private VPN credentials/)).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "Close Get Configuration" }));
    expect(screen.queryByAltText("Private VPN client configuration QR code")).toBeNull();
    await waitFor(() => expect((screen.getByRole("button", { name: "Get Configuration" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Get Configuration" }));
    await fireEvent.click(screen.getByRole("button", { name: "Show QR code" }));
    await screen.findByAltText("Private VPN client configuration QR code");
    await fireEvent.click(screen.getByRole("button", { name: "Close Get Configuration" }));
    await fireEvent.click(screen.getByRole("button", { name: /Hosts/ }));
    expect(screen.queryByAltText("Private VPN client configuration QR code")).toBeNull();
  });
  it("clears health from the previous instance when switching instances", async () => {
    const first = manifest();
    const second = structuredClone(first);
    second.configuration.instance.id = "instance-2";
    second.configuration.instance.display_name = "Second WG";
    current = inventory([first, second]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "inspect_remote_health" ? {
      gateway_running: true, backend_ready: true, listeners_ready: true, client_state_matches: true,
      dns_required: false, private_dns_resolves: false, public_dns_resolves: false, details: [],
    } : base(command, args));
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Deployment" }));
    await fireEvent.click(screen.getByRole("button", { name: "Check health" }));
    await screen.findByText("Deployment health");
    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    await fireEvent.click(screen.getByRole("button", { name: /Second WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Deployment" }));
    expect(screen.queryByText("Deployment health")).toBeNull();
  });
  it("shows pending deployment independently of saved configuration", async () => {
    current = inventory([manifest()]);
    current.discovery.deployments[current.discovery.instances[0].configuration.instance.id] = { deployed_revision: 3, pending_operation: null };
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await screen.findByText(/Changes ready to deploy ·/);
    expect(screen.getByText("Configuration details")).toBeTruthy();
  });
  it("disables complete export when this client lacks the peer private key", async () => {
    const remote = manifest();
    remote.configuration.peers.push({ id: "peer-1", user_id: null, display_name: "Phone", ipv4_address: "10.64.0.2", ipv6_address: null,
      dns_name: null, enabled: true, created_at: "2026-11-10T12:00:00Z", identity: { backend: "wireguard", public_key: "public", preshared_key: "psk-1" } });
    current = inventory([remote]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_peer_availability" ?
      [{ peer_id: "peer-1", complete_export_available: false, reason: "Private key unavailable" }] : base(command, args));
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    await screen.findByText(/Deploy this instance once to establish its server identity/);
    expect((screen.getByRole("button", { name: "Get Configuration" }) as HTMLButtonElement).disabled).toBe(true);
    expect(invoke.mock.calls.some(([command]) => command === "export_remote_peer")).toBe(false);
  });
  it("requires a deployed certificate authority before enrolling a certificate peer", async () => {
    const remote = manifest();
    remote.configuration.instance = { ...summary("openvpn").instance, display_name: "Remote OpenVPN", host_id: "appliance-1" };
    current = inventory([remote]);
    await renderConnected();
    await screen.findByText("Remote OpenVPN");
    await fireEvent.click(screen.getByRole("button", { name: /Remote OpenVPN.*OpenVPN/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    expect(screen.getByText("Deploy this instance once to establish its certificate authority before enrolling devices.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Add Device" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("shows remote deployment receipts from a fresh client without secret fields", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_runtime_history" ?
      [{ request_id: "operation-1", desired_revision: 4, operation: "deploy", succeeded: true, requires_recovery: false, deployed_revision: 4 }] : base(command, args));
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Deployment" }));
    await fireEvent.click(screen.getByRole("button", { name: "View deployment history" }));
    await screen.findByText("deploy · desired revision 4 · Succeeded · deployed revision 4");
    expect(document.body.textContent).not.toMatch(/private_key|preshared_key|operation-1/i);
  });
  it("reports an unresolved runtime operation without clearing its warning", async () => {
    current = inventory([manifest()]);
    current.discovery.deployments[current.discovery.instances[0].configuration.instance.id] = { deployed_revision: 3, pending_operation: "pending-1" };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "reconcile_remote_runtime" ? "unresolved" : base(command, args));
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("button", { name: "Check operation outcome" }));
    await screen.findByText(/The operation outcome is unresolved/);
    expect(screen.getByText(/An interrupted runtime operation requires reconciliation/)).toBeTruthy();
  });
  it("renders migration only for matching local candidates", async () => {
    candidates = [{ instance_id: "legacy-1", host_id: host.id, display_name: "Old VPN", backend: "wireguard", supported: true, status: "requires_preview" }];
    await renderConnected();
    await screen.findByRole("button", { name: "Migrate Instances (1)" });
    await waitFor(() => expect((screen.getByRole("button", { name: "Migrate Instances (1)" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Migrate Instances (1)" }));
    expect(screen.getByRole("heading", { name: "Old VPN" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Preview migration" })).toBeTruthy();
  });
  it("exposes Danger Zone even without a host and explains unavailable remote modes", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "list_hosts" ? [] : base(command, args));
    render(App);
    await screen.findByText("Connect your first VPN server");
    await enterDangerZone();
    expect(screen.getByRole("button", { name: "Danger Zone" }).getAttribute("aria-current")).toBe("page");
    expect((screen.getByRole("button", { name: "Remove host locally" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Factory Reset local data" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Full drop unavailable" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Remote Factory Reset unavailable" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Factory Reset is not secure erasure/)).toBeTruthy();
  });
  it("allows offline local removal and never invokes cleanup after cancellation", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "discover_remote") return Promise.reject({ code: "offline", message: "Server offline" });
      if (command === "cached_remote_inventory") return { ...inventory([manifest()]), cached: true };
      return base(command, args);
    });
    confirm.mockResolvedValue(false);
    await renderConnected();
    await screen.findByText(/Offline · showing cached information/);
    await enterDangerZone();
    expect((screen.getByRole("button", { name: "Archive instance on server" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Remove host locally" }) as HTMLButtonElement).disabled).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Remove host locally" }));
    await waitFor(() => expect(confirm).toHaveBeenCalledOnce());
    expect(invoke.mock.calls.some(([command]) => command === "cleanup_local")).toBe(false);
    expect(screen.getByLabelText("Danger Zone host")).toBeTruthy();
  });
  it("removes local host state through the shared coordinator and stays in Danger Zone", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "cleanup_local" ? {} : base(command, args));
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Remove host locally" }));
    await screen.findByText("Host removed locally. VPN recovery data is preserved; server instances keep running.");
    expect(invoke).toHaveBeenCalledWith("cleanup_local", { operationId: expect.any(String), hostIds: [host.id], resetPreferences: false, confirmed: true });
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("SSH key files and exported VPN configurations are untouched"), expect.objectContaining({ title: "Local drop" }));
    expect(screen.queryByLabelText("Danger Zone host")).toBeNull();
    expect(screen.getByRole("heading", { name: "Danger Zone", level: 1 })).toBeTruthy();
    expect(invoke.mock.calls.some(([command]) => ["remove_remote_configuration", "revoke_remote_peer"].includes(command))).toBe(false);
  });
  it("retains a failed local cleanup scope and reuses its operation ID on retry", async () => {
    const base = invoke.getMockImplementation()!;
    let fail = true;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "cleanup_local") return fail ? Promise.reject({ code: "locked", message: "Recovery credential unavailable" }) : {};
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Remove host locally" }));
    await screen.findByText("Recovery credential unavailable");
    expect(screen.getByLabelText("Danger Zone host")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Factory Reset local data" }) as HTMLButtonElement).disabled).toBe(true);
    fail = false;
    await fireEvent.click(screen.getByRole("button", { name: "Retry local drop" }));
    await screen.findByText("Host removed locally. VPN recovery data is preserved; server instances keep running.");
    const calls = invoke.mock.calls.filter(([command]) => command === "cleanup_local");
    expect(calls).toHaveLength(2);
    expect(calls[1][1]).toEqual(calls[0][1]);
  });
  it("drains and cancels draft saves before entering Danger Zone and removing a host", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    let releaseDraft: (() => void) | undefined;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "save_remote_draft") return new Promise<void>((resolve) => { releaseDraft = resolve; });
      if (command === "cleanup_local") return {};
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "Retained edit" } });
    await screen.findByText(/Unsaved changes ·/);
    await fireEvent.click(screen.getByRole("button", { name: "Danger Zone" }));
    await waitFor(() => expect(releaseDraft).toBeTypeOf("function"));
    expect(screen.queryByRole("heading", { name: "Danger Zone", level: 1 })).toBeNull();
    expect(invoke.mock.calls.some(([command]) => command === "cleanup_local")).toBe(false);
    releaseDraft!();
    await screen.findByRole("heading", { name: "Danger Zone", level: 1 });
    await fireEvent.click(screen.getByRole("button", { name: "Remove host locally" }));
    await screen.findByText("Host removed locally. VPN recovery data is preserved; server instances keep running.");
    await new Promise((resolve) => setTimeout(resolve, 350));
    expect(invoke.mock.calls.filter(([command]) => command === "save_remote_draft")).toHaveLength(1);
  });
  it("confirms local Factory Reset across all saved profiles including older hidden ones", async () => {
    const base = invoke.getMockImplementation()!;
    const other = { ...host, id: "host-2", display_name: "Backup" };
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "list_hosts") return [host];
      if (command === "preview_local_factory_reset") return { host_ids: [host.id, other.id], reset_preferences: true };
      return command === "cleanup_local" ? {} : base(command, args);
    });
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Factory Reset local data" }));
    await screen.findByText("Local Factory Reset completed. VPN recovery data is preserved; servers are unchanged.");
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("all 2 saved hosts"), expect.objectContaining({ title: "Factory Reset · local data only" }));
    expect(invoke).toHaveBeenCalledWith("cleanup_local", expect.objectContaining({ hostIds: [host.id, other.id], resetPreferences: true, confirmed: true }));
    expect(screen.queryByLabelText("Danger Zone host")).toBeNull();
  });
  it("blocks Factory Reset if its local scope cannot be read", async () => {
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "preview_local_factory_reset" ? Promise.reject({ code: "storage", message: "Cannot inspect saved profiles" }) : base(command, args));
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Factory Reset local data" }));
    await screen.findByText("Cannot inspect saved profiles");
    expect(confirm).not.toHaveBeenCalled();
    expect(invoke.mock.calls.some(([command]) => command === "cleanup_local")).toBe(false);
    expect(screen.getByLabelText("Danger Zone host")).toBeTruthy();
  });
  it("archives the chosen instance and restores it from Backups with its snapshot retained", async () => {
    const original = manifest();
    const fresh = { ...original, revision: 9 };
    current = inventory([original]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "read_remote") return fresh;
      if (command === "remove_remote_configuration") { current = inventory(); const archived = { ...fresh, revision: 10, removed: true }; current.discovery.archived_instances = [archived]; return archived; }
      if (command === "restore_archived_instance") { const restored = { ...fresh, revision: 11 }; current = inventory([restored]); current.discovery.deployments[original.configuration.instance.id] = { deployed_revision: 9, pending_operation: null }; return restored; }
      if (command === "set_remote_running") return { gateway_running: true, backend_ready: true, details: [] };
      if (command === "list_remote_backups") return [{ name: "archive-retained-snapshot", created_at: original.saved_at }];
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Archive instance on server" }));
    await screen.findByText("Instance archived on server. History and recovery data are retained.");
    expect(invoke).toHaveBeenCalledWith("remove_remote_configuration", { input: { host_id: host.id, expected_revision: 9, request_id: expect.any(String), configuration: fresh.configuration }, confirmed: true });
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Connected VPN users will lose service"), expect.anything());
    await screen.findByText("No managed instances available.");
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await screen.findByRole("heading", { name: "Archived instances" });
    await fireEvent.click(screen.getByRole("button", { name: "Restore archived instance" }));
    await screen.findByText("Archived instance restored. It remains stopped until you start or deploy it. The recovery snapshot is retained.");
    await screen.findByText("archive-retained-snapshot");
    expect(invoke).toHaveBeenCalledWith("restore_archived_instance", { hostId: host.id, instanceId: original.configuration.instance.id, expectedRevision: 10, requestId: expect.any(String), confirmed: true });
    expect(invoke.mock.calls.some(([command]) => ["apply_remote_deployment", "set_remote_running"].includes(command))).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Start instance" }));
    await screen.findByText("Instance started using its restored deployed state. Preview / Deploy to apply newer saved configuration.");
    expect(invoke).toHaveBeenCalledWith("set_remote_running", { hostId: host.id, instanceId: original.configuration.instance.id, expectedRevision: 11, running: true });
  });
  it("retains failed archive restores and retries the server's pending operation ID", async () => {
    const archived = { ...manifest(), removed: true, revision: 5 };
    current = inventory(); current.discovery.archived_instances = [archived];
    current.discovery.deployments[archived.configuration.instance.id] = { deployed_revision: 4, pending_operation: "persisted-restore-request" };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "restore_archived_instance" ? Promise.reject({ code: "archive_restore_failed", message: "Runtime archive unavailable" }) : base(command, args));
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await screen.findByRole("button", { name: "Restore archived instance" });
    await fireEvent.click(screen.getByRole("button", { name: "Restore archived instance" }));
    await screen.findByText("Runtime archive unavailable");
    expect(screen.getByText("Archived revision 5")).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "Retry archived instance restore" }));
    await waitFor(() => expect(invoke.mock.calls.filter(([command]) => command === "restore_archived_instance")).toHaveLength(2));
    const calls = invoke.mock.calls.filter(([command]) => command === "restore_archived_instance");
    expect(calls[0][1]).toEqual(expect.objectContaining({ requestId: "persisted-restore-request" }));
    expect(calls[1][1]).toEqual(calls[0][1]);
  });
  it("keeps archived backups visible offline and prevents restoration", async () => {
    current = { ...inventory(), cached: true }; current.discovery.archived_instances = [{ ...manifest(), removed: true }];
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "discover_remote") return Promise.reject({ code: "offline", message: "Server unreachable" });
      return command === "cached_remote_inventory" ? current : base(command, args);
    });
    await renderConnected();
    await screen.findByText(/Offline · showing cached information/);
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await screen.findByText("Archived revision 4");
    expect((screen.getByRole("button", { name: "Restore archived instance" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("does not restore an archived instance after cancelling confirmation", async () => {
    current = inventory(); current.discovery.archived_instances = [{ ...manifest(), removed: true }];
    confirm.mockResolvedValue(false);
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    await fireEvent.click(screen.getByRole("button", { name: "Restore archived instance" }));
    await waitFor(() => expect(confirm).toHaveBeenCalledOnce());
    expect(invoke.mock.calls.some(([command]) => command === "restore_archived_instance")).toBe(false);
  });
  it("blocks archive requests to older helpers and retains the active instance", async () => {
    current = inventory([manifest()]); current.identity.capabilities = [];
    await renderConnected();
    await screen.findByText("Remote WG"); await enterDangerZone();
    expect(screen.getByText(/Automatic helper repair is required/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Archive instance on server" }) as HTMLButtonElement).disabled).toBe(true);
    expect(invoke.mock.calls.some(([command]) => command === "remove_remote_configuration")).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    expect(screen.getByText("Remote WG")).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "Backups" }));
    expect(screen.getByRole("heading", { name: "Server helper update required" })).toBeTruthy();
    expect(screen.queryByText("No archived instances")).toBeNull();
  });
  it("reports a helper downgrade without claiming archival succeeded", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "read_remote") return manifest();
      if (command === "remove_remote_configuration") return Promise.reject({ code: "helper_upgrade_required", message: "Update the server helper before archiving." });
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG"); await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Archive instance on server" }));
    await screen.findByText("Update the server helper before archiving.");
    await waitFor(() => expect((screen.getByRole("button", { name: "Archive instance on server" }) as HTMLButtonElement).disabled).toBe(true));
    expect(screen.queryByText("Instance archived on server. History and recovery data are retained.")).toBeNull();
    await fireEvent.click(screen.getByRole("button", { name: "Instances" }));
    expect(screen.getByText("Remote WG")).toBeTruthy();
  });
  it("does not archive an instance when its confirmation is cancelled", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "read_remote" ? manifest() : base(command, args));
    confirm.mockResolvedValue(false);
    await renderConnected();
    await screen.findByText("Remote WG");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Archive instance on server" }));
    await waitFor(() => expect(confirm).toHaveBeenCalledOnce());
    expect(invoke.mock.calls.some(([command]) => command === "remove_remote_configuration")).toBe(false);
  });
  it("retries a lost archival response with the same revision and request ID", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    let calls = 0;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "read_remote") return manifest();
      if (command === "remove_remote_configuration") {
        calls += 1;
        if (calls === 1) return Promise.reject({ code: "remote_exchange_failed", message: "Archive response lost" });
        current = inventory(); return { ...manifest(), removed: true };
      }
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG"); await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Archive instance on server" }));
    await screen.findByText("Archive response lost");
    await fireEvent.click(screen.getByRole("button", { name: "Archive instance on server" }));
    await screen.findByText("Instance archived on server. History and recovery data are retained.");
    const attempts = invoke.mock.calls.filter(([command]) => command === "remove_remote_configuration");
    expect(attempts[1][1]).toEqual(attempts[0][1]);
  });
  it("revokes a selected certificate in Danger Zone without removing its local keys", async () => {
    const vpn = manifest();
    vpn.configuration.instance.backend = "openvpn";
    vpn.configuration.peers = [{ id: "peer-1", display_name: "Phone", enabled: true, user_id: null, ipv4_address: null, ipv6_address: null, dns_name: null, created_at: vpn.saved_at, identity: { backend: "openvpn", common_name: "phone", certificate_serial: "01" } }];
    current = inventory([vpn]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "read_remote") return { ...vpn, revision: 7 };
      if (command === "revoke_remote_peer") { current = inventory([{ ...vpn, configuration: { ...vpn.configuration, peers: [{ ...vpn.configuration.peers[0], enabled: false }] } }]); return current.discovery.instances[0]; }
      return base(command, args);
    });
    await renderConnected();
    await screen.findByText("Remote WG");
    await enterDangerZone();
    await fireEvent.click(screen.getByRole("button", { name: "Revoke device certificate" }));
    await screen.findByText("Certificate revoked in saved configuration. Deploy the instance to apply the revocation.");
    expect(invoke).toHaveBeenCalledWith("revoke_remote_peer", { hostId: host.id, instanceId: vpn.configuration.instance.id, peerId: "peer-1", expectedRevision: 7, confirmed: true });
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Local client keys are preserved"), expect.anything());
    expect(invoke.mock.calls.some(([command]) => command === "cleanup_local")).toBe(false);
  });
  it("offers only four supported backends for creation", async () => {
    await renderConnected();
    await screen.findByText("No VPN instances configured on this server.");
    await fireEvent.click(screen.getByRole("button", { name: "Create Instance" }));
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["WireGuard", "AmneziaWG", "OpenVPN", "IKEv2/IPsec"]);
    expect(document.body.textContent).not.toMatch(/xray|vless/i);
  });
  it("reviews a stale draft against original and latest server values without writing", async () => {
    const original = manifest(), latest = structuredClone(original), local = structuredClone(original.configuration);
    latest.revision = 5; latest.configuration.instance.display_name = "Server edit";
    local.instance.display_name = "My local edit"; current = inventory([latest]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "load_remote_draft") return { host_id: host.id, base_revision: 4, configuration: local };
      if (command === "remote_history") return [original];
      if (command === "read_remote") return latest;
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Server edit");
    await fireEvent.click(screen.getByRole("button", { name: /Server edit.*WireGuard/ }));
    await screen.findByText(/The server configuration has changed since/);
    expect((screen.getByRole("button", { name: "Save to Server" }) as HTMLButtonElement).disabled).toBe(true);
    await waitFor(() => expect((screen.getByRole("button", { name: "Review differences" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Review differences" }));
    const dialog = await screen.findByRole("dialog", { name: "Review configuration changes" });
    expect(dialog.textContent).toContain("My local edit"); expect(dialog.textContent).toContain("Server edit"); expect(dialog.textContent).toContain("Remote WG");
    expect(invoke.mock.calls.some(([command]) => command === "save_remote_configuration" || command === "apply_remote_deployment")).toBe(false);
  });

  async function enterExport() {
    const remote = manifest();
    remote.configuration.peers = [{ id: "export-peer", user_id: null, display_name: "Laptop", ipv4_address: "10.64.0.2", ipv6_address: null, dns_name: null, enabled: true, created_at: remote.saved_at, identity: { backend: "wireguard", public_key: "public" } }];
    current = inventory([remote]); current.discovery.deployments[remote.configuration.instance.id] = { deployed_revision: remote.revision, pending_operation: null };
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_peer_availability" ? [{ peer_id: "export-peer", complete_export_available: true }] : base(command, args));
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Devices/ }));
    await waitFor(() => expect((screen.getByRole("button", { name: "Get Configuration" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Get Configuration" }));
    return remote;
  }
  it("copies through the scoped native command and records only a public summary", async () => {
    const remote = await enterExport(), base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "copy_remote_peer_configuration" ? null : base(command, args));
    expect(invoke.mock.calls.some(([command]) => command === "remote_peer_qr_svg")).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Copy configuration text" }));
    await screen.findByText("Configuration copied. Keep your clipboard private.");
    expect(invoke).toHaveBeenCalledWith("copy_remote_peer_configuration", { hostId: host.id, instanceId: remote.configuration.instance.id, peerId: "export-peer" });
    expect(screen.getByText(/system clipboard history/)).toBeTruthy();
  });
  it("keeps oversized QR failures visible and offers file export", async () => {
    await enterExport(); const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_peer_qr_svg" ? Promise.reject({ code: "qr_generation_failed", message: "Configuration too large. Download the file instead." }) : base(command, args));
    await fireEvent.click(screen.getByRole("button", { name: "Show QR code" }));
    await waitFor(() => expect(screen.getAllByText("Configuration too large. Download the file instead.").length).toBeGreaterThan(0));
    expect((screen.getByRole("button", { name: "Download configuration file" }) as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByAltText("Private VPN client configuration QR code")).toBeNull();
  });
  it("does not redisplay a QR response after its dialog was closed", async () => {
    await enterExport(); const base = invoke.getMockImplementation()!;
    let finish!: (value: string) => void;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_peer_qr_svg" ? new Promise<string>(resolve => finish = resolve) : base(command, args));
    await fireEvent.click(screen.getByRole("button", { name: "Show QR code" }));
    await fireEvent.click(screen.getByRole("button", { name: "Close Get Configuration" }));
    finish('<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    await waitFor(() => expect(screen.queryByText(/Preparing private configuration QR code/)).toBeNull());
    await fireEvent.click(screen.getByRole("button", { name: "Get Configuration" }));
    expect(screen.queryByAltText("Private VPN client configuration QR code")).toBeNull();
  });

  it("shows clipboard failure without claiming a successful copy", async () => {
    await enterExport(); const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "copy_remote_peer_configuration" ? Promise.reject({ code: "clipboard_unavailable", message: "Clipboard unavailable. Download the file instead." }) : base(command, args));
    await fireEvent.click(screen.getByRole("button", { name: "Copy configuration text" }));
    await waitFor(() => expect(screen.getAllByText("Clipboard unavailable. Download the file instead.").length).toBeGreaterThan(0));
    expect(screen.queryByText("Configuration copied. Keep your clipboard private.")).toBeNull();
  });
  it("keeps an operational error visible when an unrelated background task succeeds", async () => {
    current = inventory([manifest()]); const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "save_remote_configuration" ? Promise.reject({ code: "revision_conflict", message: "Server changed while editing" }) : base(command, args));
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "Local draft" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save to Server" }));
    await screen.findByText("Server changed while editing");
    await fireEvent.click(screen.getByRole("tab", { name: "Deployment" }));
    await fireEvent.click(screen.getByRole("button", { name: "View configuration history" }));
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("remote_history", expect.anything()));
    expect(screen.getByText("Server changed while editing")).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: "Dismiss error" }));
    expect(screen.queryByText("Server changed while editing")).toBeNull();
    expect(screen.getByText(/The server configuration has changed since/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save to Server" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("drops the selected device only after confirmation and reuses a lost-response request", async () => {
    const remote = manifest(); remote.configuration.peers = [{ id: "drop-me", user_id: null, display_name: "Old laptop", ipv4_address: "10.64.0.2", ipv6_address: null, dns_name: null, enabled: false, created_at: remote.saved_at, identity: { backend: "wireguard", public_key: "public" } }];
    current = inventory([remote]); current.identity.capabilities!.push("drop_peer_v1");
    const base = invoke.getMockImplementation()!; let attempts = 0;
    invoke.mockImplementation((command: string, args: unknown) => {
      if (command === "read_remote") return remote;
      if (command === "drop_remote_peer") { if (++attempts === 1) return Promise.reject({ code: "ssh_timeout", message: "Response lost; retry the same removal" }); current.discovery.instances = [{ ...remote, revision: 5, configuration: { ...remote.configuration, peers: [] } }]; return current.discovery.instances[0]; }
      return base(command, args);
    });
    await renderConnected(); await screen.findByText("Remote WG"); await enterDangerZone();
    expect(screen.getByLabelText("Managed instance")).toBeTruthy();
    expect(screen.getByLabelText("Device").textContent).toContain("Old laptop (disabled / revoked)");
    confirm.mockResolvedValueOnce(false);
    await fireEvent.click(screen.getByRole("button", { name: "Drop Device" }));
    await waitFor(() => expect(confirm).toHaveBeenCalled());
    expect(invoke.mock.calls.some(([command]) => command === "drop_remote_peer")).toBe(false);
    await waitFor(() => expect((screen.getByRole("button", { name: "Drop Device" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Drop Device" }));
    await screen.findByText("Response lost; retry the same removal");
    await fireEvent.click(screen.getByRole("button", { name: "Retry device removal" }));
    await screen.findByText("Device dropped from saved configuration. Deploy to apply access changes.");
    const calls = invoke.mock.calls.filter(([command]) => command === "drop_remote_peer");
    expect(calls).toHaveLength(2); expect(calls[0][1]).toEqual(calls[1][1]);
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
  });

  it("resets the device dropdown to the selected instance's own identities", async () => {
    const first = manifest(), second = structuredClone(first);
    second.configuration.instance.id = "second-instance"; second.configuration.instance.display_name = "Second VPN";
    const peer = { id: "first-peer", user_id: null, display_name: "First device", ipv4_address: "10.64.0.2", ipv6_address: null, dns_name: null, enabled: true, created_at: first.saved_at, identity: { backend: "wireguard", public_key: "public" } };
    first.configuration.peers = [peer]; second.configuration.peers = [{ ...peer, id: "second-peer", display_name: "Second device" }];
    current = inventory([first, second]); current.identity.capabilities!.push("drop_peer_v1");
    await renderConnected(); await screen.findByText("Remote WG"); await enterDangerZone();
    expect((screen.getByLabelText("Device") as HTMLSelectElement).value).toBe("first-peer");
    await fireEvent.change(screen.getByLabelText("Managed instance"), { target: { value: "second-instance" } });
    const devices = screen.getByLabelText("Device") as HTMLSelectElement;
    expect(devices.value).toBe("second-peer"); expect(devices.textContent).toContain("Second device"); expect(devices.textContent).not.toContain("First device");
  });
  it("asks before discarding unsaved blocking edits during navigation", async () => {
    current = inventory([manifest()]); current.identity.capabilities!.push("dns_blocking_v1");
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_blocking" ? { scheduler_available: true, state: { policy: { revision: 0, enabled: false, schedule_enabled: true, interval_days: 7, sources: [] }, sources: [], error: null, pending_request: null, last_success: null, applied_at: null, applied_version: null } } : base(command, args));
    await renderConnected(); await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: "DNS" }));
    await screen.findByRole("button", { name: "Add blocking source" });
    await waitFor(() => expect((screen.getByRole("button", { name: "Add blocking source" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Add blocking source" }));
    await screen.findByLabelText("Source 1 name");
    confirm.mockResolvedValueOnce(false);
    await fireEvent.click(screen.getByRole("button", { name: /Hosts/ }));
    await waitFor(() => expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Discard unsaved blocking settings"), expect.anything()));
    expect(screen.getByRole("heading", { name: "DNS", level: 1 })).toBeTruthy(); expect(screen.getByLabelText("Source 1 name")).toBeTruthy();
    await fireEvent.click(screen.getByRole("button", { name: /Hosts/ }));
    await screen.findByRole("heading", { name: "Hosts", level: 1 });
  });

});
