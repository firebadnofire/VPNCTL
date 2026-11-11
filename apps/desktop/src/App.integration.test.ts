import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import { summary } from "./test/fixtures";
import type { LegacyCandidate, Manifest, RemoteInventory } from "./lib/remote-types";

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
  return { host_id: host.id, identity: { appliance_id: "appliance-1", machine_fingerprint: "machine-1", ssh_public_key: "approved" }, synchronized_at: "2026-11-10T12:00:00Z", cached: false,
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
        case "legacy_candidates": return candidates;
        case "discover_remote": return current;
        case "cached_remote_inventory": case "load_remote_draft": case "save_remote_draft": case "discard_remote_draft": return null;
        case "remote_peer_availability": return [];
        default: throw new Error("Unexpected command: " + command);
      }
    });
  });
  it("discovers the selected server and distinguishes an empty inventory", async () => {
    render(App);
    await screen.findByText("No VPN instances configured on this server.");
    expect(screen.getByRole("navigation", { name: "Servers" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create Instance" })).toBeTruthy();
    expect(screen.queryByText(/Migrate Instances/)).toBeNull();
    expect(invoke.mock.calls.some(([command]) => ["list_instances", "list_instance_summaries", "create_instance"].includes(command))).toBe(false);
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
    render(App);
    await screen.findByText("Server unreachable");
    expect(screen.queryByText("No VPN instances configured on this server.")).toBeNull();
    expect((screen.getByRole("button", { name: "Create Instance" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("shows a partial discovery error without calling the server empty", async () => {
    current = inventory();
    current.discovery.errors["broken-instance"] = "Manifest schema is newer than this client";
    render(App);
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
    render(App);
    await screen.findByText(/Offline · showing cached information/);
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    expect((screen.getByRole("button", { name: "Save to Server" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("retains conflicting drafts and separates saving from deployment", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "save_remote_configuration" ? Promise.reject({ code: "revision_conflict", message: "Remote revision conflict" }) : base(command, args));
    render(App);
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await waitFor(() => expect(screen.queryByText(/Checking local export material/)).toBeNull());
    await fireEvent.click(screen.getByRole("tab", { name: "Settings" }));
    await fireEvent.input(screen.getByLabelText("Instance name"), { target: { value: "My draft" } });
    await screen.findByText(/Unsaved local edits/);
    await fireEvent.click(screen.getByRole("button", { name: "Save to Server" }));
    await screen.findByText("Remote revision conflict");
    expect((screen.getByLabelText("Instance name") as HTMLInputElement).value).toBe("My draft");
    expect(invoke).toHaveBeenCalledWith("save_remote_configuration", expect.objectContaining({ input: expect.objectContaining({ expected_revision: 4 }) }));
    expect(invoke.mock.calls.some(([command]) => command === "apply_remote_deployment")).toBe(false);
  });
  it("shows pending deployment independently of saved configuration", async () => {
    current = inventory([manifest()]);
    current.discovery.deployments[current.discovery.instances[0].configuration.instance.id] = { deployed_revision: 3, pending_operation: null };
    render(App);
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await screen.findByText(/Pending deployment · saved desired state differs/);
    expect(screen.getByText(/saved revision 4 · deployed revision 3/)).toBeTruthy();
  });
  it("disables complete export when this client lacks the peer private key", async () => {
    const remote = manifest();
    remote.configuration.peers.push({ id: "peer-1", user_id: null, display_name: "Phone", ipv4_address: "10.64.0.2", ipv6_address: null,
      dns_name: null, enabled: true, created_at: "2026-11-10T12:00:00Z", identity: { backend: "wireguard", public_key: "public", preshared_key: "psk-1" } });
    current = inventory([remote]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_peer_availability" ?
      [{ peer_id: "peer-1", complete_export_available: false, reason: "Private key unavailable" }] : base(command, args));
    render(App);
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    await screen.findByText("Private material unavailable on this client");
    expect((screen.getByRole("button", { name: "Export configuration" }) as HTMLButtonElement).disabled).toBe(true);
    expect(invoke.mock.calls.some(([command]) => command === "export_remote_peer")).toBe(false);
  });
  it("requires a deployed certificate authority before enrolling a certificate peer", async () => {
    const remote = manifest();
    remote.configuration.instance = { ...summary("openvpn").instance, display_name: "Remote OpenVPN", host_id: "appliance-1" };
    current = inventory([remote]);
    render(App);
    await screen.findByText("Remote OpenVPN");
    await fireEvent.click(screen.getByRole("button", { name: /Remote OpenVPN.*OpenVPN/ }));
    await fireEvent.click(screen.getByRole("tab", { name: "Peers / Devices" }));
    expect(screen.getByText("Deploy this instance once to establish its certificate authority before enrolling peers.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Create Peer on Server" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("shows remote deployment receipts from a fresh client without secret fields", async () => {
    current = inventory([manifest()]);
    const base = invoke.getMockImplementation()!;
    invoke.mockImplementation((command: string, args: unknown) => command === "remote_runtime_history" ?
      [{ request_id: "operation-1", desired_revision: 4, operation: "deploy", succeeded: true, requires_recovery: false, deployed_revision: 4 }] : base(command, args));
    render(App);
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
    render(App);
    await screen.findByText("Remote WG");
    await fireEvent.click(screen.getByRole("button", { name: /Remote WG.*WireGuard/ }));
    await fireEvent.click(screen.getByRole("button", { name: "Check operation outcome" }));
    await screen.findByText(/The operation outcome is unresolved/);
    expect(screen.getByText(/An interrupted runtime operation requires reconciliation/)).toBeTruthy();
  });
  it("renders migration only for matching local candidates", async () => {
    candidates = [{ instance_id: "legacy-1", host_id: host.id, display_name: "Old VPN", backend: "wireguard", supported: true, status: "requires_preview" }];
    render(App);
    await screen.findByRole("button", { name: "Migrate Instances (1)" });
    await waitFor(() => expect((screen.getByRole("button", { name: "Migrate Instances (1)" }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(screen.getByRole("button", { name: "Migrate Instances (1)" }));
    expect(screen.getByRole("heading", { name: "Old VPN" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Preview migration" })).toBeTruthy();
  });
  it("offers only four supported backends for creation", async () => {
    render(App);
    await screen.findByText("No VPN instances configured on this server.");
    await fireEvent.click(screen.getByRole("button", { name: "Create Instance" }));
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["WireGuard", "AmneziaWG", "OpenVPN", "IKEv2/IPsec"]);
    expect(document.body.textContent).not.toMatch(/xray|vless/i);
  });
});
