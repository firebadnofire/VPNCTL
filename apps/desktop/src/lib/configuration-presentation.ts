import type { Configuration } from "./remote-types";

export function configurationStatus(saved: number, deployed: number | null | undefined, dirty = false, conflict = false): string {
  if (conflict) return "Server configuration changed";
  if (dirty) return "Unsaved changes";
  if (deployed == null) return "Deployment status unknown";
  return saved === deployed ? "Configuration up to date" : "Changes ready to deploy";
}
export interface Difference { section: string; field: string; base?: string; local: string; server: string }
// Only public managed configuration is accepted here; never export artifacts or credential bindings.
function fields(configuration: Configuration): Map<string, string> {
  const result = new Map<string, string>();
  function visit(path: string, value: unknown) {
    if (Array.isArray(value)) {
      if (!value.length) result.set(path, "None");
      value.forEach((item, index) => visit(`${path} / ${item && typeof item === "object" && "id" in item ? item.id : index + 1}`, item));
    } else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        if (["created_at", "updated_at", "host_id", "id", "instance_id", "private_key_ref", "preshared_key_ref", "preshared_key"].includes(key)) continue;
        visit(path ? `${path} / ${key.replaceAll("_", " ")}` : key.replaceAll("_", " "), child);
      }
    } else result.set(path, value == null ? "Not set" : typeof value === "boolean" ? value ? "Yes" : "No" : String(value));
  }
  visit("Instance settings", configuration.instance);
  visit("Devices", configuration.peers);
  visit("DNS records", configuration.dns_records);
  visit("DNS blocklist", configuration.dns_blocklist_domains);
  visit("Users", configuration.users);
  return result;
}
export function configurationDifferences(local: Configuration, server: Configuration, base?: Configuration): Difference[] {
  const left = fields(local), right = fields(server), original = base ? fields(base) : undefined;
  return [...new Set([...left.keys(), ...right.keys(), ...(original?.keys() ?? [])])].sort().flatMap(key => {
    const l = left.get(key) ?? "Removed", r = right.get(key) ?? "Removed", b = original?.get(key) ?? "Removed";
    if (l === r && (!original || b === l)) return [];
    const [section, ...path] = key.split(" / ");
    return [{ section, field: path.join(" / ") || section, local: l, server: r, ...(original ? { base: b } : {}) }];
  });
}
