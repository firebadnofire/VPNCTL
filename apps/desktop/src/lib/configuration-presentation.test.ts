import { expect, it } from "vitest";
import { configurationDifferences, configurationStatus } from "./configuration-presentation";
import { summary } from "../test/fixtures";
import type { Configuration } from "./remote-types";
it("does not mistake unknown deployment or configuration matching for health", () => {
  expect(configurationStatus(4, undefined)).toBe("Deployment status unknown");
  expect(configurationStatus(4, 4)).toBe("Configuration up to date");
  expect(configurationStatus(5, 4)).toBe("Changes ready to deploy");
  expect(configurationStatus(5, 4, true, true)).toBe("Server configuration changed");
});
it("compares the original, local and remote configuration without credential references", () => {
  const base: Configuration = { instance: summary("wireguard").instance, peers: [], users: [], dns_records: [], dns_blocklist_domains: [] };
  const local = structuredClone(base), server = structuredClone(base);
  local.instance.display_name = "My draft"; server.instance.display_name = "Another client";
  const row = configurationDifferences(local, server, base).find(item => item.field === "display name");
  expect(row).toMatchObject({ local: "My draft", server: "Another client", base: base.instance.display_name });
  expect(configurationDifferences(local, server)[0].base).toBeUndefined();
});
