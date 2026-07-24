import { describe, expect, it } from "vitest";
import { errorText } from "./api";

describe("errorText", () => {
  it("uses structured application messages", () => {
    expect(
      errorText({
        code: "host_key_changed",
        message: "The SSH host key changed.",
        remote_state_changed: false,
      }),
    ).toBe("The SSH host key changed.");
  });

  it("keeps non-object failures readable", () => {
    expect(errorText("offline")).toBe("offline");
  });
});
