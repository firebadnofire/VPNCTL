import { afterEach, describe, expect, it, vi } from "vitest";
import { get } from "svelte/store";
import { createNotifications } from "./notifications";

afterEach(() => vi.useRealTimers());
describe("notification lifecycle", () => {
  it.each([["success", 5000], ["info", 7000], ["warning", 10000]] as const)("dismisses %s at its deadline", (kind, deadline) => {
    vi.useFakeTimers(); const n = createNotifications(); n.notify("Complete", kind);
    vi.advanceTimersByTime(deadline - 1); expect(get(n.visible)).toHaveLength(1);
    vi.advanceTimersByTime(1); expect(get(n.visible)).toHaveLength(0); expect(get(n.history)).toHaveLength(1); n.destroy();
  });
  it("deduplicates, pauses hover and focus independently, and resumes remaining time", () => {
    vi.useFakeTimers(); const n = createNotifications(); n.notify("Saved"); n.notify("Saved");
    expect(get(n.visible)).toHaveLength(1);
    vi.advanceTimersByTime(2000); n.pause(1, "hover"); n.pause(1, "focus");
    vi.advanceTimersByTime(10000); n.resume(1, "hover"); vi.advanceTimersByTime(10000);
    expect(get(n.visible)).toHaveLength(1); n.resume(1, "focus");
    vi.advanceTimersByTime(2999); expect(get(n.visible)).toHaveLength(1);
    vi.advanceTimersByTime(1); expect(get(n.visible)).toHaveLength(0); n.destroy();
  });
  it("bounds session history and dismisses without erasing history", () => {
    const n = createNotifications(); for (let i = 0; i < 110; i++) { n.notify(`Operation ${i}`); n.dismiss(i + 1); }
    expect(get(n.visible)).toHaveLength(0); expect(get(n.history)).toHaveLength(100); n.destroy(); expect(get(n.history)).toHaveLength(0);
  });
});
