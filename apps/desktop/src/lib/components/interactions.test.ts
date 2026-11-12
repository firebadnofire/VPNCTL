import { fireEvent, render, screen } from "@testing-library/svelte";
import { expect, it } from "vitest";
import Harness from "../../test/InteractionHarness.svelte";

it("opens a semantic dialog, handles Escape cancellation and restores focus", async () => {
  render(Harness); const trigger = screen.getByText("Open dialog"); trigger.focus();
  await fireEvent.click(trigger); const dialog = screen.getByRole("dialog", { name: "Test dialog" });
  expect(dialog.contains(document.activeElement)).toBe(true);
  await fireEvent(dialog, new Event("cancel", { cancelable: true }));
  expect(screen.queryByRole("dialog")).toBeNull(); expect(document.activeElement).toBe(trigger);
});
it("shows explanatory text on focus or tap and closes with Escape", async () => {
  render(Harness); const trigger = screen.getByRole("button", { name: "About saving" });
  await fireEvent.focus(trigger); expect(screen.getByRole("tooltip").textContent).toContain("remote server");
  await fireEvent.keyDown(trigger, { key: "Escape" }); expect(screen.queryByRole("tooltip")).toBeNull();
  await fireEvent.click(trigger); expect(screen.getByRole("tooltip")).toBeTruthy();
});
