import { fireEvent, render, screen } from "@testing-library/svelte";
import { expect, it, vi } from "vitest";
import ErrorFeedback from "./ErrorFeedback.svelte";

it("gives a backup prerequisite a real next step instead of claiming fields are highlighted", async () => {
  const ondeployment = vi.fn();
  render(ErrorFeedback, { props: { error: { code: "validation", message: "Deploy the instance successfully before creating a restorable manual backup.", remediation: "Correct the highlighted values and try again.", remote_state_changed: false }, operation: "Creating runtime backup", context: "Home VPN / Special", ondeployment } });
  expect(screen.getByRole("alert").textContent).not.toContain("highlighted");
  expect(screen.getByText("Creating runtime backup · Home VPN / Special")).toBeTruthy();
  await fireEvent.click(screen.getByRole("button", { name: "Open Deployment" }));
  expect(ondeployment).toHaveBeenCalledOnce();
});
it("always provides collapsed diagnostics even without server output", () => {
  render(ErrorFeedback, { props: { error: { code: "validation", message: "A device name is required.", remote_state_changed: false } } });
  const summary = screen.getByText("Technical details");
  expect(summary.closest("details")?.open).toBe(false);
  expect(screen.getByText("validation")).toBeTruthy();
  expect(screen.getByText("No additional diagnostics were supplied.")).toBeTruthy();
});
it("shows the failed stage and preserves multiline diagnostics as text", async () => {
  const ondismiss = vi.fn();
  render(ErrorFeedback, { props: { error: { code: "remote_command", message: "A fixed remote operation failed.", scope: "compose_build", technical_detail: "exit_status=1\n<script>not executable</script>", remote_state_changed: true, rollback_succeeded: false }, operation: "Deploying saved configuration", ondismiss } });
  expect(screen.getByText("A command on the server failed.")).toBeTruthy();
  expect(screen.getByText(/The server may have changed/)).toBeTruthy();
  expect(screen.getByText(/Automatic recovery did not complete/)).toBeTruthy();
  expect(screen.getByText("compose_build")).toBeTruthy();
  expect(screen.getByText(/not executable/).tagName).toBe("PRE");
  expect(document.querySelector(".error-feedback script")).toBeNull();
  await fireEvent.click(screen.getByRole("button", { name: "Dismiss error" }));
  expect(ondismiss).toHaveBeenCalledOnce();
});
