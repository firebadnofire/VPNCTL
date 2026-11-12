import { expect, it } from "vitest";
import { formFeedback } from "./form-feedback";
it("shows accessible inline validation and removes it after correction", () => {
  const form = document.createElement("form"), input = document.createElement("input"); input.required = true;
  form.append(input); document.body.append(form); const action = formFeedback(form);
  input.dispatchEvent(new Event("invalid")); expect(input.getAttribute("aria-invalid")).toBe("true");
  expect(form.querySelector(".field-error")?.textContent).toBeTruthy();
  input.value = "   "; input.dispatchEvent(new Event("focusout", { bubbles: true })); expect(input.validity.valid).toBe(false);
  input.value = "Laptop"; input.dispatchEvent(new Event("input", { bubbles: true }));
  expect(input.hasAttribute("aria-invalid")).toBe(false); expect(form.querySelector(".field-error")).toBeNull();
  action.destroy(); form.remove();
});
