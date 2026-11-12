let fieldSequence = 0;
/** Keep native constraints and add persistent inline feedback after blur or submit. */
export function formFeedback(form: HTMLFormElement) {
  const errors = new Map<HTMLInputElement | HTMLSelectElement, { node: HTMLSpanElement; describedBy: string | null }>();
  function update(event: Event) {
    const field = event.target;
    if (!(field instanceof HTMLInputElement || field instanceof HTMLSelectElement) || field.type === "password") return;
    // Whitespace-only required names should not become server mutations.
    if (field instanceof HTMLInputElement && field.type === "text" && field.required) field.setCustomValidity(field.value && !field.value.trim() ? "Enter a value containing more than spaces." : "");
    let entry = errors.get(field);
    if (field.validity.valid) {
      if (entry) { entry.node.remove(); if (entry.describedBy) field.setAttribute("aria-describedby", entry.describedBy); else field.removeAttribute("aria-describedby"); errors.delete(field); }
      field.removeAttribute("aria-invalid"); return;
    }
    if (event.type === "input" && !entry) return;
    if (!entry) {
      const node = document.createElement("span"); node.className = "field-error"; node.id = `field-error-${++fieldSequence}`;
      entry = { node, describedBy: field.getAttribute("aria-describedby") }; errors.set(field, entry);
      field.insertAdjacentElement("afterend", node);
      field.setAttribute("aria-describedby", [entry.describedBy, node.id].filter(Boolean).join(" "));
    }
    entry.node.textContent = field.validationMessage;
    field.setAttribute("aria-invalid", "true");
  }
  form.addEventListener("invalid", update, true); form.addEventListener("focusout", update); form.addEventListener("input", update);
  return { destroy() { form.removeEventListener("invalid", update, true); form.removeEventListener("focusout", update); form.removeEventListener("input", update); for (const { node } of errors.values()) node.remove(); } };
}
