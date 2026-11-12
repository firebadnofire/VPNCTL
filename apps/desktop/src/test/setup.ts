import { cleanup } from "@testing-library/svelte";
import { afterEach } from "vitest";

afterEach(() => cleanup());

// jsdom does not implement native dialog or media-query behavior.
HTMLDialogElement.prototype.showModal = function () { this.open = true; this.querySelector<HTMLButtonElement>("button")?.focus(); };
HTMLDialogElement.prototype.close = function () { this.open = false; };
Object.defineProperty(window, "matchMedia", { writable: true, value: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }) });
Element.prototype.animate = (() => ({ finished: Promise.resolve(), cancel() {}, finish() {}, onfinish: null, effect: { getComputedTiming: () => ({ progress: 1 }) } })) as unknown as typeof Element.prototype.animate;
