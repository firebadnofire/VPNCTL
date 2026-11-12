import { writable } from "svelte/store";

export type NotificationKind = "success" | "info" | "warning";
export interface Notification { id: number; message: string; kind: NotificationKind; timestamp: number }
export function createNotifications() {
  const visible = writable<Notification[]>([]);
  const history = writable<Notification[]>([]);
  let sequence = 0;
  const active = new Map<number, { remaining: number; started: number; timer?: ReturnType<typeof setTimeout>; pauses: Set<string> }>();
  function dismiss(id: number) {
    clearTimeout(active.get(id)?.timer); active.delete(id);
    visible.update(items => items.filter(item => item.id !== id));
  }
  function resume(id: number, reason: string) {
    const entry = active.get(id); if (!entry) return;
    entry.pauses.delete(reason); if (entry.pauses.size || entry.timer) return;
    entry.started = Date.now(); entry.timer = setTimeout(() => dismiss(id), entry.remaining);
  }
  function pause(id: number, reason: string) {
    const entry = active.get(id); if (!entry) return;
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = undefined; entry.remaining = Math.max(0, entry.remaining - (Date.now() - entry.started)); }
    entry.pauses.add(reason);
  }
  function record(message: string, kind: NotificationKind = "info") {
    history.update(items => items[0]?.message === message && items[0]?.kind === kind ? items : [{ id: ++sequence, message, kind, timestamp: Date.now() }, ...items].slice(0, 100));
  }
  function notify(message: string, kind: NotificationKind = "success") {
    // Callers supply public, curated operation summaries, never exported artifacts.
    let duplicate = false;
    visible.update(items => { duplicate = items.some(item => item.message === message && item.kind === kind); return items; });
    if (duplicate) return;
    const item = { id: ++sequence, message, kind, timestamp: Date.now() };
    visible.update(items => [...items, item]);
    history.update(items => [item, ...items].slice(0, 100));
    active.set(item.id, { remaining: { success: 5000, info: 7000, warning: 10000 }[kind], started: Date.now(), pauses: new Set() });
    resume(item.id, "initial");
  }
  function destroy() { for (const id of active.keys()) dismiss(id); history.set([]); }
  return { visible, history, notify, dismiss, pause, resume, record, destroy };
}
export type Notifications = ReturnType<typeof createNotifications>;
