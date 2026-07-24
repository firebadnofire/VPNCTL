import { invoke } from "@tauri-apps/api/core";
import type { AppError } from "./types";

export async function call<T>(
  command: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (cause) {
    if (typeof cause === "object" && cause !== null && "message" in cause) {
      throw cause as AppError;
    }
    throw {
      code: "desktop_bridge",
      message: cause instanceof Error ? cause.message : String(cause),
      remote_state_changed: false,
    } satisfies AppError;
  }
}

export function errorText(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    return String(error.message);
  }
  return String(error);
}
