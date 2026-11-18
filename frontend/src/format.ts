import { ApiError } from "@/api/client";
import type { components } from "@/api/schema";

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function messageFor(failure: unknown): string {
  return failure instanceof ApiError
    ? failure.message
    : "Could not reach the server. Check that GitMortem is running.";
}

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function formatBytes(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${value} B`;
  return `${value.toFixed(value < 10 ? 1 : 0)} ${BYTE_UNITS[unit]}`;
}

export function formatDuration(startedAt: string | null, finishedAt: string | null): string {
  if (startedAt === null || finishedAt === null) return "–";
  const seconds = Math.max(0, Math.round((Date.parse(finishedAt) - Date.parse(startedAt)) / 1000));
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${String(seconds % 60).padStart(2, "0")} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}

const BIDI = "\\u061C\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069";
const BIDI_CONTROLS = new RegExp(`[${BIDI}]`, "g");
const REPLACED_IN_LINES = new RegExp(`[\\0-\\x08\\x0B-\\x1F\\x7F-\\x9F${BIDI}]`, "g");

export function shown(text: string): string {
  return text.replace(BIDI_CONTROLS, "\uFFFD");
}

export function shownLine(text: string): string {
  return text.replace(REPLACED_IN_LINES, "\uFFFD");
}

const REPLACED_IN_NAMES = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function shownName(text: string): string {
  return text.replace(REPLACED_IN_NAMES, "\uFFFD");
}

export function statusReport(
  result: components["schemas"]["StatusOut"],
  note: string,
): { severity: "success" | "warn"; detail: string } {
  const parts = [`${result.changed} changed`];
  if (result.unchanged > 0) parts.push(`${result.unchanged} already that status`);
  if (result.skipped_total > 0) parts.push(`${result.skipped_total} skipped`);
  let detail = parts.join(", ");
  if (note.trim() !== "" && result.changed === 0) {
    detail += ". The note was not added, because nothing changed.";
  }
  return { severity: result.changed > 0 ? "success" : "warn", detail };
}
