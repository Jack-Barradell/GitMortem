import { ApiError } from "@/api/client";
import { messageFor } from "@/format";
import type { components } from "@/api/schema";
import { IMPORT_REFUSALS, RULE_REFUSALS } from "@/labels";

type RuleRefusalReason = components["schemas"]["RuleRefusal"];
type ImportRefusalReason = components["schemas"]["ImportRefusal"];

export function isRuleRefusal(reason: unknown): reason is RuleRefusalReason {
  return typeof reason === "string" && Object.hasOwn(RULE_REFUSALS, reason);
}

function detailOf(failure: unknown): Record<string, unknown> {
  const body = failure instanceof ApiError ? failure.body : undefined;
  const detail =
    typeof body === "object" && body !== null && "detail" in body ? body.detail : undefined;
  return typeof detail === "object" && detail !== null ? (detail as Record<string, unknown>) : {};
}

export function ruleProblems(failure: unknown): string[] {
  const detail = detailOf(failure);
  if (isRuleRefusal(detail.reason)) return [RULE_REFUSALS[detail.reason]];
  const fields = detail.json;
  if (typeof fields === "object" && fields !== null) {
    const lines = Object.entries(fields).flatMap(([field, messages]) =>
      (Array.isArray(messages) ? messages : []).map(
        (message) => `${field}: ${String(message).replace(/^Value error, /, "")}`,
      ),
    );
    if (lines.length > 0) return lines;
  }
  return [messageFor(failure)];
}

export interface FileRefusal {
  index: number | null;
  reason: string;
}

export function fileRefusals(failure: unknown): FileRefusal[] | null {
  const refused = detailOf(failure).refused;
  if (!Array.isArray(refused)) return null;
  return refused.map((found: { index?: unknown; reason?: unknown }) => ({
    index: typeof found.index === "number" ? found.index : null,
    reason: typeof found.reason === "string" ? found.reason : "",
  }));
}

export function reasonOf(failure: unknown): string | null {
  const reason = detailOf(failure).reason;
  return typeof reason === "string" ? reason : null;
}

export function importProblem(failure: unknown): string {
  const reason = reasonOf(failure);
  if (reason !== null && Object.hasOwn(IMPORT_REFUSALS, reason)) {
    return IMPORT_REFUSALS[reason as ImportRefusalReason];
  }
  return messageFor(failure);
}
