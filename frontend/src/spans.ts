import { ApiError, reasonIn } from "@/api/client";
import { confirmFirst } from "@/confirmFirst";

type Confirmer = Parameters<typeof confirmFirst>[0];

export class SpanDeclined extends Error {
  constructor() {
    super("The change was not confirmed.");
    this.name = "SpanDeclined";
  }
}

export function spannedRepositories(failure: unknown): number | null {
  if (!(failure instanceof ApiError) || failure.status !== 409) return null;
  if (reasonIn(failure.body) !== "spans_repositories") return null;
  const detail = (failure.body as { detail?: { repositories?: unknown } }).detail;
  return typeof detail?.repositories === "number" ? detail.repositories : null;
}

export function askAcross(confirm: Confirmer, repositories: number): Promise<boolean> {
  return new Promise((resolve) => {
    confirmFirst(confirm, {
      header: `Applies to ${repositories} repositories`,
      message:
        `This secret was found in ${repositories} repositories. Its status applies everywhere ` +
        "it was found, not only where this row shows it.",
      acceptLabel: "Set status",
      accept: () => resolve(true),
      reject: () => resolve(false),
      hidden: () => resolve(false),
    });
  });
}

export async function withAcross<T>(
  send: (across: number | null) => Promise<T>,
  ask: (repositories: number) => Promise<boolean>,
  first: number | null = null,
): Promise<{ result: T; across: number | null }> {
  try {
    return { result: await send(first), across: first };
  } catch (failure) {
    const repositories = spannedRepositories(failure);
    if (repositories === null) throw failure;
    if (!(await ask(repositories))) throw new SpanDeclined();
    return { result: await send(repositories), across: repositories };
  }
}
