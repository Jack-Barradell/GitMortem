import { decodeChunk, type HighlightReply, type HighlightRequest, type LineTokens } from "./encode";
import type { LangId } from "./languages";
import workerUrl from "./highlight.worker.ts?worker&url";

export const MAX_HIGHLIGHT_BYTES = 5 << 20;
export const MAX_HIGHLIGHT_LINES = 100_000;
export const WATCHDOG_MS = 5_000;

interface ScriptUrlPolicy {
  createScriptURL(input: string): unknown;
}
interface PolicyFactory {
  createPolicy(name: string, rules: { createScriptURL(input: string): string }): ScriptUrlPolicy;
}

interface Session {
  readonly id: number;
  readonly worker: Worker;
  readonly lines: readonly string[];
  next: number;
  readonly ready: LineTokens[][];
  ended: boolean;
  wake: () => void;
}

let policy: ScriptUrlPolicy | null | undefined;
let worker: Worker | null = null;
let watchdog: ReturnType<typeof setTimeout> | undefined;
let active: Session | null = null;
let lastId = 0;

function scriptUrl(): unknown {
  const factory = (globalThis as { trustedTypes?: PolicyFactory }).trustedTypes;
  if (factory === undefined) return workerUrl;
  if (policy === undefined) {
    try {
      policy = factory.createPolicy("gitmortem-worker", {
        createScriptURL(input) {
          if (input !== workerUrl) throw new TypeError("Only the highlighter's worker may start.");
          return input;
        },
      });
    } catch {
      policy = null;
    }
  }
  return policy?.createScriptURL(workerUrl) ?? null;
}

function isReply(data: unknown): data is HighlightReply {
  if (typeof data !== "object" || data === null) return false;
  const { kind, id } = data as { kind?: unknown; id?: unknown };
  if (typeof id !== "number") return false;
  if (kind === "end" || kind === "failed") return true;
  return kind === "chunk" && (data as { data?: unknown }).data instanceof Uint32Array;
}

function started(): Worker | null {
  if (worker !== null) return worker;
  const url = scriptUrl();
  if (url === null) return null;
  let made: Worker;
  try {
    made = new Worker(url as string, { type: "module" });
  } catch {
    return null;
  }
  made.onmessage = (event: MessageEvent<unknown>) => {
    if (isReply(event.data)) received(event.data);
    else if (active !== null) stop(active);
    arm();
  };
  made.onerror = (event) => {
    event.preventDefault();
    kill();
  };
  made.onmessageerror = kill;
  worker = made;
  return made;
}

function arm(): void {
  clearTimeout(watchdog);
  watchdog = active === null ? undefined : setTimeout(kill, WATCHDOG_MS);
}

function end(): void {
  const session = active;
  active = null;
  arm();
  if (session === null) return;
  session.ended = true;
  session.wake();
}

function kill(): void {
  worker?.terminate();
  worker = null;
  end();
}

function stop(session: Session): void {
  session.worker.postMessage({ kind: "stop", id: session.id } satisfies HighlightRequest);
  end();
}

function received(reply: HighlightReply): void {
  if (reply.kind === "failed") {
    kill();
    return;
  }
  const session = active;
  if (session === null || reply.id !== session.id) return;
  if (reply.kind === "end") {
    end();
    return;
  }
  const chunk = decodeChunk(reply.data, session.lines, session.next);
  if (chunk === null) {
    stop(session);
    return;
  }
  session.next += chunk.length;
  session.ready.push(chunk);
  session.wake();
}

function utf8Bytes(text: string): number {
  let bytes = 0;
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit < 0xdc00 && (text.charCodeAt(index + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
  }
  return bytes;
}

export function withinHighlightCaps(text: string): boolean {
  if (text.length > MAX_HIGHLIGHT_BYTES) return false;
  let lines = 1;
  for (let at = text.indexOf("\n"); at !== -1; at = text.indexOf("\n", at + 1)) {
    lines += 1;
    if (lines > MAX_HIGHLIGHT_LINES) return false;
  }
  return utf8Bytes(text) <= MAX_HIGHLIGHT_BYTES;
}

export async function* highlight(
  text: string,
  lang: LangId,
): AsyncGenerator<LineTokens[], void, undefined> {
  if (!withinHighlightCaps(text)) return;
  const to = started();
  if (to === null) return;
  if (active !== null) stop(active);
  const session: Session = {
    id: (lastId += 1),
    worker: to,
    lines: text.split("\n"),
    next: 0,
    ready: [],
    ended: false,
    wake: () => {},
  };
  active = session;
  to.postMessage({ kind: "highlight", id: session.id, text, lang } satisfies HighlightRequest);
  arm();
  try {
    for (;;) {
      const chunk = session.ready.shift();
      if (chunk !== undefined) yield chunk;
      else if (session.ended) return;
      else await new Promise<void>((resolve) => (session.wake = resolve));
    }
  } finally {
    if (active === session) stop(session);
  }
}
