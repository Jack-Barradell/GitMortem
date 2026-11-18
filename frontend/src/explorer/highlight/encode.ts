import type { LangId } from "./languages";

export const TOKEN_CLASSES = [
  "tok-plain",
  "tok-keyword",
  "tok-string",
  "tok-string-expression",
  "tok-comment",
  "tok-constant",
  "tok-function",
  "tok-parameter",
  "tok-punctuation",
  "tok-link",
  "tok-inserted",
  "tok-deleted",
  "tok-changed",
] as const;

export const MAX_HIGHLIGHT_LINE_CHARS = 5_000;

export type LineTokens = Uint32Array;

export type HighlightRequest =
  { kind: "highlight"; id: number; text: string; lang: LangId } | { kind: "stop"; id: number };

export type HighlightReply =
  | { kind: "chunk"; id: number; data: Uint32Array }
  | { kind: "end"; id: number }
  | { kind: "failed"; id: number };

export interface ShikiToken {
  content: string;
  color?: string;
}

const CLASS_OF = new Map<string, number>(
  TOKEN_CLASSES.map((name, index) => [
    index === 0 ? "var(--gm-foreground)" : `var(--gm-token-${name.slice("tok-".length)})`,
    index,
  ]),
);

const CR = 13;

export function classOf(color: string | undefined): number {
  return CLASS_OF.get(color ?? "") ?? 0;
}

export function lineBody(line: string): string {
  let end = line.length;
  while (end > 0 && line.charCodeAt(end - 1) === CR) end -= 1;
  return end === line.length ? line : line.slice(0, end);
}

export function encodeChunk(
  lines: readonly string[],
  tokens: readonly (readonly ShikiToken[])[],
): Uint32Array {
  const words: number[] = [lines.length];
  for (const [index, line] of lines.entries()) {
    const pairs: number[] = [];
    let runLength = 0;
    let runClass = 0;
    const add = (length: number, cls: number) => {
      if (length === 0) return;
      if (cls !== runClass && runLength > 0) {
        pairs.push(runLength, runClass);
        runLength = 0;
      }
      runClass = cls;
      runLength += length;
    };
    for (const token of tokens[index] ?? []) add(token.content.length, classOf(token.color));
    add(line.length - lineBody(line).length, 0);
    if (runLength > 0) pairs.push(runLength, runClass);
    words.push(pairs.length / 2);
    for (const word of pairs) words.push(word);
  }
  return Uint32Array.from(words);
}

export function decodeChunk(
  data: Uint32Array,
  lines: readonly string[],
  from: number,
): LineTokens[] | null {
  const count = data[0];
  if (count === undefined || count === 0 || count > lines.length - from) return null;
  const decoded: LineTokens[] = [];
  let at = 1;
  for (const line of lines.slice(from, from + count)) {
    const pairs = data[at];
    if (pairs === undefined || at + 1 + pairs * 2 > data.length) return null;
    const words = data.subarray(at + 1, at + 1 + pairs * 2);
    let covered = 0;
    for (const [offset, word] of words.entries()) {
      if (offset % 2 === 1) {
        if (word >= TOKEN_CLASSES.length) return null;
        continue;
      }
      if (word === 0) return null;
      covered += word;
      if (covered > line.length) return null;
    }
    if (covered !== line.length) return null;
    decoded.push(words);
    at += 1 + words.length;
  }
  return at === data.length ? decoded : null;
}
