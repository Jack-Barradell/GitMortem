export type Find = "hit" | "current";

export interface Piece {
  text: string;
  cls: number;
  known: boolean;
  find: Find | undefined;
  subject: string | undefined;
}

export interface Span {
  from: number;
  to: number;
}

export interface Drawn {
  index: number;
  gap: number;
}

export function rowsToDraw(
  count: number,
  view: Span,
  kept: Span | null,
): { top: number; rows: Drawn[] } {
  const last = Math.max(0, count - 1);
  const within = (at: number) => Math.min(Math.max(0, at), last);
  const spans = [view, ...(kept === null ? [] : [kept])]
    .map((span) => ({ from: within(span.from), to: within(span.to) }))
    .sort((a, b) => a.from - b.from);
  const rows: Drawn[] = [];
  let end = -1;
  for (const span of spans) {
    if (span.to <= end) continue;
    const from = Math.max(span.from, end + 1);
    if (rows.length > 0 && from > end + 1) rows.push({ index: end + 1, gap: from - end - 1 });
    for (let index = from; index <= span.to; index += 1) rows.push({ index, gap: 0 });
    end = span.to;
  }
  return { top: Math.min(...spans.map((span) => span.from)), rows };
}
