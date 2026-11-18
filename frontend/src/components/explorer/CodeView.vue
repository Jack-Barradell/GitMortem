<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import {
  computed,
  markRaw,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  useId,
  useTemplateRef,
  watch,
} from "vue";
import type { components } from "@/api/schema";
import { MAX_HIGHLIGHT_LINE_CHARS, lineBody, type LineTokens } from "@/explorer/highlight/encode";
import { highlight, withinHighlightCaps } from "@/explorer/highlight/highlightClient";
import { languageFor } from "@/explorer/highlight/languages";
import { rowsToDraw, type Find, type Piece, type Span } from "@/explorer/rows";
import { shownLine } from "@/format";
import CodeRow from "./CodeRow.vue";

type Mark = components["schemas"]["FileOut.MarkOut"];

const props = defineProps<{ text: string; path: string; line: number | null; marks: Mark[] }>();
const emit = defineEmits<{ pick: [subject: string] }>();

const ROW_HEIGHT = 20;
const ROWS_ABOVE = 4;
const BUFFER = 10;
const MAX_KEPT_ROWS = 20_000;
const KEPT_CAP =
  "A selection is kept for up to 20,000 lines: past that, the lines scrolled away leave it.";
const TOO_LARGE = "Too large to highlight (over 5 MiB or 100,000 lines): shown as plain text.";
const NOT_HIGHLIGHTED = "Not highlighted: shown as plain text.";
const LONG_LINES = "Lines over 5,000 characters are shown as plain text.";
const MAX_FIND_MATCHES = 100_000;
const MAX_ROW_MATCHES = 200;
const byNumber = (a: number, b: number) => a - b;

const scroller = useTemplateRef<HTMLElement>("scroller");
const root = useTemplateRef<HTMLElement>("root");
const scrollTop = ref(0);
const viewHeight = ref(0);
const firstRow = computed(() => Math.floor(scrollTop.value / ROW_HEIGHT));
const rowsShown = computed(() => Math.ceil(viewHeight.value / ROW_HEIGHT));
const kept = ref<Span | null>(null);
const keptCapped = ref(false);

const lines = computed(() => markRaw(props.text.split("\n")));
const lineStarts = computed(() => {
  const starts = new Uint32Array(lines.value.length);
  let at = 0;
  for (const [index, line] of lines.value.entries()) {
    starts[index] = at;
    at += line.length + 1;
  }
  return starts;
});
const drawn = computed(() =>
  rowsToDraw(
    lines.value.length,
    { from: firstRow.value - BUFFER, to: firstRow.value + rowsShown.value + BUFFER },
    kept.value,
  ),
);
const drawnTop = computed(() => drawn.value.top * ROW_HEIGHT);
const gutter = computed(() => ({
  "--code-gutter-digits": String(String(lines.value.length).length),
}));
const marksByLine = computed(() => {
  const byLine = new Map<number, Mark[]>();
  for (const mark of props.marks) {
    const onLine = byLine.get(mark.line);
    if (onLine === undefined) byLine.set(mark.line, [mark]);
    else onLine.push(mark);
  }
  return byLine;
});

let tokens: (LineTokens | undefined)[] = [];
const painted = ref(0);
const note = ref("");
const longLines = ref(false);
let generation = 0;

async function paint(): Promise<void> {
  const mine = (generation += 1);
  tokens = [];
  painted.value += 1;
  note.value = "";
  longLines.value = false;
  const lang = languageFor(props.path);
  if (lang === null) return;
  if (!withinHighlightCaps(props.text)) {
    note.value = TOO_LARGE;
    return;
  }
  longLines.value = lines.value.some(
    (line) =>
      line.length > MAX_HIGHLIGHT_LINE_CHARS && lineBody(line).length > MAX_HIGHLIGHT_LINE_CHARS,
  );
  let at = 0;
  for await (const chunk of highlight(props.text, lang)) {
    if (mine !== generation) return;
    for (const pairs of chunk) tokens[at++] = pairs;
    painted.value += 1;
  }
  if (mine === generation && at < lines.value.length) {
    note.value =
      at === 0 ? NOT_HIGHLIGHTED : `Highlighted to line ${at}; the rest is shown as plain text.`;
  }
}

watch([() => props.text, () => props.path], () => void paint(), { immediate: true });

const query = ref("");
const current = ref(0);
const findId = useId();

function found(text: string, needle: string): { starts: Uint32Array; cut: boolean } {
  let starts = new Uint32Array(0);
  if (needle === "" || needle.includes("\n")) return { starts, cut: false };
  let count = 0;
  for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + needle.length)) {
    if (count === MAX_FIND_MATCHES) return { starts, cut: true };
    if (count === starts.length) {
      const grown = new Uint32Array(Math.min(MAX_FIND_MATCHES, Math.max(64, count * 2)));
      grown.set(starts);
      starts = grown;
    }
    starts[count++] = at;
  }
  return { starts: starts.subarray(0, count), cut: false };
}

const finding = computed(() => found(props.text, query.value));
const hits = computed(() => finding.value.starts);

function firstAtOrAfter(values: Uint32Array, at: number): number {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if ((values[middle] ?? 0) < at) low = middle + 1;
    else high = middle;
  }
  return low;
}

function lineAt(offset: number): number {
  return firstAtOrAfter(lineStarts.value, offset + 1) - 1;
}

function restart(): void {
  const from = props.line === null ? 0 : (lineStarts.value[props.line - 1] ?? 0);
  const next = firstAtOrAfter(hits.value, from);
  current.value = next < hits.value.length ? next : 0;
}

function step(by: number): void {
  const count = hits.value.length;
  if (count === 0) return;
  current.value = (current.value + by + count) % count;
  void reveal();
}

const findCount = computed(() => {
  if (query.value === "") return "";
  const { starts, cut } = finding.value;
  if (starts.length === 0) return "No matches";
  const at = (current.value + 1).toLocaleString("en-US");
  const of = starts.length.toLocaleString("en-US");
  return cut ? `${at} of the first ${of}` : `${at} of ${of}`;
});

watch(() => props.text, restart);
watch(query, () => {
  restart();
  void reveal();
});

const mountedView = () => scroller.value as HTMLElement;

function measure(view: HTMLElement): void {
  scrollTop.value = view.scrollTop;
  viewHeight.value = view.clientHeight;
}

function scrolled(event: Event): void {
  measure(event.currentTarget as HTMLElement);
}

function scrollToRow(index: number): void {
  const view = scroller.value;
  if (view === null) return;
  view.scrollTo({ top: Math.max(0, index - ROWS_ABOVE) * ROW_HEIGHT });
  measure(view);
}

async function reveal(): Promise<void> {
  const at = hits.value[current.value];
  if (at === undefined) return;
  const index = lineAt(at);
  if (index < firstRow.value || index >= firstRow.value + rowsShown.value) scrollToRow(index);
  await nextTick();
  root.value
    ?.querySelector('[data-find="current"]')
    ?.scrollIntoView({ block: "nearest", inline: "nearest" });
}

async function openAt(): Promise<void> {
  await nextTick();
  scrollToRow(props.line === null ? 0 : props.line - 1);
}
watch([() => props.text, () => props.line], () => void openAt());

function release(): void {
  kept.value = null;
  keptCapped.value = false;
}

function pointIn(node: Node, offset: number, element: Element): number {
  const range = document.createRange();
  range.selectNodeContents(element);
  return range.comparePoint(node, offset);
}

function rowAt(view: HTMLElement, node: Node, offset: number): number {
  const holder = node instanceof Element ? node : node.parentElement;
  const own = holder?.closest<HTMLElement>("[data-line]");
  if (own) return Number(own.dataset.line) - 1;
  const rows = view.querySelectorAll<HTMLElement>("[data-line]");
  let low = 0;
  let high = rows.length - 1;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (pointIn(node, offset, rows.item(middle)) > 0) low = middle + 1;
    else high = middle;
  }
  return Number(rows.item(low).dataset.line) - 1;
}

function selected(): void {
  const view = mountedView();
  const selection = document.getSelection();
  if (!selection?.rangeCount) {
    release();
    return;
  }
  const range = selection.getRangeAt(0);
  const startsIn = pointIn(range.startContainer, range.startOffset, view) === 0;
  const endsIn = pointIn(range.endContainer, range.endOffset, view) === 0;
  if (!startsIn && !endsIn) {
    release();
    return;
  }
  if (keptCapped.value && !range.collapsed) return;
  const from = startsIn ? rowAt(view, range.startContainer, range.startOffset) : 0;
  const to = endsIn ? rowAt(view, range.endContainer, range.endOffset) : lines.value.length - 1;
  if (to - from + 1 > MAX_KEPT_ROWS) {
    kept.value = null;
    keptCapped.value = true;
    return;
  }
  keptCapped.value = false;
  if (kept.value?.from !== from || kept.value.to !== to) kept.value = { from, to };
}

watch(() => props.text, release);

let resizes: ResizeObserver | null = null;
onMounted(() => {
  const view = mountedView();
  measure(view);
  resizes = new ResizeObserver(() => measure(view));
  resizes.observe(view);
  document.addEventListener("selectionchange", selected);
  void openAt();
});
onBeforeUnmount(() => {
  generation += 1;
  resizes?.disconnect();
  document.removeEventListener("selectionchange", selected);
});

function matchesIn(line: string, index: number, clamp: (offset: number) => number) {
  const lineStart = lineStarts.value[index] ?? 0;
  const first = firstAtOrAfter(hits.value, lineStart);
  const after = firstAtOrAfter(hits.value, lineStart + line.length);
  let from = first;
  if (current.value >= first && current.value < after) {
    const centred = current.value - MAX_ROW_MATCHES / 2;
    from = Math.max(first, Math.min(centred, after - MAX_ROW_MATCHES));
  }
  const shown: [number, number, Find][] = [];
  const marked = hits.value.subarray(from, Math.min(after, from + MAX_ROW_MATCHES));
  for (const [offset, at] of marked.entries()) {
    const start = at - lineStart;
    const kind = from + offset === current.value ? "current" : "hit";
    shown.push([clamp(start), clamp(start + query.value.length), kind]);
  }
  return shown;
}

function piecesOf(line: string, index: number): Piece[] {
  void painted.value;
  const end = line.endsWith("\r") ? line.length - 1 : line.length;
  const clamp = (offset: number) => Math.min(Math.max(offset, 0), end);
  const cuts = [0, end];
  const runs: { end: number; cls: number }[] = [];
  let at = 0;
  for (const [offset, word] of (tokens[index] ?? []).entries()) {
    if (offset % 2 === 0) at += word;
    else runs.push({ end: at, cls: word });
  }
  for (const run of runs) cuts.push(clamp(run.end));
  const opens: number[] = [];
  const closes: number[] = [];
  const onLine = marksByLine.value.get(index + 1) ?? [];
  for (const mark of onLine) {
    const start = clamp(mark.start);
    const stop = clamp(mark.end);
    if (start >= stop) continue;
    opens.push(start);
    closes.push(stop);
    cuts.push(start, stop);
  }
  opens.sort(byNumber);
  closes.sort(byNumber);
  const matches = matchesIn(line, index, clamp);
  for (const [start, stop] of matches) cuts.push(start, stop);
  cuts.sort(byNumber);

  const owned = onLine
    .filter((m): m is Mark & { subject: string } => m.subject !== null)
    .map((m) => ({ start: clamp(m.start), end: clamp(m.end), subject: m.subject }))
    .sort((a, b) => a.start - b.start);
  let active: typeof owned = [];
  let nextOwned = 0;

  const pieces: Piece[] = [];
  let run = 0;
  let opened = 0;
  let closed = 0;
  let match = 0;
  for (const [point, from] of cuts.entries()) {
    const to = cuts[point + 1];
    if (to === undefined) break;
    if (to === from) continue;
    while ((runs[run]?.end ?? Infinity) <= from) run += 1;
    while ((opens[opened] ?? Infinity) <= from) opened += 1;
    while ((closes[closed] ?? Infinity) <= from) closed += 1;
    while ((matches[match]?.[1] ?? Infinity) <= from) match += 1;
    const cls = runs[run]?.cls ?? 0;
    const known = opened > closed;
    const covering = matches[match];
    const find = covering !== undefined && covering[0] <= from ? covering[2] : undefined;
    let subject: string | undefined;
    if (known && owned.length > 0) {
      while ((owned[nextOwned]?.start ?? Infinity) <= from) {
        active.push(owned[nextOwned] as (typeof owned)[number]);
        nextOwned += 1;
      }
      if (active.some((m) => m.end <= from)) active = active.filter((m) => m.end > from);
      subject = active[0]?.subject;
    }
    const last = pieces.at(-1);
    const text = shownLine(line.slice(from, to));
    if (
      last !== undefined &&
      last.cls === cls &&
      last.known === known &&
      last.find === find &&
      last.subject === subject
    )
      last.text += text;
    else pieces.push({ text, cls, known, find, subject });
  }
  return pieces;
}

function picked(event: MouseEvent): void {
  const target = event.target;
  const marked = target instanceof Element ? target.closest<HTMLElement>("[data-subject]") : null;
  const subject = marked?.dataset.subject;
  if (subject) emit("pick", subject);
}
</script>

<template>
  <div ref="root" class="code-view flex h-full min-h-0 flex-col" :style="gutter">
    <form class="flex items-center gap-2 pb-2" role="search" @submit.prevent="step(1)">
      <label :for="findId" class="text-sm">Find in this file</label>
      <InputText
        :id="findId"
        v-model="query"
        size="small"
        autocomplete="off"
        spellcheck="false"
        @keydown.enter.shift.prevent="step(-1)"
      />
      <Button
        type="button"
        icon="pi pi-chevron-up"
        size="small"
        severity="secondary"
        text
        aria-label="Previous match"
        :disabled="hits.length === 0"
        @click="step(-1)"
      />
      <Button
        type="submit"
        icon="pi pi-chevron-down"
        size="small"
        severity="secondary"
        text
        aria-label="Next match"
        :disabled="hits.length === 0"
      />
      <span class="text-sm text-surface-500" data-test="find-count" aria-live="polite">{{
        findCount
      }}</span>
    </form>
    <p v-if="note" class="pb-2 text-sm text-surface-500" data-test="highlight-note">{{ note }}</p>
    <p v-if="longLines" class="pb-2 text-sm text-surface-500" data-test="long-lines-note">
      {{ LONG_LINES }}
    </p>
    <div
      class="min-h-0 flex-1 overflow-hidden rounded-md border border-surface-200 dark:border-surface-700"
    >
      <div
        ref="scroller"
        class="code-scroller font-mono text-sm"
        role="region"
        aria-label="The file's lines"
        tabindex="0"
        @scroll.passive="scrolled"
        @click="picked"
      >
        <div class="code-spacer" :style="{ height: `${lines.length * ROW_HEIGHT}px` }">
          <div class="code-rows" :style="{ transform: `translateY(${drawnTop}px)` }">
            <template
              v-for="item in drawn.rows"
              :key="item.gap === 0 ? item.index : `gap${item.index}`"
            >
              <CodeRow
                v-if="item.gap === 0"
                :index="item.index"
                :text="lines[item.index] ?? ''"
                :target="item.index + 1 === line"
                :pieces-of="piecesOf"
              />
              <div
                v-else
                class="code-gap"
                :data-gap="item.index"
                :style="{ height: `${item.gap * ROW_HEIGHT}px` }"
              />
            </template>
          </div>
        </div>
      </div>
    </div>
    <p
      v-if="keptCapped"
      class="pt-2 text-sm text-surface-500"
      data-test="selection-cap-note"
      role="status"
    >
      {{ KEPT_CAP }}
    </p>
  </div>
</template>
