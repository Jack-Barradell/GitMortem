<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Textarea from "primevue/textarea";
import { computed, onBeforeUnmount, ref, useTemplateRef, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { ruleProblems } from "@/problems";

type Match = components["schemas"]["RuleTestOut.RuleMatchOut"];

const MAX_SAMPLE = 65_536;
const LINES_PER_PAGE = 50;
const MATCHES_PER_LINE = 100;

const pattern = defineModel<string>("pattern", { required: true });
const sample = ref("");

interface Segment {
  text: string;
  kind: "plain" | "match" | "value";
}
interface ShownLine {
  number: number;
  segments: Segment[];
  more: number;
}
interface Outcome {
  total: number;
  lines: { number: number; text: string; matches: Match[] }[];
}

const outcome = ref<Outcome | null>(null);
const problems = ref<string[]>([]);
const running = ref(false);
const page = ref(0);

let generation = 0;

watch([pattern, sample], () => {
  generation++;
  outcome.value = null;
  problems.value = [];
});
onBeforeUnmount(() => {
  generation++;
});

const root = useTemplateRef<HTMLElement>("root");

function focus(): void {
  const box = root.value?.querySelector<HTMLTextAreaElement>("#try-pattern");
  box?.scrollIntoView({ block: "nearest" });
  box?.focus();
}
defineExpose({ focus });

function outcomeOf(matches: Match[], text: string): Outcome {
  const all = text.split("\n");
  const byLine = new Map<number, Match[]>();
  for (const found of matches) {
    const held = byLine.get(found.line);
    if (held === undefined) byLine.set(found.line, [found]);
    else held.push(found);
  }
  const lines = [...byLine.entries()]
    .filter(([number]) => number >= 1 && number <= all.length)
    .sort(([a], [b]) => a - b)
    .map(([number, found]) => ({ number, text: all[number - 1] ?? "", matches: found }));
  return { total: matches.length, lines };
}

function segmentsOf(text: string, matches: Match[]): Segment[] {
  const segments: Segment[] = [];
  let at = 0;
  const add = (kind: Segment["kind"], to: number): void => {
    const end = Math.min(Math.max(to, at), text.length);
    if (end > at) segments.push({ text: text.slice(at, end), kind });
    at = end;
  };
  for (const found of matches) {
    add("plain", found.start);
    add("match", found.value_start);
    add("value", found.value_end);
    add("match", found.end);
  }
  add("plain", text.length);
  return segments;
}

const pageCount = computed(() => Math.ceil((outcome.value?.lines.length ?? 0) / LINES_PER_PAGE));

const shown = computed<ShownLine[]>(() => {
  const start = page.value * LINES_PER_PAGE;
  return (outcome.value?.lines ?? []).slice(start, start + LINES_PER_PAGE).map((line) => ({
    number: line.number,
    segments: segmentsOf(line.text, line.matches.slice(0, MATCHES_PER_LINE)),
    more: Math.max(line.matches.length - MATCHES_PER_LINE, 0),
  }));
});

const count = new Intl.NumberFormat("en-US");
const summary = computed(() => {
  const found = outcome.value;
  if (found === null) return "";
  if (found.total === 0) return "No match.";
  const lines = found.lines.length;
  return (
    `${count.format(found.total)} ${found.total === 1 ? "match" : "matches"} on ` +
    `${count.format(lines)} ${lines === 1 ? "line" : "lines"}.`
  );
});

async function run(): Promise<void> {
  if (running.value) return;
  running.value = true;
  problems.value = [];
  outcome.value = null;
  page.value = 0;
  const tried = sample.value;
  const asked = generation;
  try {
    const reply = await api<components["schemas"]["RuleTestOut"]>("/api/rules/test", {
      method: "POST",
      body: { pattern: pattern.value, sample: tried },
    });
    if (asked === generation) outcome.value = outcomeOf(reply.matches, tried);
  } catch (failure) {
    if (asked === generation) problems.value = ruleProblems(failure);
  } finally {
    running.value = false;
  }
}
</script>

<template>
  <section ref="root" aria-labelledby="try-heading">
    <h2 id="try-heading" class="text-sm font-semibold">Try a pattern</h2>
    <form class="mt-3 flex max-w-3xl flex-col gap-3" data-test="try-form" @submit.prevent="run">
      <div class="flex flex-col gap-1">
        <label for="try-pattern" class="text-sm font-medium">Pattern</label>
        <Textarea
          id="try-pattern"
          v-model="pattern"
          spellcheck="false"
          autocomplete="off"
          :rows="3"
          class="w-full font-mono"
        />
      </div>
      <div class="flex flex-col gap-1">
        <label for="try-sample" class="text-sm font-medium">Sample text</label>
        <Textarea
          id="try-sample"
          v-model="sample"
          spellcheck="false"
          autocomplete="off"
          :maxlength="MAX_SAMPLE"
          :rows="6"
          class="w-full font-mono"
        />
        <small class="text-surface-500">
          {{ count.format(sample.length) }} of {{ count.format(MAX_SAMPLE) }} characters
        </small>
      </div>
      <div>
        <Button
          type="submit"
          label="Test"
          icon="pi pi-play"
          size="small"
          :loading="running"
          :disabled="running || pattern === ''"
          data-test="try-run"
        />
      </div>
    </form>

    <Message
      v-if="problems.length > 0"
      severity="error"
      size="small"
      class="mt-3 max-w-3xl"
      role="alert"
      data-test="try-error"
    >
      <p v-for="problem in problems" :key="problem">{{ problem }}</p>
    </Message>

    <div v-if="outcome !== null" class="mt-3 max-w-3xl" data-test="try-result">
      <p class="text-sm font-semibold">{{ summary }}</p>
      <ul
        v-if="shown.length > 0"
        class="mt-2 rounded border border-surface-200 p-2 font-mono text-sm dark:border-surface-700"
      >
        <li v-for="line in shown" :key="line.number" class="flex gap-3">
          <span class="w-12 shrink-0 text-right text-surface-500 select-none">{{
            line.number
          }}</span>
          <div class="min-w-0 grow">
            <span :data-line="line.number" class="break-all whitespace-pre-wrap"
              ><template v-for="(segment, i) in line.segments" :key="i"
                ><span
                  v-if="segment.kind === 'value'"
                  data-span="value"
                  class="rounded-sm bg-primary/20 font-semibold underline"
                  >{{ segment.text }}</span
                ><span
                  v-else-if="segment.kind === 'match'"
                  data-span="match"
                  class="underline decoration-dotted"
                  >{{ segment.text }}</span
                ><template v-else>{{ segment.text }}</template></template
              ></span
            >
            <p v-if="line.more > 0" class="font-sans text-xs text-surface-500">
              and {{ count.format(line.more) }} more matches on this line, not shown
            </p>
          </div>
        </li>
      </ul>
      <div v-if="pageCount > 1" class="mt-2 flex items-center gap-2 text-sm">
        <Button
          label="Previous"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="page === 0"
          data-test="try-previous"
          @click="page--"
        />
        <span>Page {{ page + 1 }} of {{ pageCount }}</span>
        <Button
          label="Next"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="page >= pageCount - 1"
          data-test="try-next"
          @click="page++"
        />
      </div>
    </div>
  </section>
</template>
