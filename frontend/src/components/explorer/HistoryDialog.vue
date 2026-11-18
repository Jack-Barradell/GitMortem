<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import { computed, ref, useId, watch } from "vue";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import MarkedSegments from "@/components/MarkedSegments.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import { formatTime, messageFor, shown } from "@/format";
import { EXPLORER_UNAVAILABLE } from "@/labels";
import { MAX_QUERY_CHARS } from "@/stores/explorer";
import { useExplorer } from "@/stores/explorer";

type Schemas = components["schemas"];
type Page = Schemas["ExplorerHistoryOut"];
type Row = Schemas["ExplorerHistoryOut.HistoryRowOut"];

const ANALYST_ONLY = "Only an analyst can search the history: a commit message may hold a value.";
const SHORT = 12;
const count = (n: number) => n.toLocaleString("en-US");
const commits = (n: number) => `${count(n)} ${n === 1 ? "commit" : "commits"}`;

const props = defineProps<{ repositoryId: number; visible: boolean }>();
const explorer = useExplorer();
const emit = defineEmits<{ "update:visible": [visible: boolean]; open: [commit: string] }>();

const queryId = useId();
const typed = ref("");
const applied = ref<string | null>(null);
const rows = ref<Row[]>([]);
const nextSkip = ref<number | null>(null);
const scanned = ref(0);
const unread = ref(0);
const cut = ref(false);
const marksDropped = ref(false);
const reading = ref(false);
const read = ref(false);
const answered = ref(false);
const error = ref("");
const unavailable = ref<Schemas["ExplorerHistoryOut.Unavailable"] | null>(null);
let generation = 0;

async function readPage(skip: number, query: string | null, more: boolean): Promise<void> {
  const mine = (generation += 1);
  reading.value = true;
  error.value = "";
  unavailable.value = null;
  if (!more) {
    answered.value = false;
    applied.value = query;
    rows.value = [];
    nextSkip.value = null;
    scanned.value = 0;
    unread.value = 0;
    cut.value = false;
    marksDropped.value = false;
  }
  try {
    const page = await api<Page>(`/api/repositories/${props.repositoryId}/history`, {
      method: "POST",
      body: { skip, query, ...explorer.versionField() },
    });
    if (mine !== generation) return;
    read.value = true;
    if ("unavailable" in page) {
      unavailable.value = page.unavailable;
      nextSkip.value = null;
      return;
    }
    answered.value = true;
    rows.value = [...rows.value, ...page.rows];
    nextSkip.value = page.next_skip;
    scanned.value += page.scanned;
    unread.value += page.unread;
    cut.value = page.cut;
    if (page.marks_dropped) marksDropped.value = true;
  } catch (failure) {
    if (mine !== generation) return;
    error.value =
      failure instanceof ApiError && failure.status === 403 ? ANALYST_ONLY : messageFor(failure);
  } finally {
    if (mine === generation) reading.value = false;
  }
}

watch(
  () => props.visible,
  (open) => {
    if (open && !read.value && !reading.value) void readPage(0, null, false);
  },
  { immediate: true },
);
watch(
  () => [props.repositoryId, explorer.version] as const,
  () => {
    generation += 1;
    read.value = false;
    reading.value = false;
    if (props.visible) void readPage(0, null, false);
  },
);

function search(): void {
  void readPage(0, typed.value === "" ? null : typed.value, false);
}

function showAll(): void {
  typed.value = "";
  void readPage(0, null, false);
}

function more(): void {
  if (nextSkip.value !== null) void readPage(nextSkip.value, applied.value, true);
}

function choose(row: Row): void {
  emit("open", row.id);
  emit("update:visible", false);
}

const status = computed(() =>
  applied.value === null || !answered.value
    ? null
    : `Searched ${commits(scanned.value)}: ${count(rows.value.length)} found.`,
);
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    header="History"
    class="w-full max-w-4xl"
    data-test="history-dialog"
    @update:visible="emit('update:visible', $event)"
  >
    <p class="text-sm text-surface-500">
      Newest first. A value GitMortem knows is highlighted in each subject. A search reads messages
      and authors, case-sensitive.
    </p>
    <form class="mt-2 flex flex-wrap items-center gap-2" role="search" @submit.prevent="search">
      <label :for="queryId" class="text-sm">Search the history</label>
      <InputText
        :id="queryId"
        v-model="typed"
        type="text"
        size="small"
        class="min-w-0 flex-1"
        autocomplete="off"
        spellcheck="false"
        :maxlength="MAX_QUERY_CHARS"
        data-test="history-query"
      />
      <Button type="submit" label="Search" size="small" data-test="history-search" />
      <Button
        v-if="applied !== null"
        type="button"
        label="Show all"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="history-clear"
        @click="showAll"
      />
    </form>

    <Message
      v-if="error"
      severity="error"
      size="small"
      class="mt-2"
      role="alert"
      data-test="history-error"
    >
      {{ error }}
    </Message>
    <Message
      v-if="unavailable"
      severity="secondary"
      size="small"
      class="mt-2"
      data-test="history-unavailable"
    >
      {{ EXPLORER_UNAVAILABLE[unavailable] }}
    </Message>
    <p v-if="status" class="mt-2 text-sm" data-test="history-status">{{ status }}</p>
    <p v-if="unread > 0" class="mt-1 text-sm text-surface-500" data-test="history-unread">
      {{ commits(unread) }} over 1 MiB could not be searched.
    </p>
    <p v-if="cut" class="mt-1 text-sm text-surface-500" data-test="history-cut">
      Reading stopped at a bound (50,000 commits or 20 s a page){{
        nextSkip !== null ? ": More carries on from there." : "."
      }}
    </p>

    <MarksDroppedNote v-if="marksDropped" class="mt-1" />

    <ul class="mt-3 flex flex-col">
      <li v-for="(row, index) in rows" :key="index">
        <button
          type="button"
          class="flex w-full flex-wrap items-baseline gap-x-3 px-2 py-1 text-left text-sm hover:bg-surface-100 dark:hover:bg-surface-800"
          data-test="history-row"
          @click="choose(row)"
        >
          <span class="font-mono" :title="row.id" data-test="row-id">{{
            row.id.slice(0, SHORT)
          }}</span>
          <span
            v-if="row.holds_findings"
            class="text-amber-600 dark:text-amber-400"
            title="Holds a finding"
            data-test="holds-findings"
            ><i class="pi pi-key" aria-hidden="true" /><span class="sr-only"
              >Holds a finding</span
            ></span
          >
          <span v-if="row.too_large" class="text-surface-500">Over 1 MiB: not read</span>
          <span v-else class="min-w-0 flex-1 break-words"
            ><MarkedSegments :segments="row.subject.segments" /><span
              v-if="row.subject_cut"
              class="text-surface-500"
              title="The subject goes on"
              >…</span
            ></span
          >
          <span class="text-surface-500">{{ shown(row.author.name) }}</span>
          <time v-if="row.author.at" :datetime="row.author.at" class="text-surface-500">{{
            formatTime(row.author.at)
          }}</time>
        </button>
      </li>
    </ul>
    <p v-if="reading" class="mt-2 text-sm text-surface-500">Reading the history…</p>
    <p
      v-else-if="read && rows.length === 0 && !error && !unavailable"
      class="mt-2 text-sm text-surface-500"
    >
      No commits.
    </p>
    <Button
      v-if="nextSkip !== null && !reading"
      label="More"
      size="small"
      severity="secondary"
      variant="outlined"
      class="mt-2"
      data-test="history-more"
      @click="more"
    />
  </Dialog>
</template>
