<script setup lang="ts">
import Message from "primevue/message";
import { computed, shallowRef, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { ENTRY_KINDS, EXPLORER_UNAVAILABLE } from "@/labels";
import { joinPath } from "@/stores/explorer";
import { useExplorer } from "@/stores/explorer";

type Schemas = components["schemas"];
type Entry = Schemas["FolderOut.EntryOut"];
type Listing = Schemas["FolderOut.FolderListOut"];

type Folder =
  | { state: "reading" }
  | { state: "listed"; listing: Listing }
  | { state: "unavailable"; reason: Schemas["FolderOut.Unavailable"] }
  | { state: "failed"; message: string };

type Row = { key: string; depth: number } & (
  | { type: "entry"; entry: Entry; path: string[]; at: string }
  | { type: "note"; folder: Exclude<Folder, { state: "listed" }> }
  | { type: "empty" }
  | { type: "truncated"; shown: number; total: number }
);

const OPENS_NOTHING: Record<"link" | "submodule", string> = {
  link: "A symbolic link: the explorer does not follow it.",
  submodule: "A submodule: its files are in another repository.",
};

const props = defineProps<{
  repositoryId: number;
  commit: string;
  selected: string[];
  reveal: string[];
}>();
const explorer = useExplorer();
const emit = defineEmits<{ open: [path: string[]] }>();

const folders = shallowRef(new Map<string, Folder>());
const expanded = shallowRef(new Set<string>());
let generation = 0;

function keep(key: string, folder: Folder): void {
  folders.value = new Map(folders.value).set(key, folder);
}

async function read(path: string[]): Promise<void> {
  const key = joinPath(path);
  const mine = generation;
  keep(key, { state: "reading" });
  const where = key === "" ? "" : `&path=${key}`;
  try {
    const answer = await api<Schemas["FolderOut"]>(
      `/api/repositories/${props.repositoryId}/explore/tree?commit=${props.commit}${where}${explorer.versionQuery("&")}`,
    );
    if (mine !== generation) return;
    keep(
      key,
      "unavailable" in answer
        ? { state: "unavailable", reason: answer.unavailable }
        : { state: "listed", listing: answer },
    );
  } catch (failure) {
    if (mine === generation) keep(key, { state: "failed", message: messageFor(failure) });
  }
}

function open(path: string[]): void {
  const key = joinPath(path);
  if (!expanded.value.has(key)) expanded.value = new Set(expanded.value).add(key);
  const state = folders.value.get(key)?.state;
  if (state !== "listed" && state !== "reading") void read(path);
}

function toggle(path: string[]): void {
  const key = joinPath(path);
  if (!expanded.value.has(key)) {
    open(path);
    return;
  }
  const closed = new Set(expanded.value);
  closed.delete(key);
  expanded.value = closed;
}

function openDownTo(path: string[]): void {
  for (let depth = 1; depth <= path.length; depth += 1) open(path.slice(0, depth));
}

watch(
  [() => props.repositoryId, () => props.commit],
  () => {
    generation += 1;
    folders.value = new Map();
    expanded.value = new Set();
    open([]);
    openDownTo(props.reveal);
  },
  { immediate: true },
);
watch(
  () => props.reveal,
  (path) => openDownTo(path),
);

const selectedKey = computed(() => joinPath(props.selected));

const rows = computed(() => {
  const shown: Row[] = [];
  const seen = new Map<string, number>();
  const unique = (key: string): string => {
    const times = seen.get(key) ?? 0;
    seen.set(key, times + 1);
    return times === 0 ? key : `${key}#${times}`;
  };
  const walk = (path: string[], depth: number): void => {
    const key = joinPath(path);
    const folder = folders.value.get(key);
    if (folder === undefined) return;
    if (folder.state !== "listed") {
      shown.push({ key: unique(`${folder.state}:${key}`), depth, type: "note", folder });
      return;
    }
    const { entries, total, truncated } = folder.listing;
    if (entries.length === 0) shown.push({ key: unique(`empty:${key}`), depth, type: "empty" });
    for (const entry of entries) {
      const child = [...path, entry.raw];
      const childKey = joinPath(child);
      shown.push({ key: unique(childKey), depth, type: "entry", entry, path: child, at: childKey });
      if (entry.kind === "tree" && expanded.value.has(childKey)) walk(child, depth + 1);
    }
    if (truncated) {
      shown.push({
        key: unique(`truncated:${key}`),
        depth,
        type: "truncated",
        shown: entries.length,
        total,
      });
    }
  };
  walk([], 0);
  return shown;
});

const indent = (depth: number) => ({ paddingLeft: `${0.25 + depth}rem` });
const count = (n: number) => n.toLocaleString("en-US");
const rowClass =
  "flex w-full items-center gap-1.5 rounded-none px-1 py-0.5 text-left hover:bg-surface-100 dark:hover:bg-surface-800";
</script>

<template>
  <ul class="font-mono text-sm" aria-label="Files at this commit" data-test="tree">
    <li
      v-for="row in rows"
      :key="row.key"
      :data-path="row.type === 'entry' ? row.at : undefined"
      :data-kind="row.type === 'entry' ? row.entry.kind : undefined"
      :style="indent(row.depth)"
    >
      <template v-if="row.type === 'entry'">
        <button
          v-if="row.entry.kind === 'tree'"
          type="button"
          :class="rowClass"
          :aria-expanded="expanded.has(row.at)"
          @click="toggle(row.path)"
        >
          <i
            :class="['pi', expanded.has(row.at) ? 'pi-chevron-down' : 'pi-chevron-right']"
            class="text-xs text-surface-500"
            aria-hidden="true"
          />
          <i class="pi pi-folder text-surface-500" aria-hidden="true" />
          <span class="break-all">{{ row.entry.name }}</span>
        </button>
        <button
          v-else-if="row.entry.kind === 'blob'"
          type="button"
          :class="[rowClass, 'pl-5', { 'bg-highlight': row.at === selectedKey }]"
          :aria-current="row.at === selectedKey ? 'true' : undefined"
          @click="emit('open', row.path)"
        >
          <i class="pi pi-file text-surface-500" aria-hidden="true" />
          <span class="break-all">{{ row.entry.name }}</span>
        </button>
        <span
          v-else
          class="flex items-center gap-1.5 py-0.5 pr-1 pl-6 text-surface-500"
          :title="OPENS_NOTHING[row.entry.kind]"
        >
          <i :class="['pi', row.entry.kind === 'link' ? 'pi-link' : 'pi-box']" aria-hidden="true" />
          <span class="break-all">{{ row.entry.name }}</span>
          <span class="font-sans text-xs">{{ ENTRY_KINDS[row.entry.kind] }}</span>
        </span>
      </template>
      <p
        v-else-if="row.type === 'empty'"
        class="py-0.5 pl-6 font-sans text-surface-500"
        data-test="folder-empty"
      >
        Nothing here.
      </p>
      <p
        v-else-if="row.type === 'truncated'"
        class="py-0.5 pl-6 font-sans text-surface-500"
        data-test="folder-truncated"
      >
        Showing the first {{ count(row.shown) }} of {{ count(row.total) }} entries.
      </p>
      <p
        v-else-if="row.folder.state === 'reading'"
        class="py-0.5 pl-6 font-sans text-surface-500"
        data-test="folder-loading"
      >
        Reading the folder…
      </p>
      <Message
        v-else-if="row.folder.state === 'unavailable'"
        severity="secondary"
        size="small"
        variant="simple"
        class="py-0.5 pl-6 font-sans"
        data-test="folder-unavailable"
      >
        {{ EXPLORER_UNAVAILABLE[row.folder.reason] }}
      </Message>
      <Message
        v-else
        severity="error"
        size="small"
        variant="simple"
        class="py-0.5 pl-6 font-sans"
        role="alert"
        data-test="folder-error"
      >
        {{ row.folder.message }}
      </Message>
    </li>
  </ul>
</template>
