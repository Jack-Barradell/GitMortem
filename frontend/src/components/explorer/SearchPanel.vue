<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import Tab from "primevue/tab";
import TabList from "primevue/tablist";
import TabPanel from "primevue/tabpanel";
import TabPanels from "primevue/tabpanels";
import Tabs from "primevue/tabs";
import { computed, ref, useId, watch } from "vue";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, shownLine } from "@/format";
import { ENTRY_KINDS, EXPLORER_UNAVAILABLE } from "@/labels";
import { MAX_QUERY_CHARS } from "@/stores/explorer";
import { useExplorer } from "@/stores/explorer";

type Schemas = components["schemas"];
type NameHits = Schemas["NameHitsOut"];
type NameHit = Schemas["NameHitsOut.NameHitOut"];
type Found = Schemas["SearchOut"];
type LineHit = Schemas["SearchOut.LineHitOut"];
type Segment = Schemas["SearchOut.SegmentOut"];

const ANALYST_ONLY = "Only an analyst can search in files: a file may hold a value.";
const OPENS_NOTHING: Record<"link" | "submodule", string> = {
  link: "A symbolic link: the explorer does not follow it.",
  submodule: "A submodule: its files are in another repository.",
};
const count = (n: number) => n.toLocaleString("en-US");
const plural = (n: number, one: string, many: string) => `${count(n)} ${n === 1 ? one : many}`;
const pathText = (path: Segment[]) => path.map((segment) => segment.name).join("/");
const rawPath = (path: Segment[]) => path.map((segment) => segment.raw);

const props = defineProps<{ repositoryId: number; commit: string }>();
const explorer = useExplorer();
const emit = defineEmits<{
  open: [path: string[], line: number | null];
  reveal: [path: string[]];
}>();

const tab = ref("names");
const namesId = useId();
const filesId = useId();
const nameQuery = ref("");
const fileQuery = ref("");
const names = ref<NameHits | null>(null);
const namesError = ref("");
const namesReading = ref(false);
const found = ref<Found | null>(null);
const filesError = ref("");
const filesReading = ref(false);
let generation = 0;
let namesAsked = 0;
let filesAsked = 0;

watch([() => props.repositoryId, () => props.commit], () => {
  generation += 1;
  names.value = null;
  namesError.value = "";
  namesReading.value = false;
  found.value = null;
  filesError.value = "";
  filesReading.value = false;
});

async function findNames(): Promise<void> {
  const query = nameQuery.value;
  if (query === "") return;
  const mine = generation;
  const asked = (namesAsked += 1);
  const current = () => mine === generation && asked === namesAsked;
  names.value = null;
  namesError.value = "";
  namesReading.value = true;
  try {
    const answer = await api<NameHits>(`/api/repositories/${props.repositoryId}/explore/names`, {
      method: "POST",
      body: { commit: props.commit, query, ...explorer.versionField() },
    });
    if (current()) names.value = answer;
  } catch (failure) {
    if (current()) namesError.value = messageFor(failure);
  } finally {
    if (current()) namesReading.value = false;
  }
}

async function findInFiles(): Promise<void> {
  const query = fileQuery.value;
  if (query === "") return;
  const mine = generation;
  const asked = (filesAsked += 1);
  const current = () => mine === generation && asked === filesAsked;
  found.value = null;
  filesError.value = "";
  filesReading.value = true;
  try {
    const answer = await api<Found>(`/api/repositories/${props.repositoryId}/explore/search`, {
      method: "POST",
      body: { commit: props.commit, query, folder: [], ...explorer.versionField() },
    });
    if (current()) found.value = answer;
  } catch (failure) {
    if (!current()) return;
    filesError.value =
      failure instanceof ApiError && failure.status === 403 ? ANALYST_ONLY : messageFor(failure);
  } finally {
    if (current()) filesReading.value = false;
  }
}

const nameList = computed(() =>
  names.value !== null && "hits" in names.value ? names.value : null,
);
const namesUnavailable = computed(() =>
  names.value !== null && "unavailable" in names.value ? names.value.unavailable : null,
);
const fileList = computed(() =>
  found.value !== null && "hits" in found.value ? found.value : null,
);
const filesUnavailable = computed(() =>
  found.value !== null && "unavailable" in found.value ? found.value.unavailable : null,
);

const groups = computed(() => {
  const byFile: { path: Segment[]; hits: LineHit[] }[] = [];
  let last = "";
  for (const hit of fileList.value?.hits ?? []) {
    const key = rawPath(hit.path).join(".");
    const group = byFile.at(-1);
    if (group !== undefined && key === last) group.hits.push(hit);
    else byFile.push({ path: hit.path, hits: [hit] });
    last = key;
  }
  return byFile;
});

function chooseName(hit: NameHit): void {
  if (hit.kind === "tree") emit("reveal", rawPath(hit.path));
  else emit("open", rawPath(hit.path), null);
}

const hitClass =
  "flex w-full items-baseline gap-1.5 px-1 py-0.5 text-left font-mono text-sm hover:bg-surface-100 dark:hover:bg-surface-800";
</script>

<template>
  <Tabs v-model:value="tab">
    <TabList>
      <Tab value="names">By name</Tab>
      <Tab value="files">In files</Tab>
    </TabList>
    <TabPanels class="!px-0">
      <TabPanel value="names">
        <form class="flex items-end gap-2" role="search" @submit.prevent="findNames">
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <label :for="namesId" class="text-sm">A file or folder name holding</label>
            <InputText
              :id="namesId"
              v-model="nameQuery"
              type="text"
              size="small"
              autocomplete="off"
              spellcheck="false"
              :maxlength="MAX_QUERY_CHARS"
              data-test="names-query"
            />
          </div>
          <Button
            type="submit"
            label="Find"
            size="small"
            :loading="namesReading"
            :disabled="nameQuery === ''"
          />
        </form>
        <Message
          v-if="namesError"
          severity="error"
          size="small"
          class="mt-2"
          role="alert"
          data-test="names-error"
        >
          {{ namesError }}
        </Message>
        <Message
          v-else-if="namesUnavailable"
          severity="secondary"
          size="small"
          class="mt-2"
          data-test="names-unavailable"
        >
          {{ EXPLORER_UNAVAILABLE[namesUnavailable] }}
        </Message>
        <template v-else-if="nameList">
          <p class="mt-2 text-sm" data-test="names-summary">
            {{
              nameList.hits.length === 0
                ? "Nothing found."
                : `${count(nameList.hits.length)} found.`
            }}
          </p>
          <p v-if="nameList.cut" class="mt-1 text-sm text-surface-500" data-test="names-cut">
            The search stopped at a bound (500 matches, or 1,000,000 entries looked at): there may
            be more.
          </p>
          <ul class="mt-2">
            <li v-for="(hit, index) in nameList.hits" :key="index">
              <button
                v-if="hit.kind === 'blob' || hit.kind === 'tree'"
                type="button"
                :class="hitClass"
                data-test="name-hit"
                @click="chooseName(hit)"
              >
                <i
                  :class="['pi', hit.kind === 'tree' ? 'pi-folder' : 'pi-file']"
                  class="text-surface-500"
                  aria-hidden="true"
                />
                <span class="break-all">{{ pathText(hit.path) }}</span>
              </button>
              <span
                v-else
                class="flex items-center gap-1.5 px-1 py-0.5 font-mono text-sm break-all text-surface-500"
                :title="OPENS_NOTHING[hit.kind]"
                data-test="name-hit"
              >
                <i :class="['pi', hit.kind === 'link' ? 'pi-link' : 'pi-box']" aria-hidden="true" />
                <span>{{ pathText(hit.path) }}</span>
                <span class="font-sans text-xs">{{ ENTRY_KINDS[hit.kind] }}</span>
              </span>
            </li>
          </ul>
        </template>
      </TabPanel>

      <TabPanel value="files">
        <form class="flex items-end gap-2" role="search" @submit.prevent="findInFiles">
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <label :for="filesId" class="text-sm">Text in the files</label>
            <InputText
              :id="filesId"
              v-model="fileQuery"
              type="text"
              size="small"
              autocomplete="off"
              spellcheck="false"
              :maxlength="MAX_QUERY_CHARS"
              data-test="files-query"
            />
          </div>
          <Button
            type="submit"
            label="Search"
            size="small"
            :loading="filesReading"
            :disabled="fileQuery === ''"
          />
        </form>
        <Message
          v-if="filesError"
          severity="error"
          size="small"
          class="mt-2"
          role="alert"
          data-test="files-error"
        >
          {{ filesError }}
        </Message>
        <Message
          v-else-if="filesUnavailable"
          severity="secondary"
          size="small"
          class="mt-2"
          data-test="files-unavailable"
        >
          {{ EXPLORER_UNAVAILABLE[filesUnavailable] }}
        </Message>
        <template v-else-if="fileList">
          <p class="mt-2 text-sm" data-test="files-summary">
            {{
              fileList.hits.length === 0
                ? "Nothing found."
                : `${plural(fileList.hits.length, "line", "lines")} in ${plural(fileList.files, "file", "files")}.`
            }}
          </p>
          <p
            v-if="fileList.skipped_large > 0"
            class="mt-1 text-sm text-surface-500"
            data-test="skipped-large"
          >
            {{ plural(fileList.skipped_large, "file", "files") }} over 250 MiB
            {{ fileList.skipped_large === 1 ? "was" : "were" }} not searched.
          </p>
          <p
            v-if="fileList.skipped_binary > 0"
            class="mt-1 text-sm text-surface-500"
            data-test="skipped-binary"
          >
            {{ plural(fileList.skipped_binary, "binary file", "binary files") }}
            {{ fileList.skipped_binary === 1 ? "was" : "were" }} passed over.
          </p>
          <p v-if="fileList.cut" class="mt-1 text-sm text-surface-500" data-test="files-cut">
            The search stopped at a bound (1,000 lines, 200 files, 1 GiB read, or 20 s): there may
            be more.
          </p>
          <section v-for="(group, index) in groups" :key="index" class="mt-2">
            <h3 class="font-mono text-sm font-semibold break-all" data-test="hit-file">
              {{ pathText(group.path) }}
            </h3>
            <ul>
              <li v-for="(hit, at) in group.hits" :key="at">
                <button
                  type="button"
                  :class="hitClass"
                  data-test="file-hit"
                  @click="emit('open', rawPath(group.path), hit.line)"
                >
                  <span class="w-10 shrink-0 text-right text-surface-500" data-test="hit-line">{{
                    hit.line
                  }}</span>
                  <span class="min-w-0 break-words whitespace-pre-wrap" data-test="hit-text"
                    >{{ shownLine(hit.text.slice(0, hit.start))
                    }}<mark>{{ shownLine(hit.text.slice(hit.start, hit.end)) }}</mark
                    >{{ shownLine(hit.text.slice(hit.end))
                    }}<span v-if="hit.cut" class="text-surface-500" title="The line goes on"
                      >…</span
                    ></span
                  >
                </button>
              </li>
            </ul>
          </section>
        </template>
      </TabPanel>
    </TabPanels>
  </Tabs>
</template>
