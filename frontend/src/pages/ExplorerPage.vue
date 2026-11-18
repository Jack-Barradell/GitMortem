<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Tab from "primevue/tab";
import TabList from "primevue/tablist";
import TabPanel from "primevue/tabpanel";
import TabPanels from "primevue/tabpanels";
import Tabs from "primevue/tabs";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import type { components } from "@/api/schema";
import CodeView from "@/components/explorer/CodeView.vue";
import FileSecretsPanel from "@/components/explorer/FileSecretsPanel.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import CommitBar from "@/components/explorer/CommitBar.vue";
import FileTree from "@/components/explorer/FileTree.vue";
import HistoryDialog from "@/components/explorer/HistoryDialog.vue";
import RefsDialog from "@/components/explorer/RefsDialog.vue";
import SearchPanel from "@/components/explorer/SearchPanel.vue";
import VersionBar from "@/components/explorer/VersionBar.vue";
import { exploredFrom } from "@/exploredFrom";
import { formatBytes, messageFor, shown } from "@/format";
import { EXPLORER_UNAVAILABLE, SUBJECT_KINDS } from "@/labels";
import {
  EXPLORE,
  displayPath,
  readAddress,
  subjectAddress,
  subjectOfFrom,
  useExplorer,
} from "@/stores/explorer";
import {
  staysInTriage,
  subjectKey,
  useTriage,
  type Neighbours,
  type Subject,
} from "@/stores/triage";

type FileShown = components["schemas"]["FileOut.FileShownOut"];

const ANALYST_ONLY = "Only an analyst can open files: a file may hold a value.";

const route = useRoute();
const router = useRouter();
const explorer = useExplorer();
const triage = useTriage();

const repositoryId = ref<number | null>(null);
const badAddress = ref(false);
const sidebar = ref("files");
const revealed = ref<string[]>([]);
const historyOpen = ref(false);
const refsOpen = ref(false);
const nav = ref<Neighbours | null>(null);
const navError = ref("");
const walkError = ref("");
let openedAt = "";
let navAsked = 0;
let walkAsked = 0;
let shownFrom: string | null = null;

function idFrom(param: unknown): number | null {
  const id = Number(param);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

async function readNeighbours(from: string | null): Promise<void> {
  const asked = ++navAsked;
  walkAsked += 1;
  nav.value = null;
  navError.value = "";
  walkError.value = "";
  const at = subjectOfFrom(from);
  if (at === null) return;
  try {
    const found = await triage.neighbours(at);
    if (asked === navAsked) nav.value = found;
  } catch (failure) {
    if (asked === navAsked) navError.value = messageFor(failure);
  }
}

async function walk(to: Subject): Promise<void> {
  const asked = ++walkAsked;
  walkError.value = "";
  try {
    const address = await subjectAddress(to, subjectKey(to));
    if (asked === walkAsked) await router.push(address);
  } catch (failure) {
    if (asked === walkAsked) walkError.value = messageFor(failure);
  }
}

async function chooseVersion(version: number | null): Promise<void> {
  if (explorer.repositoryId === null) return;
  const query: Record<string, string> = version === null ? {} : { version: String(version) };
  await router.push({ name: EXPLORE, params: { id: String(explorer.repositoryId) }, query });
}

watch(
  [() => route.name, () => route.params.id, () => route.query],
  () => {
    if (route.name !== EXPLORE) return;
    walkAsked += 1;
    const id = idFrom(route.params.id);
    const address = readAddress(route.query);
    openedAt = route.path;
    repositoryId.value = id;
    badAddress.value = id === null || address === null;
    if (id === null || address === null) {
      explorer.leave();
      void readNeighbours(null);
      shownFrom = null;
      return;
    }
    if (explorer.version !== address.version) {
      explorer.version = address.version;
      explorer.leave();
    }
    if (address.from !== shownFrom) void readNeighbours(address.from);
    shownFrom = address.from;
    if (address.commit === null) {
      void explorer.findHead(id, address);
      return;
    }
    const { commit, path, line } = address;
    explorer.arrive(id, { commit, path, line }, address.from);
    revealed.value = path.slice(0, -1);
  },
  { immediate: true },
);

onBeforeUnmount(() => {
  navAsked += 1;
  walkAsked += 1;
  explorer.leave();
  const to = router.currentRoute.value;
  if (to.path === openedAt || !staysInTriage(to)) triage.leaveTriage();
});

const backTo = computed(() => {
  const path = exploredFrom.value;
  if (path === null) return null;
  const subject = /^\/(secrets|findings)\/(\d+)/.exec(path);
  if (subject === null) return { path, label: "Back to Secrets" };
  const kind = subject[1] === "secrets" ? "secret" : "finding";
  return { path, label: `Back to ${SUBJECT_KINDS[kind]} ${subject[2]}` };
});

const place = computed(() => explorer.place);
const heading = computed(() => {
  if (explorer.repository !== null) return shown(explorer.repository.name);
  return repositoryId.value === null ? "Repository" : `Repository ${repositoryId.value}`;
});
const shownPath = computed(() => (place.value === null ? "" : displayPath(place.value.path)));
const file = computed((): FileShown | null =>
  explorer.file !== null && !("unavailable" in explorer.file) ? explorer.file : null,
);
const picked = ref<string | null>(null);
watch(file, () => {
  picked.value = null;
});
const fileUnavailable = computed(() =>
  explorer.file !== null && "unavailable" in explorer.file ? explorer.file.unavailable : null,
);
const fileError = computed(() => {
  const failure = explorer.fileFailure;
  if (failure === null) return null;
  return failure.status === 403 ? ANALYST_ONLY : failure.message;
});

function openCommit(commit: string): void {
  void explorer.go(commit, place.value?.path ?? []);
}

function openFile(path: string[], line: number | null = null): void {
  if (place.value !== null) void explorer.go(place.value.commit, path, line);
}

function openLine(line: number): void {
  if (place.value !== null) void explorer.go(place.value.commit, place.value.path, line);
}

function openFound(commit: string, line: number): void {
  if (place.value !== null) void explorer.go(commit, place.value.path, line);
}

function showFolder(path: string[]): void {
  revealed.value = path;
  sidebar.value = "files";
}
</script>

<template>
  <AppPage :title="heading" fluid>
    <template #summary>
      <span class="flex flex-wrap items-center gap-x-3 gap-y-1">
        <RouterLink to="/repositories" class="font-medium gm-link"> Repositories </RouterLink>
        <span v-if="explorer.repository" class="font-mono break-all" data-test="repository-path">{{
          shown(explorer.repository.display_path)
        }}</span>
      </span>
    </template>
    <template #actions>
      <Button
        v-if="backTo"
        as="router-link"
        :to="backTo.path"
        :label="backTo.label"
        icon="pi pi-list"
        size="small"
        severity="secondary"
        data-test="back-to-triage"
      />
      <nav
        v-if="nav && (nav.previous || nav.next)"
        class="flex gap-2"
        aria-label="Previous and next in the list"
      >
        <Button
          label="Previous in list"
          icon="pi pi-angle-double-left"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="!nav.previous"
          data-test="previous"
          @click="nav.previous && walk(nav.previous)"
        />
        <Button
          label="Next in list"
          icon="pi pi-angle-double-right"
          icon-pos="right"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="!nav.next"
          data-test="next"
          @click="nav.next && walk(nav.next)"
        />
      </nav>
      <nav class="flex gap-2" aria-label="Places visited">
        <Button
          label="Back"
          icon="pi pi-arrow-left"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="!explorer.canBack"
          data-test="back"
          @click="explorer.back()"
        />
        <Button
          label="Forward"
          icon="pi pi-arrow-right"
          icon-pos="right"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="!explorer.canForward"
          data-test="forward"
          @click="explorer.forward()"
        />
        <Button
          label="History"
          icon="pi pi-history"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="explorer.repositoryId === null"
          data-test="history"
          @click="historyOpen = true"
        />
        <Button
          label="Branches and tags"
          icon="pi pi-tags"
          size="small"
          severity="secondary"
          variant="outlined"
          :disabled="explorer.repositoryId === null"
          data-test="refs-open"
          @click="refsOpen = true"
        />
      </nav>
    </template>
    <VersionBar
      v-if="explorer.repository?.kind === 'uploaded' && explorer.repositoryId !== null"
      :repository-id="explorer.repositoryId"
      :versions="explorer.repository.versions ?? []"
      :version="explorer.version"
      @choose="chooseVersion"
    />

    <Message v-if="navError" severity="warn" size="small" data-test="nav-error">
      Previous and next could not be read: {{ navError }}
    </Message>
    <Message v-if="walkError" severity="error" size="small" role="alert" data-test="walk-error">
      {{ walkError }}
    </Message>
    <Message
      v-if="explorer.repositoryFailure"
      severity="error"
      size="small"
      role="alert"
      data-test="repository-error"
    >
      {{ explorer.repositoryFailure.message }}
    </Message>
    <Message v-if="badAddress" severity="error" size="small" role="alert" data-test="address-error">
      This address names no commit or file the explorer can open.
      <RouterLink
        :to="repositoryId === null ? '/repositories' : `/repositories/${repositoryId}/explore`"
        class="font-medium underline"
        >Open HEAD</RouterLink
      >
    </Message>
    <Message
      v-if="explorer.headFailure"
      severity="error"
      size="small"
      role="alert"
      data-test="head-error"
    >
      {{ explorer.headFailure.message }}
    </Message>
    <Message
      v-if="explorer.headUnavailable"
      severity="secondary"
      size="small"
      data-test="head-unavailable"
    >
      HEAD cannot be opened: {{ EXPLORER_UNAVAILABLE[explorer.headUnavailable] }}
    </Message>

    <template v-if="place !== null && explorer.repositoryId !== null">
      <PagePanel as="div">
        <CommitBar :commit="explorer.commit" :failure="explorer.commitFailure" @open="openCommit" />
      </PagePanel>
      <div class="grid gap-6 lg:grid-cols-[minmax(16rem,22rem)_minmax(0,1fr)]">
        <PagePanel as="div" class="min-w-0">
          <aside class="min-w-0">
            <Tabs v-model:value="sidebar">
              <TabList>
                <Tab value="files" data-test="sidebar-files">Files</Tab>
                <Tab value="search" data-test="sidebar-search">Search</Tab>
              </TabList>
              <TabPanels class="!px-0">
                <TabPanel value="files">
                  <div class="max-h-[70vh] overflow-auto">
                    <FileTree
                      :repository-id="explorer.repositoryId"
                      :commit="place.commit"
                      :selected="place.path"
                      :reveal="revealed"
                      @open="openFile"
                    />
                  </div>
                </TabPanel>
                <TabPanel value="search">
                  <SearchPanel
                    :repository-id="explorer.repositoryId"
                    :commit="place.commit"
                    @open="openFile"
                    @reveal="showFolder"
                  />
                </TabPanel>
              </TabPanels>
            </Tabs>
          </aside>
        </PagePanel>

        <PagePanel as="div" class="min-w-0">
          <section class="flex min-w-0 flex-col gap-2" aria-label="File" data-test="file">
            <p
              v-if="place.path.length === 0"
              class="text-sm text-surface-500 dark:text-surface-400"
              data-test="no-file"
            >
              Choose a file in the tree, or search for one.
            </p>
            <template v-else>
              <h2 class="font-mono text-sm font-semibold break-all" data-test="file-path">
                {{ shownPath }}
              </h2>
              <Message
                v-if="fileError !== null"
                severity="error"
                size="small"
                role="alert"
                data-test="file-error"
              >
                {{ fileError }}
              </Message>
              <Message
                v-else-if="fileUnavailable"
                severity="secondary"
                size="small"
                data-test="file-unavailable"
              >
                {{ EXPLORER_UNAVAILABLE[fileUnavailable] }}
              </Message>
              <p
                v-else-if="file === null"
                class="text-sm text-surface-500 dark:text-surface-400"
                data-test="file-loading"
              >
                Reading the file…
              </p>
              <p v-else-if="file.binary" class="text-sm" data-test="file-binary">
                A binary file of {{ formatBytes(file.size) }}: there is no text to show.
              </p>
              <p v-else-if="file.too_large" class="text-sm" data-test="file-too-large">
                A file of {{ formatBytes(file.size) }}: over 250 MiB, too large to show.
              </p>
              <template v-else-if="file.text !== null">
                <p
                  v-if="file.marks_truncated"
                  class="text-sm text-surface-500"
                  data-test="marks-truncated"
                >
                  Only the first 10,000 places a known value appears are marked.
                </p>
                <MarksDroppedNote v-if="file.marks_dropped" />
                <div class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_18rem]">
                  <div class="h-[70vh] min-h-96 min-w-0">
                    <CodeView
                      :text="file.text"
                      :path="shownPath"
                      :line="place.line"
                      :marks="file.marks"
                      @pick="(key) => (picked = key)"
                    />
                  </div>
                  <div class="min-w-0 xl:max-h-[70vh] xl:overflow-y-auto">
                    <FileSecretsPanel
                      :subjects="file.subjects"
                      :seen="file.last_change_id"
                      :picked="picked"
                      :unchecked="file.canary_unchecked"
                      :cut="file.subjects_cut"
                      :lines-unchecked="file.lines_unchecked"
                      :dropped="file.marks_dropped"
                      @line="openLine"
                      @open="(found) => openFound(found.commit, found.line)"
                    />
                  </div>
                </div>
              </template>
            </template>
          </section>
        </PagePanel>
      </div>
    </template>

    <HistoryDialog
      v-if="explorer.repositoryId !== null"
      v-model:visible="historyOpen"
      :repository-id="explorer.repositoryId"
      @open="openCommit"
    />
    <RefsDialog
      v-if="explorer.repositoryId !== null"
      v-model:visible="refsOpen"
      :repository-id="explorer.repositoryId"
      @open="openCommit"
    />
  </AppPage>
</template>
