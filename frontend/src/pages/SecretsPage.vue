<script setup lang="ts">
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent, type DataTableSortEvent } from "primevue/datatable";
import Dialog from "primevue/dialog";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import Tag from "primevue/tag";
import Textarea from "primevue/textarea";
import Toast from "primevue/toast";
import { useConfirm } from "primevue/useconfirm";
import { useToast } from "primevue/usetoast";
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  isNavigationFailure,
  NavigationFailureType,
  onBeforeRouteLeave,
  useRoute,
  useRouter,
} from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { copyText } from "@/clipboard";
import FirstRootPanel from "@/components/FirstRootPanel.vue";
import ManualCopyDialog from "@/components/ManualCopyDialog.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import SecretsFilters from "@/components/SecretsFilters.vue";
import StatusBand from "@/components/StatusBand.vue";
import StatusSelect from "@/components/StatusSelect.vue";
import ExportDialog from "@/components/ExportDialog.vue";
import SkippedDialog from "@/components/SkippedDialog.vue";
import { formatTime, messageFor, shown, statusReport } from "@/format";
import {
  NO_LONGER_REPORTED,
  REPORTED_LIVE,
  SECRET_STATUSES,
  STATUS_OPTIONS,
  VALUE_MODES,
  VIEWS,
} from "@/labels";
import { MAX_NOTE_CHARS } from "@/notes";
import { useSay } from "@/notify";
import { reasonOf } from "@/problems";
import { askAcross, SpanDeclined, withAcross } from "@/spans";
import { placeAddress } from "@/stores/explorer";
import {
  FILTER_QUIET_MS,
  PAGE_SIZES,
  staysInTriage,
  subjectKey,
  listedPath,
  useTriage,
  type ListSort,
  type Row,
  type SecretStatus,
  type Subject,
  type ValueSearch,
  type View,
} from "@/stores/triage";

type Schemas = components["schemas"];
type Root = Schemas["ScanRootOut"];
type Facets = Schemas["FacetsOut"];
type Skipped = Schemas["StatusOut.SkippedOut"];
type Value = Schemas["ValuesOut.ValueOut"];

const MIN_PARTIAL = 3;
const MAX_SEARCH_CHARS = 4096;
const SORTABLE = new Set<string>([
  "date",
  "repo",
  "org",
  "path",
  "type",
  "tool",
  "status",
  "findings",
  "repos",
]);

const triage = useTriage();
const route = useRoute();
const router = useRouter();
const say = useSay();
const toast = useToast();
const confirm = useConfirm();

const viewOptions = Object.entries(VIEWS).map(([value, label]) => ({ value, label }));
const modeOptions = Object.entries(VALUE_MODES).map(([value, label]) => ({ value, label }));

const repoOf = (row: Row): string =>
  row.org === null ? shown(row.repo_name) : `${shown(row.org)}/${shown(row.repo_name)}`;
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

const roots = ref<Root[] | null>(null);

async function loadRoots(): Promise<void> {
  try {
    roots.value = await api<Root[]>("/api/scan-roots");
  } catch (failure) {
    say("error", "Scan roots not loaded", messageFor(failure));
  }
}

const facets = ref<Facets | null>(null);

async function loadFacets(): Promise<void> {
  try {
    facets.value = await api<Facets>("/api/triage/facets");
  } catch (failure) {
    say("error", "Filters not loaded", messageFor(failure));
  }
}

const listError = ref("");

async function refresh(summary = true): Promise<void> {
  if (route.path !== "/secrets") return;
  const written = await router.replace({ query: triage.toRoute() });
  const overtaken = NavigationFailureType.cancelled | NavigationFailureType.aborted;
  if (isNavigationFailure(written, overtaken) || route.path !== "/secrets") return;
  try {
    if (await triage.load(summary)) listError.value = "";
  } catch (failure) {
    listError.value = messageFor(failure);
  }
}

let quiet: ReturnType<typeof setTimeout> | null = null;

function refreshSoon(): void {
  if (quiet !== null) clearTimeout(quiet);
  quiet = setTimeout(() => {
    quiet = null;
    void refresh();
  }, FILTER_QUIET_MS);
}

watch(
  () => route.query,
  (query) => {
    if (route.path === "/secrets" && triage.fromRoute(query)) void refresh();
  },
);

function changeView(view: View): void {
  triage.setView(view);
  void refresh();
}

function onPage(event: DataTablePageEvent): void {
  if (event.rows !== triage.query.perPage) triage.setPerPage(event.rows);
  else triage.setPage(event.page + 1);
  void refresh(false);
}

function onSort(event: DataTableSortEvent): void {
  const field = typeof event.sortField === "string" ? event.sortField : "";
  const valueSort = field === "value" && valueSortable.value;
  if (!SORTABLE.has(field) && !valueSort) return;
  triage.setSort(field as ListSort, event.sortOrder === 1 ? "asc" : "desc");
  void refresh(false);
}

const valueSortable = computed(() => triage.query.view === "unique");

const searching = computed(() => triage.query.filters.text !== "" || triage.valueSearch !== null);
const anyFilter = computed(
  () => searching.value || Object.keys(triage.toRoute()).some((key) => key !== "per"),
);

const textDraft = ref(triage.query.filters.text);

function search(): void {
  triage.setFilters({ text: textDraft.value });
  void refresh();
}

const valueDraft = ref(triage.valueSearch?.text ?? "");
const valueMode = ref<ValueSearch["mode"]>(triage.valueSearch?.mode ?? "exact");
const valueError = ref("");
const VALUE_INPUT = {
  name: "value-search",
  autocomplete: "off",
  spellcheck: "false",
  autocapitalize: "off",
  autocorrect: "off",
  "data-1p-ignore": "true",
  "data-lpignore": "true",
  "data-bwignore": "true",
  "data-form-type": "other",
} as const;

function onValueEnter(event: KeyboardEvent): void {
  if (!event.isComposing) searchValues();
}

function searchValues(): void {
  const chars = [...valueDraft.value].length;
  if (chars === 0) valueError.value = "Type a value to search for.";
  else if (valueMode.value === "partial" && chars < MIN_PARTIAL) {
    valueError.value = `A partial search needs at least ${MIN_PARTIAL} characters.`;
  } else if (chars > MAX_SEARCH_CHARS) {
    valueError.value = `A value search takes at most ${MAX_SEARCH_CHARS} characters.`;
  } else {
    valueError.value = "";
    triage.setValueSearch({ text: valueDraft.value, mode: valueMode.value });
    void refresh();
  }
}

function clearValueSearch(): void {
  valueDraft.value = "";
  valueError.value = "";
  triage.setValueSearch(null);
  void refresh();
}

const actionError = ref("");
const canSelectMatching = computed(
  () => !triage.matchingAll && triage.pageSelected && triage.totalUnique > triage.selection.size,
);

function isSelected(row: Row): boolean {
  return triage.matchingAll || triage.selection.has(subjectKey(row));
}

const statusOpen = ref(false);
const statusChoice = ref<SecretStatus | null>(null);
const statusNote = ref("");
const skipped = ref<Skipped[]>([]);
const skippedTotal = ref(0);

function openStatus(): void {
  statusOpen.value = true;
}

function applyStatus(): void {
  const status = statusChoice.value;
  if (status === null) return;
  const note = statusNote.value;
  statusOpen.value = false;
  const count = triage.selectedCount;
  if (count === 1) {
    void changeStatus(status, note);
    return;
  }
  confirm.require({
    header: `Set ${count} to ${SECRET_STATUSES[status]}?`,
    message:
      "A status applies to each secret everywhere it was found, in every repository and commit.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Set status",
    rejectLabel: "Cancel",
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: () => void changeStatus(status, note, true),
  });
}

async function changeStatus(status: SecretStatus, note: string, confirmed = false): Promise<void> {
  actionError.value = "";
  const asked = triage.listGeneration();
  let result: Schemas["StatusOut"];
  try {
    ({ result } = await withAcross(
      (across) => triage.setStatus(status, note, across),
      (repositories) => (confirmed ? Promise.resolve(true) : askAcross(confirm, repositories)),
    ));
  } catch (failure) {
    if (failure instanceof SpanDeclined) return;
    actionError.value = messageFor(failure);
    if (reasonOf(failure) === "reported_moved" && triage.endMatchingAll(asked)) await refresh();
    return;
  }
  const report = statusReport(result, note);
  say(report.severity, "Status set", report.detail);
  statusChoice.value = null;
  if (result.changed > 0) statusNote.value = "";
  skipped.value = result.skipped;
  skippedTotal.value = result.skipped_total;
  await refresh();
}

const changing = ref<string | null>(null);
interface Undoable {
  subject: Subject;
  previous: SecretStatus;
  set: SecretStatus;
  seen: number;
  batch: string;
  across: number | null;
}
const undoable = ref<Undoable | null>(null);

function rowLabel(row: Row): string {
  return `Status of ${repoOf(row)} ${shown(row.display_path)}`;
}

async function changeRowStatus(
  subject: Subject,
  previous: SecretStatus,
  status: SecretStatus,
  repos: number,
  undoing: Undoable | null = null,
): Promise<void> {
  if (status === previous || changing.value !== null) return;
  actionError.value = "";
  toast.removeGroup("status");
  undoable.value = null;
  changing.value = subjectKey(subject);
  const seen = undoing?.seen ?? triage.lastChangeId;
  try {
    let first = undoing?.across ?? null;
    if (undoing === null && repos > 1) {
      if (!(await askAcross(confirm, repos))) return;
      first = repos;
    }
    let result: Schemas["StatusOut"];
    let across: number | null;
    try {
      ({ result, across } = await withAcross(
        (confirmed) =>
          triage.setSubjectStatus(
            subject,
            status,
            undoing === null ? undefined : { seen, ownBatches: [undoing.batch] },
            confirmed,
          ),
        (repositories) => askAcross(confirm, repositories),
        first,
      ));
    } catch (failure) {
      if (failure instanceof SpanDeclined) return;
      actionError.value = messageFor(failure);
      return;
    }
    skipped.value = result.skipped;
    skippedTotal.value = result.skipped_total;
    if (result.changed === 0 && result.skipped_total === 0) {
      say("warn", "Already that status", "Someone may have set it since the list was read.");
    }
    await refresh();
    if (result.changed === 0 || route.path !== "/secrets") return;
    if (undoing !== null) {
      say("success", `Set back to ${SECRET_STATUSES[status]}`);
      return;
    }
    undoable.value = { subject, previous, set: status, seen, batch: result.batch_id, across };
    toast.add({
      group: "status",
      severity: "success",
      summary: `Set to ${SECRET_STATUSES[status]}`,
      life: 10000,
    });
  } finally {
    changing.value = null;
  }
}

function onRowStatus(row: Row, status: SecretStatus): void {
  void changeRowStatus(
    { kind: row.kind, id: row.id },
    row.status as SecretStatus,
    status,
    row.repos,
  );
}

function undo(): void {
  const last = undoable.value;
  if (last === null) return;
  void changeRowStatus(last.subject, last.set, last.previous, 1, last);
}

const exportOpen = ref(false);
const manualCopy = ref<string | null>(null);
const manualCount = ref(0);

async function fetchValues(): Promise<Value[] | null> {
  actionError.value = "";
  try {
    const answer = await api<Schemas["ValuesOut"]>("/api/triage/values", {
      method: "POST",
      body: triage.valuesTarget(),
    });
    return answer.items;
  } catch (failure) {
    actionError.value = messageFor(failure);
    return null;
  }
}

async function copy(): Promise<void> {
  const items = await fetchValues();
  if (items === null) return;
  const text = items.map((item) => item.value).join("\n");
  if ((await copyText(text)) === "copied") {
    say("success", `Copied ${plural(items.length, "value", "values")}`);
  } else {
    manualCount.value = items.length;
    manualCopy.value = text;
  }
}

async function exploreRow(row: Row): Promise<void> {
  actionError.value = "";
  try {
    await router.push(await placeAddress(row.anchor_finding_id, subjectKey(row)));
  } catch (failure) {
    actionError.value = messageFor(failure);
  }
}

async function copyRow(row: Row): Promise<void> {
  if ((await copyText(row.value)) === "copied") {
    say("success", "Copied the value");
  } else {
    manualCount.value = 1;
    manualCopy.value = row.value;
  }
}

function closeManualCopy(): void {
  manualCopy.value = null;
}

function closeSkipped(): void {
  skipped.value = [];
  skippedTotal.value = 0;
}

let leavingFor: string | null = null;
onBeforeRouteLeave((to) => {
  leavingFor = to.path;
});
const stopWatchingNavigation = router.afterEach((_to, _from, failure) => {
  if (failure) leavingFor = null;
});
onBeforeUnmount(() => {
  if (quiet !== null) clearTimeout(quiet);
  stopWatchingNavigation();
  textDraft.value = "";
  valueDraft.value = "";
  closeManualCopy();
  if (leavingFor === null || !staysInTriage({ path: leavingFor })) triage.leaveTriage();
});

onMounted(async () => {
  triage.fromRoute(route.query);
  await Promise.all([loadRoots(), loadFacets(), refresh()]);
});
</script>

<template>
  <AppPage title="Secrets" fluid>
    <template #summary>
      <span data-test="totals"
        >{{ plural(triage.totalFindings, "finding", "findings") }},
        {{ triage.totalUnique }} unique</span
      >
    </template>
    <template #actions>
      <div class="flex items-center gap-2"></div>
      <Button
        icon="pi pi-refresh"
        aria-label="Reload"
        title="Read the list again"
        severity="secondary"
        variant="text"
        rounded
        data-test="reload"
        @click="refresh()"
      />
      <Button
        label="Export"
        icon="pi pi-download"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="export"
        @click="exportOpen = true"
      />
    </template>

    <FirstRootPanel v-if="roots !== null && roots.length === 0" />

    <PagePanel>
      <StatusBand @change="refresh()" />
    </PagePanel>

    <PagePanel flush>
      <div
        class="flex flex-col gap-4 border-b border-surface-200 px-4 py-4 sm:px-6 dark:border-surface-700"
      >
        <div class="flex flex-wrap items-center gap-3">
          <SelectButton
            :model-value="triage.query.view"
            :options="viewOptions"
            option-label="label"
            option-value="value"
            :allow-empty="false"
            aria-label="View"
            size="small"
            data-test="view"
            @update:model-value="changeView"
          />
          <form
            class="flex min-w-0 flex-1 items-center gap-2"
            data-test="search"
            @submit.prevent="search"
          >
            <label for="list-search" class="sr-only">Search</label>
            <InputText
              id="list-search"
              v-model="textDraft"
              maxlength="256"
              autocomplete="off"
              spellcheck="false"
              size="small"
              placeholder="Search paths, commit messages, types, authors or repositories"
              class="min-w-0 flex-1 sm:max-w-lg"
            />
            <Button type="submit" label="Search" size="small" severity="secondary" />
          </form>
        </div>

        <SecretsFilters :facets="facets" @change="refreshSoon" />

        <div class="flex flex-col gap-1" role="search" data-test="value-search">
          <label
            for="value-search"
            class="text-xs font-semibold text-surface-600 dark:text-surface-300"
            >Value search</label
          >
          <div class="flex flex-wrap items-center gap-2">
            <div class="flex w-72 items-center gap-1">
              <InputText
                id="value-search"
                v-model="valueDraft"
                type="text"
                v-bind="VALUE_INPUT"
                size="small"
                class="min-w-0 flex-1 font-mono"
                @keydown.enter.prevent="onValueEnter"
              />
            </div>
            <SelectButton
              v-model="valueMode"
              :options="modeOptions"
              option-label="label"
              option-value="value"
              :allow-empty="false"
              aria-label="Match"
              size="small"
              data-test="value-mode"
            />
            <Button
              label="Search values"
              size="small"
              severity="secondary"
              data-test="search-values"
              @click="searchValues"
            />
            <Button
              v-if="triage.valueSearch"
              label="Clear"
              size="small"
              severity="secondary"
              variant="text"
              data-test="clear-value-search"
              @click="clearValueSearch"
            />
          </div>
          <Message
            v-if="valueError"
            severity="error"
            size="small"
            role="alert"
            data-test="value-search-error"
          >
            {{ valueError }}
          </Message>
        </div>
      </div>

      <div
        v-if="triage.selectedCount > 0"
        role="toolbar"
        aria-label="Selected secrets"
        class="fixed inset-x-4 top-3 z-40 mx-auto flex w-fit max-w-[calc(100vw-2rem)] flex-wrap items-center gap-2 rounded-lg border border-primary-200 bg-primary-50 px-4 py-2 shadow-lg lg:left-64 dark:border-primary-800 dark:bg-surface-800"
        data-test="selection"
      >
        <span v-if="triage.matchingAll" class="text-sm font-medium">
          All {{ triage.totalUnique }} matching are selected.
        </span>
        <span v-else class="text-sm font-medium">{{ triage.selection.size }} selected</span>
        <Button
          v-if="canSelectMatching"
          :label="`Select all ${triage.totalUnique} matching`"
          size="small"
          variant="text"
          data-test="select-matching"
          @click="triage.selectAllMatching()"
        />
        <Button
          label="Clear selection"
          size="small"
          severity="secondary"
          variant="text"
          data-test="clear-selection"
          @click="triage.clearSelection()"
        />
        <span class="flex flex-wrap items-center gap-2">
          <Button label="Set status" size="small" data-test="set-status" @click="openStatus" />
          <Button
            label="Copy"
            icon="pi pi-copy"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="copy"
            @click="copy"
          />
        </span>
      </div>
      <div
        v-if="actionError || listError || triage.canaryUnchecked"
        class="flex flex-col gap-2 px-4 pt-4 sm:px-6"
      >
        <Message
          v-if="actionError"
          severity="error"
          size="small"
          role="alert"
          data-test="action-error"
        >
          {{ actionError }}
        </Message>
        <Message v-if="listError" severity="error" size="small" role="alert" data-test="list-error">
          {{ listError }}
        </Message>
        <Message
          v-if="triage.canaryUnchecked && !listError"
          severity="warn"
          size="small"
          data-test="canary-unchecked"
        >
          These rows were not checked for canary words: they hold too many findings, or GitMortem
          was busy. Reload, show fewer rows a page, or filter by Possible canaries only.
        </Message>
      </div>

      <DataTable
        :value="triage.rows"
        data-key="anchor_finding_id"
        lazy
        paginator
        striped-rows
        :rows="triage.perPage"
        :rows-per-page-options="[...PAGE_SIZES]"
        :first="(triage.page - 1) * triage.perPage"
        :total-records="triage.totalRows"
        :loading="triage.loading"
        :sort-field="triage.query.sort"
        :sort-order="triage.query.order === 'asc' ? 1 : -1"
        size="small"
        scrollable
        @page="onPage"
        @sort="onSort"
      >
        <template #empty>
          <p class="py-6 text-center text-surface-500 dark:text-surface-400">
            <template v-if="anyFilter">Nothing matches these filters.</template>
            <template v-else>
              Nothing has been found yet. Findings are listed here once a scan has run.
            </template>
          </p>
        </template>
        <Column class="w-10">
          <template #header>
            <Checkbox
              binary
              :model-value="triage.matchingAll || triage.pageSelected"
              :disabled="triage.matchingAll || triage.rows.length === 0"
              aria-label="Select this page"
              data-test="select-page"
              @update:model-value="triage.selectPage($event)"
            />
          </template>
          <template #body="{ data }">
            <Checkbox
              binary
              :model-value="isSelected(data)"
              :disabled="triage.matchingAll"
              :aria-label="`Select ${shown(data.display_path)}`"
              @update:model-value="triage.toggle(data, $event)"
            />
          </template>
        </Column>
        <Column field="repo" header="Repository" sortable>
          <template #body="{ data }"
            ><span class="inline-block min-w-32 text-sm font-medium" data-test="repo-name">{{
              shown(data.repo_name)
            }}</span></template
          >
        </Column>
        <Column field="org" header="Org" sortable>
          <template #body="{ data }"
            ><span
              v-if="data.org !== null"
              class="inline-block min-w-24 text-sm"
              data-test="repo-org"
              >{{ shown(data.org) }}</span
            ><span
              v-else
              class="text-sm text-surface-400"
              title="No org"
              aria-label="No org"
              data-test="repo-org"
              >—</span
            ></template
          >
        </Column>
        <Column field="type" header="Type" sortable>
          <template #body="{ data }"
            ><span class="inline-block min-w-36 text-sm">{{
              shown(data.kind_label)
            }}</span></template
          >
        </Column>
        <Column field="path" header="File" sortable>
          <template #body="{ data }">
            <RouterLink
              :to="listedPath(triage.query.view, data, data.anchor_finding_id)"
              class="inline-block min-w-48 font-mono text-sm wrap-anywhere gm-link"
              data-test="open-subject"
              >{{ shown(data.display_path) }}</RouterLink
            >
          </template>
        </Column>
        <Column field="status" header="Status" sortable>
          <template #body="{ data }">
            <div class="flex flex-wrap items-center gap-1">
              <StatusSelect
                :status="data.status"
                :label="rowLabel(data)"
                :saving="changing === subjectKey(data)"
                :disabled="changing !== null"
                :title="
                  triage.query.view === 'all'
                    ? 'Sets the status of this row\'s secret, everywhere it was found'
                    : undefined
                "
                @change="onRowStatus(data, $event)"
              />
              <Tag
                v-if="data.repos > 1"
                :value="`${data.repos} repos`"
                severity="warn"
                :title="`Found in ${data.repos} repositories: a status applies to all of them`"
                data-test="repo-count"
              />
              <Button
                v-if="undoable !== null && subjectKey(undoable.subject) === subjectKey(data)"
                label="Undo"
                size="small"
                severity="secondary"
                variant="text"
                :aria-label="`Undo: set back to ${SECRET_STATUSES[undoable.previous]}`"
                :disabled="changing !== null"
                data-test="row-undo"
                @click="undo"
              />
              <Tag
                v-if="triage.possibleCanary(data) && data.status !== 'canary'"
                value="Possible canary"
                severity="info"
                title="A canary word appears in its commit message, file path, line or author"
                data-test="mark-canary"
              />
              <Tag
                v-if="data.no_longer_reported"
                :value="NO_LONGER_REPORTED"
                severity="secondary"
                title="No current run reports it: a re-read superseded the runs that did"
                data-test="mark-no-longer"
              />
              <Tag
                v-if="data.reported_live"
                :value="REPORTED_LIVE"
                severity="danger"
                title="An imported TruffleHog report said it was verified live when it was run"
                data-test="mark-live"
              />
            </div>
          </template>
        </Column>
        <Column header="Commit">
          <template #body="{ data }">
            <span class="font-mono text-sm" :title="shown(data.commit)">
              {{ shown(data.commit.slice(0, 8)) }}
            </span>
          </template>
        </Column>
        <Column field="date" header="Authored" sortable>
          <template #body="{ data }">
            <time
              v-if="data.authored_at"
              :datetime="data.authored_at"
              class="text-sm whitespace-nowrap"
            >
              {{ formatTime(data.authored_at) }}
            </time>
            <span v-else class="text-sm text-surface-500">unknown</span>
          </template>
        </Column>
        <Column field="value" header="Value" :sortable="valueSortable">
          <template #body="{ data }">
            <span class="font-mono text-sm break-all">{{ shown(data.value) }}</span>
          </template>
        </Column>
        <Column header="Actions">
          <template #body="{ data }">
            <div class="flex items-center gap-0.5 whitespace-nowrap">
              <Button
                as="router-link"
                :to="listedPath(triage.query.view, data, data.anchor_finding_id)"
                icon="pi pi-eye"
                size="small"
                severity="secondary"
                variant="text"
                rounded
                title="View"
                :aria-label="`View ${shown(data.display_path)} in ${repoOf(data)}`"
                data-test="row-view"
              />
              <Button
                icon="pi pi-folder-open"
                size="small"
                severity="secondary"
                variant="text"
                rounded
                :disabled="!data.repository_on_disk"
                :title="
                  data.repository_on_disk
                    ? 'Explore the repository at this commit'
                    : 'Not on this machine: an import named this repository'
                "
                :aria-label="`Explore ${repoOf(data)} at this commit, at ${shown(data.display_path)}`"
                data-test="row-explore"
                @click="exploreRow(data)"
              />
              <Button
                icon="pi pi-copy"
                size="small"
                severity="secondary"
                variant="text"
                rounded
                title="Copy the value"
                :aria-label="`Copy the value of ${shown(data.display_path)}`"
                data-test="row-copy"
                @click="copyRow(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <Dialog
      v-model:visible="statusOpen"
      modal
      header="Set status"
      class="w-full max-w-lg"
      data-test="status-dialog"
    >
      <form class="flex flex-col gap-4" @submit.prevent="applyStatus">
        <p class="text-sm">
          {{ plural(triage.selectedCount, "subject", "subjects") }}. Any status can follow any
          other; the history keeps every change.
        </p>
        <div class="flex flex-col gap-1">
          <label id="status-choice-label" for="status-choice" class="text-sm font-medium"
            >Status</label
          >
          <Select
            v-model="statusChoice"
            input-id="status-choice"
            aria-labelledby="status-choice-label"
            :options="STATUS_OPTIONS"
            option-label="label"
            option-value="value"
            placeholder="Choose a status"
            data-test="status-choice"
          />
        </div>
        <div class="flex flex-col gap-1">
          <label for="status-note" class="text-sm font-medium">Note (optional)</label>
          <Textarea
            id="status-note"
            v-model="statusNote"
            rows="3"
            :maxlength="MAX_NOTE_CHARS"
            spellcheck="false"
            autocomplete="off"
          />
          <span class="text-sm text-surface-500">Added to each subject the change moves.</span>
        </div>
        <div class="flex justify-end gap-2">
          <Button
            label="Cancel"
            severity="secondary"
            variant="outlined"
            data-test="cancel-status"
            @click="statusOpen = false"
          />
          <Button
            type="submit"
            label="Set status"
            :disabled="statusChoice === null"
            data-test="apply-status"
          />
        </div>
      </form>
    </Dialog>

    <SkippedDialog
      :skipped="skipped"
      :total="skippedTotal"
      :seen="triage.seen"
      @close="closeSkipped"
    />

    <ManualCopyDialog :text="manualCopy" :count="manualCount" @close="closeManualCopy" />
    <ExportDialog :visible="exportOpen" @close="exportOpen = false" />

    <Toast group="status" position="bottom-right">
      <template #message="{ message }">
        <div data-test="status-toast" class="flex flex-1 items-start gap-3">
          <div class="min-w-0 flex-1">
            <p class="font-semibold">{{ message.summary }}</p>
            <p class="mt-0.5 text-sm">{{ message.detail }}</p>
          </div>
          <Button
            v-if="undoable !== null"
            label="Undo"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="undo-status"
            @click="undo"
          />
        </div>
      </template>
    </Toast>
  </AppPage>
</template>
