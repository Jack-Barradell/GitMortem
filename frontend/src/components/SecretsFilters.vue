<script setup lang="ts">
import AutoComplete from "primevue/autocomplete";
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import DatePicker from "primevue/datepicker";
import MultiSelect from "primevue/multiselect";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import { computed, ref } from "vue";
import ChoicePicker from "@/components/ChoicePicker.vue";
import { NO_ORG_VALUE, triageChoices } from "@/pickers";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor, shown } from "@/format";
import {
  REPORTED_LIVE,
  REPORTED_SCOPES,
  SCAN_SCOPES,
  SCAN_STATES,
  STATUS_OPTIONS,
  TOOLS,
} from "@/labels";
import {
  dateOf,
  dayOf,
  MAX_PATHS,
  useTriage,
  type Filters,
  type ReportedScope,
  type ScanScope,
} from "@/stores/triage";

type Facets = components["schemas"]["FacetsOut"];
type PathChoice = components["schemas"]["PathsOut"]["items"][number];
type FacetScan = Facets["scans"][number];

const props = defineProps<{ facets: Facets | null }>();
const emit = defineEmits<{ change: [] }>();
const triage = useTriage();
const filters = computed(() => triage.query.filters);

function set(patch: Partial<Filters>): void {
  triage.setFilters(patch);
  emit("change");
}

const scopeOptions = Object.entries(SCAN_SCOPES).map(([value, label]) => ({ value, label }));
const reportedOptions = Object.entries(REPORTED_SCOPES).map(([value, label]) => ({ value, label }));
const liveOptions = [
  { value: true, label: REPORTED_LIVE },
  { value: false, label: `Not ${REPORTED_LIVE.toLowerCase()}` },
];
const reusedOptions = [
  { value: true, label: "Found in more than one repository" },
  { value: false, label: "Found in one repository" },
];
const NO_ORG = NO_ORG_VALUE;
const SOURCES = {
  org: triageChoices("org"),
  repository: triageChoices("repository"),
  kind: triageChoices("kind"),
};
const chosenOrgs = computed(() => [
  ...(filters.value.noOrg ? [NO_ORG] : []),
  ...filters.value.orgs,
]);
function pickOrgs(picked: string[]): void {
  set({ orgs: picked.filter((org) => org !== NO_ORG), noOrg: picked.includes(NO_ORG) });
}
const toolLabel = (tool: keyof typeof TOOLS): string => TOOLS[tool];
const scanLabel = (scan: FacetScan): string =>
  `Scan ${scan.id} · ${formatTime(scan.created_at)} · ${SCAN_STATES[scan.state]}`;

function pickScan(scanId: number | null | undefined): void {
  set(scanId === null || scanId === undefined ? { scanId: null, scanScope: "seen" } : { scanId });
}

const pathChoices = ref<string[]>([]);
const pathCounts = ref(new Map<string, string>());
const pathsError = ref("");
let pathsAsked = 0;

async function suggestPaths(typed: string): Promise<void> {
  const asked = ++pathsAsked;
  try {
    const found = await api<components["schemas"]["PathsOut"]>("/api/triage/paths", {
      method: "POST",
      body: { repository_ids: [...filters.value.repositoryIds], text: typed.slice(0, 256) },
    });
    if (asked !== pathsAsked) return;
    pathsError.value = "";
    pathCounts.value = new Map(found.items.map((item) => [item.path, countOf(item)]));
    pathChoices.value = found.items
      .map((item) => item.path)
      .filter((path) => !filters.value.paths.includes(path));
  } catch (failure) {
    if (asked !== pathsAsked) return;
    pathChoices.value = [];
    pathsError.value = messageFor(failure);
  }
}

function pickPaths(picked: string[] | null): void {
  set({ paths: (picked ?? []).slice(0, MAX_PATHS) });
}

function countOf(item: PathChoice): string {
  return `${item.unique} ${item.unique === 1 ? "secret" : "secrets"}`;
}

const open = ref(false);

const anyChosen = computed(() => {
  const f = filters.value;
  return (
    f.orgs.length +
      f.repositoryIds.length +
      f.paths.length +
      f.kinds.length +
      f.tools.length +
      f.statuses.length >
      0 ||
    f.statusesNegated ||
    f.kindsNegated ||
    f.noOrg ||
    f.reused !== null ||
    f.canary ||
    f.scanId !== null ||
    f.reported !== "all" ||
    f.reportedLive !== null ||
    f.from !== null ||
    f.to !== null
  );
});

function clearChoices(): void {
  set({
    orgs: [],
    noOrg: false,
    repositoryIds: [],
    paths: [],
    kinds: [],
    kindsNegated: false,
    tools: [],
    statuses: [],
    statusesNegated: false,
    scanId: null,
    scanScope: "seen",
    reported: "all",
    reportedLive: null,
    reused: null,
    canary: false,
    from: null,
    to: null,
  });
}

const range = computed<(Date | null)[] | null>(() => {
  const { from, to } = filters.value;
  if (from === null && to === null) return null;
  return [from === null ? null : dateOf(from), to === null ? null : dateOf(to)];
});

function pickRange(value: unknown): void {
  if (value === null || value === undefined) {
    set({ from: null, to: null });
    return;
  }
  const [start, end] = Array.isArray(value) ? (value as (Date | null)[]) : [];
  if (start instanceof Date && end instanceof Date) set({ from: dayOf(start), to: dayOf(end) });
}
</script>

<template>
  <div role="group" aria-label="Filters">
    <button
      type="button"
      class="flex items-center gap-2 rounded-md px-2 py-1 text-sm font-medium text-surface-700 hover:bg-surface-100 lg:hidden dark:text-surface-200 dark:hover:bg-surface-800"
      :aria-expanded="open"
      aria-controls="filters-grid"
      data-test="toggle-filters"
      @click="open = !open"
    >
      <i class="pi pi-filter text-xs" aria-hidden="true" />
      Filters<span v-if="anyChosen" class="text-primary"> in use</span>
      <i
        :class="open ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
        class="text-xs"
        aria-hidden="true"
      />
    </button>
    <div
      id="filters-grid"
      :class="[
        'grid grid-cols-1 items-start gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6',
        open ? 'mt-3 lg:mt-0' : 'hidden lg:grid',
      ]"
    >
      <div class="flex min-w-0 flex-col gap-1">
        <label for="filter-org" class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Org</label
        >
        <ChoicePicker
          :source="SOURCES.org"
          input-id="filter-org"
          :model-value="chosenOrgs"
          placeholder="Any org"
          test="filter-org"
          @update:model-value="pickOrgs($event as string[])"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-repo"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Repository</label
        >
        <ChoicePicker
          :source="SOURCES.repository"
          input-id="filter-repo"
          :model-value="filters.repositoryIds"
          placeholder="Any repository"
          test="filter-repo"
          @update:model-value="set({ repositoryIds: $event as number[] })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-file"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >File</label
        >
        <AutoComplete
          input-id="filter-file"
          :model-value="filters.paths"
          :suggestions="pathChoices"
          multiple
          fluid
          :delay="200"
          placeholder="Any file"
          :pt="{ input: { spellcheck: 'false', autocomplete: 'off' } }"
          data-test="filter-file"
          @complete="suggestPaths($event.query)"
          @update:model-value="pickPaths($event)"
        >
          <template #option="{ option }">
            <span class="flex w-full min-w-0 items-baseline justify-between gap-3">
              <span class="font-mono text-xs break-all">{{ shown(option) }}</span>
              <span class="shrink-0 text-xs text-surface-500 dark:text-surface-400">{{
                pathCounts.get(option)
              }}</span>
            </span>
          </template>
          <template #chip="{ value, removeCallback }">
            <span
              class="inline-flex max-w-full items-center gap-1 rounded-md bg-surface-100 px-2 py-0.5 dark:bg-surface-700"
              data-test="filter-file-chip"
            >
              <span class="font-mono text-xs break-all">{{ shown(value) }}</span>
              <button
                type="button"
                class="flex shrink-0 items-center text-surface-500 hover:text-surface-800 dark:text-surface-400 dark:hover:text-surface-100"
                :aria-label="`Remove ${shown(value)}`"
                @click="removeCallback($event)"
              >
                <i class="pi pi-times-circle text-xs" aria-hidden="true" />
              </button>
            </span>
          </template>
        </AutoComplete>
        <span v-if="pathsError" class="text-xs text-red-600 dark:text-red-400" role="alert">{{
          pathsError
        }}</span>
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-kind"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Type</label
        >
        <ChoicePicker
          :source="SOURCES.kind"
          input-id="filter-kind"
          :model-value="filters.kinds"
          placeholder="Any type"
          test="filter-kind"
          @update:model-value="set({ kinds: $event as string[] })"
        />
        <div class="flex items-center gap-2">
          <Checkbox
            binary
            input-id="kind-negated"
            :model-value="filters.kindsNegated"
            data-test="kind-negated"
            @update:model-value="set({ kindsNegated: $event })"
          />
          <label for="kind-negated" class="text-xs">Is none of these</label>
        </div>
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-tool"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Tool</label
        >
        <MultiSelect
          input-id="filter-tool"
          :model-value="filters.tools"
          :options="props.facets?.tools ?? []"
          :option-label="toolLabel"
          placeholder="Any"
          class="w-full"
          data-test="filter-tool"
          @update:model-value="set({ tools: $event })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-status"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Status</label
        >
        <MultiSelect
          input-id="filter-status"
          :model-value="filters.statuses"
          :options="STATUS_OPTIONS"
          option-label="label"
          option-value="value"
          :max-selected-labels="2"
          placeholder="Any"
          class="w-full"
          data-test="filter-status"
          @update:model-value="set({ statuses: $event })"
        />
        <div class="flex items-center gap-2">
          <Checkbox
            binary
            input-id="status-negated"
            :model-value="filters.statusesNegated"
            data-test="status-negated"
            @update:model-value="set({ statusesNegated: $event })"
          />
          <label for="status-negated" class="text-xs">Is none of these</label>
        </div>
      </div>
      <div class="flex min-w-0 flex-col gap-1 sm:col-span-2">
        <label
          for="filter-scan"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Scan</label
        >
        <Select
          input-id="filter-scan"
          :model-value="filters.scanId"
          :options="props.facets?.scans ?? []"
          :option-label="scanLabel"
          option-value="id"
          show-clear
          placeholder="Any"
          class="w-full"
          data-test="filter-scan"
          @update:model-value="pickScan"
        />
        <SelectButton
          :model-value="filters.scanScope"
          :options="scopeOptions"
          option-label="label"
          option-value="value"
          :allow-empty="false"
          :disabled="filters.scanId === null"
          size="small"
          aria-label="Seen in or new in the scan"
          data-test="filter-scope"
          @update:model-value="set({ scanScope: $event as ScanScope })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1 sm:col-span-2">
        <span
          id="filter-reported-label"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Reported</span
        >
        <SelectButton
          :model-value="filters.reported"
          :options="reportedOptions"
          option-label="label"
          option-value="value"
          :allow-empty="false"
          size="small"
          aria-labelledby="filter-reported-label"
          data-test="filter-reported"
          @update:model-value="set({ reported: $event as ReportedScope })"
        />
        <label
          for="filter-live"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Reported live</label
        >
        <Select
          input-id="filter-live"
          :model-value="filters.reportedLive"
          :options="liveOptions"
          option-label="label"
          option-value="value"
          show-clear
          placeholder="Any"
          class="w-full"
          data-test="filter-live"
          @update:model-value="set({ reportedLive: $event ?? null })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-reused"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Reuse</label
        >
        <Select
          input-id="filter-reused"
          :model-value="filters.reused"
          :options="reusedOptions"
          option-label="label"
          option-value="value"
          show-clear
          placeholder="Any"
          class="w-full"
          data-test="filter-reused"
          @update:model-value="set({ reused: $event ?? null })"
        />
        <div class="flex items-center gap-2">
          <Checkbox
            binary
            input-id="filter-canary"
            :model-value="filters.canary"
            data-test="filter-canary"
            @update:model-value="set({ canary: $event })"
          />
          <label for="filter-canary" class="text-xs">Possible canaries only</label>
        </div>
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="filter-dates"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Authored</label
        >
        <DatePicker
          input-id="filter-dates"
          :model-value="range"
          selection-mode="range"
          :manual-input="false"
          date-format="yy-mm-dd"
          show-button-bar
          placeholder="Any time"
          class="w-full"
          @update:model-value="pickRange"
        />
      </div>
      <Button
        v-if="anyChosen"
        class="self-end"
        label="Clear filters"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="clear-filters"
        @click="clearChoices"
      />
    </div>
  </div>
</template>
