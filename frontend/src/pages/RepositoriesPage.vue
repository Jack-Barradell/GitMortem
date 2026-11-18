<script setup lang="ts">
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent, type DataTableSortEvent } from "primevue/datatable";
import Message from "primevue/message";
import Select from "primevue/select";
import Tag from "primevue/tag";
import { useConfirm } from "primevue/useconfirm";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import DeleteReposDialog from "@/components/DeleteReposDialog.vue";
import DiscoveryPanel from "@/components/DiscoveryPanel.vue";
import AppPage from "@/components/page/AppPage.vue";
import FieldLabel from "@/components/page/FieldLabel.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import RepositoryFilters from "@/components/RepositoryFilters.vue";
import { formatBytes, formatTime, messageFor, shownName } from "@/format";
import {
  DELETION_FAILURES,
  DELETION_STATES,
  REPOSITORY_KINDS,
  REPOSITORY_REFUSALS,
  REPOSITORY_STATES,
  toolStatusLabel,
  type Severity,
} from "@/labels";
import { confirmFirst } from "@/confirmFirst";
import { useSay } from "@/notify";
import {
  anyFilter,
  apiRepositoryFilters,
  matches,
  noFilters,
  queryOf,
  REPO_SORTS,
  viewOf,
  type RepoFilters,
  type RepoSort,
  type RepoView,
} from "@/repositoryFilters";
import { useSession } from "@/stores/session";
import { FILTER_QUIET_MS, PAGE_SIZES } from "@/stores/triage";

type Schemas = components["schemas"];
type Root = Schemas["ScanRootOut"];
type Repo = Schemas["RepositoryPageOut.RepositoryOut"];
type Refusal = NonNullable<Repo["refusal"]>;
type DeletionState = NonNullable<Repo["deletion_state"]>;
type DeletionFailure = NonNullable<Repo["deletion_failure"]>;
type RepoPage = Schemas["RepositoryPageOut"];
type RepoList = Schemas["RepositoryListOut"];
type Tool = Schemas["ToolListOut.ToolOut"];
type Selection =
  | { mode: "ids"; ids: Set<number> }
  | {
      mode: "matching";
      filters: RepoFilters;
      count: number;
      excluded: Set<number>;
      included: Set<number>;
    };

const PER_PAGE = 200;
const ROWS = 50;
const MAX_ROWS = 500;
const STATE_SEVERITY: Record<Repo["state"], Severity> = {
  scannable: "success",
  refused: "warn",
  missing: "secondary",
};

const session = useSession();
const confirm = useConfirm();
const route = useRoute();
const router = useRouter();
const say = useSay();

const roots = ref<Root[]>([]);
const rootsLoaded = ref(false);
const rootId = ref<number | null>(null);
const root = computed(() => roots.value.find((r) => r.id === rootId.value) ?? null);
const rootLabel = (r: Root): string => (r.usable ? r.path : `${r.path} (unusable)`);

async function loadRoots(): Promise<void> {
  try {
    roots.value = await api<Root[]>("/api/scan-roots");
  } catch (failure) {
    say("error", "Scan roots not loaded", messageFor(failure));
  } finally {
    rootsLoaded.value = true;
  }
}

function rootToOpen(): Root | undefined {
  const asked = route.query.root;
  return roots.value.find((r) => String(r.id) === asked) ?? roots.value[0];
}

async function open(chosen: Root): Promise<void> {
  rootId.value = chosen.id;
  repos.value = [];
  total.value = 0;
  selection.value = { mode: "ids", ids: new Set() };
  scanError.value = "";
  await loadRepos(chosen.id);
}

async function pick(chosen: Root): Promise<void> {
  const filters = { ...view.value.filters, orgs: [], noOrg: false };
  view.value = { ...view.value, filters, page: 1 };
  await router.replace({ query: { root: String(chosen.id), ...queryOf(view.value) } });
  await open(chosen);
}

function noteDiscovery(id: number, discoveryId: number): void {
  roots.value = roots.value.map((r) =>
    r.id === id ? { ...r, last_discovery_id: discoveryId } : r,
  );
}

const repos = ref<Repo[]>([]);
const reposLoading = ref(false);
const total = ref(0);
const counts = ref({ filters: noFilters(), matching: 0, rootScannable: 0, rootUnscanned: 0 });
const selection = ref<Selection>({ mode: "ids", ids: new Set() });
const view = ref<RepoView>(viewOf(route.query));

const selectedCount = computed(() => {
  const chosen = selection.value;
  if (chosen.mode === "ids") return chosen.ids.size;
  return chosen.count - chosen.excluded.size + chosen.included.size;
});
const wholeRoot = computed(() => {
  const chosen = selection.value;
  return (
    chosen.mode === "matching" &&
    !anyFilter(chosen.filters) &&
    chosen.excluded.size === 0 &&
    chosen.included.size === 0
  );
});

function scannableNow(repo: Repo): boolean {
  return repo.state === "scannable" && repo.deletion_state === null;
}

function inSnapshot(repo: Repo, filters: RepoFilters): boolean {
  return scannableNow(repo) && matches(repo, filters);
}

function ticked(repo: Repo): boolean {
  const chosen = selection.value;
  if (chosen.mode === "ids") return chosen.ids.has(repo.id);
  if (chosen.included.has(repo.id)) return true;
  return inSnapshot(repo, chosen.filters) && !chosen.excluded.has(repo.id);
}

function allMatching(filters: RepoFilters, count: number): Selection {
  return { mode: "matching", filters, count, excluded: new Set(), included: new Set() };
}

function show(next: Partial<RepoView>): void {
  view.value = { ...view.value, ...next };
  const at = rootId.value === null ? {} : { root: String(rootId.value) };
  void router.replace({ query: { ...at, ...queryOf(view.value) } });
}

let quiet: ReturnType<typeof setTimeout> | null = null;

function reload(): void {
  if (rootId.value !== null) void loadPage(rootId.value);
}

function onFilters(filters: RepoFilters): void {
  show({ filters, page: 1 });
  if (quiet !== null) clearTimeout(quiet);
  quiet = setTimeout(() => {
    quiet = null;
    reload();
  }, FILTER_QUIET_MS);
}

function onPage(event: DataTablePageEvent): void {
  show({ page: Math.floor(event.first / event.rows) + 1, rows: event.rows });
  reload();
}

function onSort(event: DataTableSortEvent): void {
  const field = typeof event.sortField === "string" ? event.sortField : "";
  if (!(REPO_SORTS as readonly string[]).includes(field)) return;
  show({ sort: field as RepoSort, descending: event.sortOrder === -1, page: 1 });
  reload();
}

let listing = 0;
onBeforeUnmount(() => {
  listing += 1;
  if (quiet !== null) clearTimeout(quiet);
});

function defaultSelection(): void {
  const { rootUnscanned, rootScannable } = counts.value;
  selection.value =
    rootUnscanned > 0
      ? allMatching({ ...noFilters(), scanned: "never" }, rootUnscanned)
      : allMatching(noFilters(), rootScannable);
}

let resetOwed = false;

async function loadPage(id: number, reset = false): Promise<void> {
  const mine = ++listing;
  if (reset) resetOwed = true;
  reposLoading.value = true;
  try {
    const { filters, sort, descending, page, rows } = view.value;
    const found = await api<RepoList>("/api/repositories/query", {
      method: "POST",
      body: {
        root: id,
        filters: apiRepositoryFilters(filters),
        sort,
        order: descending ? "desc" : "asc",
        page,
        per_page: rows,
      },
    });
    if (mine !== listing) return;
    if (found.items.length === 0 && page > 1 && found.total > 0) {
      show({ page: Math.ceil(found.total / rows) });
      reposLoading.value = false;
      await loadPage(id);
      return;
    }
    repos.value = found.items;
    total.value = found.total;
    counts.value = {
      filters: { ...filters },
      matching: found.matching_scannable,
      rootScannable: found.root_scannable,
      rootUnscanned: found.root_unscanned,
    };
    if (resetOwed) {
      resetOwed = false;
      defaultSelection();
    }
  } catch (failure) {
    if (mine === listing) say("error", "Repositories not loaded", messageFor(failure));
  } finally {
    if (mine === listing) reposLoading.value = false;
  }
}

async function loadRepos(id: number): Promise<void> {
  await loadPage(id, true);
}

const uploaded = ref<Repo[]>([]);

async function loadUploaded(): Promise<void> {
  try {
    const found = new Map<number, Repo>();
    for (let page = 1; ; page += 1) {
      const result = await api<RepoPage>(
        `/api/repositories?kind=uploaded&page=${page}&per_page=${PER_PAGE}`,
      );
      for (const repo of result.items) found.set(repo.id, repo);
      if (result.items.length < PER_PAGE || found.size >= result.total) break;
    }
    uploaded.value = [...found.values()];
  } catch (failure) {
    say("error", "Uploaded repositories not loaded", messageFor(failure));
  }
}

const deleting = ref<number[]>([]);
const deleteOpen = ref(false);

function askDelete(ids: number[]): void {
  if (ids.length === 0) return;
  deleting.value = ids;
  deleteOpen.value = true;
}

async function deleted(): Promise<void> {
  say("success", "Deletion started", "The repositories are refused to scans while it runs.");
  if (root.value) await loadRepos(root.value.id);
  await Promise.all([loadUploaded(), loadNotOnDisk()]);
}

const notOnDisk = ref<Repo[]>([]);

async function loadNotOnDisk(): Promise<void> {
  try {
    const found = new Map<number, Repo>();
    for (let page = 1; ; page += 1) {
      const result = await api<RepoPage>(
        `/api/repositories?kind=not_on_disk&page=${page}&per_page=${PER_PAGE}`,
      );
      for (const repo of result.items) found.set(repo.id, repo);
      if (result.items.length < PER_PAGE || found.size >= result.total) break;
    }
    notOnDisk.value = [...found.values()];
  } catch (failure) {
    say("error", "Repositories not on disk not loaded", messageFor(failure));
  }
}

function toggle(repo: Repo, on: boolean): void {
  const chosen = selection.value;
  if (chosen.mode === "ids") {
    const ids = new Set(chosen.ids);
    if (on) ids.add(repo.id);
    else ids.delete(repo.id);
    selection.value = { mode: "ids", ids };
    return;
  }
  const excluded = new Set(chosen.excluded);
  const included = new Set(chosen.included);
  const matched = inSnapshot(repo, chosen.filters);
  if (matched && on) excluded.delete(repo.id);
  if (matched && !on) excluded.add(repo.id);
  if (!matched && on) included.add(repo.id);
  if (!matched && !on) included.delete(repo.id);
  selection.value = { ...chosen, excluded, included };
}

function selectAll(): void {
  selection.value = allMatching({ ...counts.value.filters }, counts.value.matching);
}

function selectUnscanned(): void {
  selection.value = allMatching({ ...noFilters(), scanned: "never" }, counts.value.rootUnscanned);
}

function selectNone(): void {
  selection.value = { mode: "ids", ids: new Set() };
}

const resolving = ref(false);

async function matchingIds(rootOf: number, filters: RepoFilters): Promise<number[]> {
  const ids: number[] = [];
  let read = 0;
  for (let page = 1; ; page += 1) {
    const found = await api<RepoList>("/api/repositories/query", {
      method: "POST",
      body: {
        root: rootOf,
        filters: { ...apiRepositoryFilters(filters), states: ["scannable"] },
        page,
        per_page: MAX_ROWS,
      },
    });
    read += found.items.length;
    ids.push(...found.items.filter(scannableNow).map((repo) => repo.id));
    if (found.items.length < MAX_ROWS || read >= found.total) return ids;
  }
}

async function deleteSelected(): Promise<void> {
  const chosen = selection.value;
  if (chosen.mode === "ids") {
    askDelete([...chosen.ids]);
    return;
  }
  if (rootId.value === null) return;
  resolving.value = true;
  try {
    const matched = await matchingIds(rootId.value, chosen.filters);
    const kept = matched.filter((id) => !chosen.excluded.has(id));
    askDelete([...new Set([...kept, ...chosen.included])]);
  } catch (failure) {
    say("error", "Repositories not loaded", messageFor(failure));
  } finally {
    resolving.value = false;
  }
}

const tools = ref<Tool[]>([]);
const toolsError = ref("");
const scanning = ref(false);
const scanError = ref("");

async function loadTools(): Promise<void> {
  try {
    tools.value = await api<Tool[]>("/api/tools");
  } catch (failure) {
    toolsError.value = messageFor(failure);
  }
}

const noRules = (t: Tool): boolean => t.name === "custom-rules" && (t.enabled_rules ?? 0) === 0;
const canRun = (t: Tool): boolean => t.usable && !noRules(t);
const whyNot = (t: Tool): string => (noRules(t) ? "no rule enabled" : toolStatusLabel(t.status));

function cannotRun(enabled: Tool[]): string {
  if (enabled.length > 1) {
    const named = enabled.map((t) => `${t.name} (${whyNot(t)})`).join(", ");
    return `No enabled scanner tool can be run: ${named}.`;
  }
  return enabled.map((t) => `${t.name} is enabled but cannot be run (${whyNot(t)}).`).join("");
}

const blocker = computed<{ text: string; toTools: boolean } | null>(() => {
  if (root.value !== null && !root.value.usable) {
    return { text: "This scan root cannot be scanned.", toTools: false };
  }
  if (toolsError.value) {
    return { text: `The scanner tools could not be checked: ${toolsError.value}`, toTools: false };
  }
  const enabled = tools.value.filter((t) => t.enabled);
  if (enabled.length === 0) return { text: "No scanner tool is enabled.", toTools: true };
  if (!enabled.some(canRun)) return { text: cannotRun(enabled), toTools: true };
  if (selectedCount.value === 0) {
    return { text: "Select at least one repository.", toTools: false };
  }
  return null;
});

function askScan(): void {
  const many = wholeRoot.value && root.value !== null ? "every repository in this root" : null;
  const count = selectedCount.value;
  confirmFirst(confirm, {
    header: "Start a scan?",
    message: `Every enabled tool scans ${many ?? `${count} ${count === 1 ? "repository" : "repositories"}`}.`,
    acceptLabel: "Scan",
    accept: scan,
  });
}

function scanBody(rootOf: number): Schemas["ScanIn"] {
  const chosen = selection.value;
  if (chosen.mode === "ids") return { repository_ids: [...chosen.ids], matching: null };
  if (wholeRoot.value) return { scan_root_ids: [rootOf], matching: null };
  return {
    matching: {
      scan_root_id: rootOf,
      filters: apiRepositoryFilters(chosen.filters),
      excluded_ids: [...chosen.excluded],
      included_ids: [...chosen.included],
    },
  };
}

async function scan(): Promise<void> {
  if (rootId.value === null) return;
  scanning.value = true;
  scanError.value = "";
  const count = selectedCount.value;
  try {
    const started = await api<Schemas["ScanIdOut"]>("/api/scans", {
      method: "POST",
      body: scanBody(rootId.value),
    });
    say("success", "Scan started", `${count} ${count === 1 ? "repository" : "repositories"}`);
    await router.push(`/scans/${started.scan_id}`);
  } catch (failure) {
    scanError.value = messageFor(failure);
  } finally {
    scanning.value = false;
  }
}

onMounted(async () => {
  await Promise.all([loadRoots(), loadTools(), loadNotOnDisk(), loadUploaded()]);
  const first = rootToOpen();
  if (first !== undefined) await open(first);
});
</script>

<template>
  <AppPage title="Repositories" fluid>
    <PagePanel v-if="rootsLoaded && roots.length === 0">
      <p class="text-sm" data-test="no-roots">
        No scan roots yet.
        <template v-if="session.isAdmin">
          Add one on the
          <RouterLink to="/scan-roots" class="font-medium gm-link">Scan roots</RouterLink>
          page.
        </template>
        <template v-else>Ask an admin to add one.</template>
      </p>
    </PagePanel>

    <template v-if="root">
      <PagePanel>
        <div class="flex flex-col">
          <FieldLabel for="scan-root">Scan root</FieldLabel>
          <Select
            input-id="scan-root"
            :model-value="root"
            :options="roots"
            :option-label="rootLabel"
            data-key="id"
            class="max-w-full min-w-80 self-start font-mono"
            @update:model-value="pick"
          />
        </div>
        <Message v-if="!root.usable" severity="warn" size="small" class="mt-3">
          This scan root is gone, or no longer inside a base the operator allowed, so it can be
          neither discovered nor scanned. Its repositories are still listed.
        </Message>
        <DiscoveryPanel :key="root.id" :root="root" @follow="noteDiscovery" @ended="loadRepos" />
      </PagePanel>

      <PagePanel flush>
        <div class="border-b border-surface-200 px-4 py-4 sm:px-6 dark:border-surface-700">
          <RepositoryFilters
            :model-value="view.filters"
            :root="root.id"
            @update:model-value="onFilters"
          />
        </div>
        <div
          class="flex flex-wrap items-center gap-2 border-b border-surface-200 px-4 py-3 sm:px-6 dark:border-surface-700"
        >
          <Button
            label="Select all"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="select-all"
            @click="selectAll"
          />
          <Button
            :label="`Select not scanned (${counts.rootUnscanned})`"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="select-unscanned"
            :disabled="counts.rootUnscanned === 0"
            @click="selectUnscanned"
          />
          <Button
            label="Select none"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="select-none"
            @click="selectNone"
          />
          <span class="text-sm" data-test="selection-count">
            {{ selectedCount }} of {{ counts.rootScannable }} scannable repositories selected
          </span>
          <Button
            v-if="session.isAdmin"
            label="Delete selected"
            size="small"
            severity="danger"
            variant="outlined"
            data-test="delete-selected"
            :disabled="selectedCount === 0"
            :loading="resolving"
            @click="deleteSelected"
          />
          <Button
            label="Scan selected"
            icon="pi pi-play"
            class="ml-auto"
            :loading="scanning"
            :disabled="blocker !== null || scanning"
            data-test="scan-selected"
            @click="askScan"
          />
        </div>
        <p
          v-if="blocker"
          class="px-4 pt-3 text-right text-sm text-surface-500 sm:px-6 dark:text-surface-400"
          data-test="scan-blocker"
        >
          {{ blocker.text }}
          <template v-if="blocker.toTools && session.isAdmin">
            Change it on the
            <RouterLink to="/tools" class="font-medium gm-link">Tools</RouterLink>
            page.
          </template>
          <template v-else-if="blocker.toTools">Ask an admin to change it.</template>
        </p>
        <Message
          v-if="scanError"
          severity="error"
          size="small"
          class="mx-4 mt-3 sm:mx-6"
          role="alert"
          data-test="scan-error"
        >
          {{ scanError }}
        </Message>

        <DataTable
          :value="repos"
          data-key="id"
          :loading="reposLoading"
          lazy
          :paginator="total > PAGE_SIZES[0]"
          :rows="view.rows"
          :first="(view.page - 1) * view.rows"
          :total-records="total"
          :rows-per-page-options="[...PAGE_SIZES]"
          :sort-field="view.sort"
          :sort-order="view.descending ? -1 : 1"
          size="small"
          striped-rows
          data-test="root-repositories"
          @page="onPage"
          @sort="onSort"
        >
          <template #empty
            ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
              <template v-if="anyFilter(view.filters)"
                >No repositories match these filters.</template
              >
              <template v-else
                >No repositories listed under this root. Discover them first.</template
              >
            </p></template
          >
          <Column header="Scan">
            <template #body="{ data }">
              <Checkbox
                binary
                :model-value="ticked(data)"
                :disabled="data.state !== 'scannable'"
                :aria-label="`Scan ${shownName(data.display_path)}`"
                @update:model-value="toggle(data, $event)"
              />
            </template>
          </Column>
          <Column header="Org" sortable sort-field="org">
            <template #body="{ data }">{{
              data.org === null ? "–" : shownName(data.org)
            }}</template>
          </Column>
          <Column header="Name" sortable sort-field="name">
            <template #body="{ data }">
              <span class="font-medium">{{ shownName(data.name) }}</span>
            </template>
          </Column>
          <Column header="Path" sortable sort-field="path">
            <template #body="{ data }">
              <span class="font-mono break-all">{{ shownName(data.display_path) }}</span>
            </template>
          </Column>
          <Column header="Kind" sortable sort-field="kind">
            <template #body="{ data }">{{ REPOSITORY_KINDS[data.kind as Repo["kind"]] }}</template>
          </Column>
          <Column header="Commits" sortable sort-field="commits">
            <template #body="{ data }">
              <span v-if="data.commit_count !== null">{{ data.commit_count }}</span>
              <span v-else class="text-surface-500 dark:text-surface-400">not counted</span>
            </template>
          </Column>
          <Column header="Size" sortable sort-field="size">
            <template #body="{ data }">
              <span class="whitespace-nowrap">{{ formatBytes(data.size_bytes) }}</span>
            </template>
          </Column>
          <Column header="Last scanned" sortable sort-field="scanned">
            <template #body="{ data }">
              <span class="flex flex-wrap items-center gap-2" data-test="last-scanned">
                <time
                  v-if="data.last_scanned_at"
                  :datetime="data.last_scanned_at"
                  class="whitespace-nowrap"
                  >{{ formatTime(data.last_scanned_at) }}</time
                >
                <span v-else class="text-surface-500 dark:text-surface-400">Never</span>
                <Tag v-if="data.scanning" value="Scanning now" severity="info" />
              </span>
            </template>
          </Column>
          <Column header="State" sortable sort-field="state">
            <template #body="{ data }">
              <Tag
                :value="REPOSITORY_STATES[data.state as Repo['state']]"
                :severity="STATE_SEVERITY[data.state as Repo['state']]"
              />
              <p
                v-if="data.refusal"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
              >
                {{ REPOSITORY_REFUSALS[data.refusal as Refusal] }}
              </p>
              <p v-if="data.deletion_state" class="mt-1 text-sm" data-test="deletion-state">
                {{ DELETION_STATES[data.deletion_state as DeletionState] }}
                <template v-if="data.deletion_failure">
                  : {{ DELETION_FAILURES[data.deletion_failure as DeletionFailure] }}
                </template>
              </p>
            </template>
          </Column>
          <Column header="Explore">
            <template #body="{ data }">
              <RouterLink
                :to="`/repositories/${data.id}/explore`"
                :aria-label="`Explore ${data.display_path}`"
                class="inline-flex items-center gap-1.5 text-sm font-medium gm-link"
                data-test="explore"
                ><i class="pi pi-folder-open text-xs" aria-hidden="true" />Explore</RouterLink
              >
            </template>
          </Column>
          <Column v-if="session.isAdmin" header="Delete">
            <template #body="{ data }">
              <Button
                :label="data.deletion_state === 'failed' ? 'Retry' : 'Delete'"
                size="small"
                severity="danger"
                variant="text"
                data-test="delete-one"
                :disabled="data.deletion_state === 'deleting'"
                @click="askDelete([data.id])"
              />
            </template>
          </Column>
        </DataTable>
      </PagePanel>
    </template>

    <PagePanel v-if="uploaded.length > 0" title="Uploaded" flush data-test="uploaded">
      <p class="px-4 pt-1 pb-3 text-sm text-surface-500 sm:px-6 dark:text-surface-400">
        Rebuilt from uploaded zips. Each keeps its versions when a newer upload lacked something an
        older one held; scans read every version.
      </p>
      <DataTable
        :value="uploaded"
        data-key="id"
        :paginator="uploaded.length > ROWS"
        :rows="ROWS"
        size="small"
        striped-rows
      >
        <Column header="Org">
          <template #body="{ data }">{{ data.org === null ? "–" : shownName(data.org) }}</template>
        </Column>
        <Column header="Name">
          <template #body="{ data }">
            <span class="font-medium">{{ shownName(data.name) }}</span>
          </template>
        </Column>
        <Column header="Versions">
          <template #body="{ data }">
            <span data-test="version-count">{{ data.versions?.length ?? 0 }}</span>
          </template>
        </Column>
        <Column header="Updates">
          <template #body="{ data }">{{ data.updates }}</template>
        </Column>
        <Column header="State">
          <template #body="{ data }">
            <span v-if="data.deletion_state" data-test="deletion-state">
              {{ DELETION_STATES[data.deletion_state as DeletionState] }}
            </span>
            <span v-else>{{ REPOSITORY_STATES[data.state as Repo["state"]] }}</span>
          </template>
        </Column>
        <Column header="Explore">
          <template #body="{ data }">
            <RouterLink
              :to="`/repositories/${data.id}/explore`"
              :aria-label="`Explore ${data.display_path}`"
              class="inline-flex items-center gap-1.5 text-sm font-medium gm-link"
              data-test="explore"
              ><i class="pi pi-folder-open text-xs" aria-hidden="true" />Explore</RouterLink
            >
          </template>
        </Column>
        <Column v-if="session.isAdmin" header="Delete">
          <template #body="{ data }">
            <Button
              :label="data.deletion_state === 'failed' ? 'Retry' : 'Delete'"
              size="small"
              severity="danger"
              variant="text"
              data-test="delete-uploaded"
              :disabled="data.deletion_state === 'deleting'"
              @click="askDelete([data.id])"
            />
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <DeleteReposDialog
      v-if="session.isAdmin"
      v-model:visible="deleteOpen"
      :ids="deleting"
      @deleted="deleted"
    />

    <PagePanel v-if="notOnDisk.length > 0" title="Not on disk" flush data-test="not-on-disk">
      <p class="px-4 pt-1 pb-3 text-sm text-surface-500 sm:px-6 dark:text-surface-400">
        Named by an import, these are not on this machine: they are never scanned, and their
        findings have no lines to read or files to explore. Import the report again against the
        repository on disk to have both.
      </p>
      <DataTable
        :value="notOnDisk"
        data-key="id"
        :paginator="notOnDisk.length > ROWS"
        :rows="ROWS"
        size="small"
        striped-rows
      >
        <Column header="Org">
          <template #body="{ data }">{{ shownName(data.org) }}</template>
        </Column>
        <Column header="Name">
          <template #body="{ data }">
            <span class="font-medium">{{ shownName(data.name) }}</span>
          </template>
        </Column>
        <Column header="Kind">
          <template #body="{ data }">{{ REPOSITORY_KINDS[data.kind as Repo["kind"]] }}</template>
        </Column>
      </DataTable>
    </PagePanel>
  </AppPage>
</template>
