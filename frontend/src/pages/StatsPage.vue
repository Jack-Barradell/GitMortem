<script setup lang="ts">
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Message from "primevue/message";
import { onBeforeUnmount, ref, watch } from "vue";
import {
  onBeforeRouteLeave,
  RouterLink,
  useRoute,
  useRouter,
  type LocationQueryRaw,
} from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import { messageFor, shown } from "@/format";
import { SECRET_STATUSES, TOOLS } from "@/labels";
import { staysInTriage, useTriage, type SecretStatus } from "@/stores/triage";

type Stats = components["schemas"]["StatsOut"];
type Group = Stats["by_org"]["groups"][number];
type Dimension = "org" | "repository" | "kind" | "status" | "tool";
type ToolName = keyof typeof TOOLS;

const DIMENSIONS: { name: Dimension; title: string; field: keyof Stats }[] = [
  { name: "org", title: "Org", field: "by_org" },
  { name: "repository", title: "Repository", field: "by_repository" },
  { name: "kind", title: "Type", field: "by_kind" },
  { name: "status", title: "Status", field: "by_status" },
  { name: "tool", title: "Tool", field: "by_tool" },
];

const triage = useTriage();
const route = useRoute();
const router = useRouter();
const found = ref<Stats | null>(null);
const error = ref("");
const loading = ref(false);
let asked = 0;

watch(
  () => route.query,
  () => {
    if (route.path !== "/stats") return;
    triage.fromRoute(route.query);
    void load();
  },
  { immediate: true },
);

let leavingFor: string | null = null;
onBeforeRouteLeave((to) => {
  leavingFor = to.path;
});
const stopWatchingNavigation = router.afterEach((_to, _from, failure) => {
  if (failure) leavingFor = null;
});
onBeforeUnmount(() => {
  stopWatchingNavigation();
  asked += 1;
  if (leavingFor === null || !staysInTriage({ path: leavingFor })) triage.leaveTriage();
});

async function load(): Promise<void> {
  const mine = ++asked;
  loading.value = true;
  error.value = "";
  try {
    const answer = await api<Stats>("/api/triage/stats", {
      method: "POST",
      body: triage.statsBody(),
    });
    if (mine === asked) found.value = answer;
  } catch (failure) {
    if (mine === asked) error.value = messageFor(failure);
  } finally {
    if (mine === asked) loading.value = false;
  }
}

function groupsOf(field: keyof Stats): Stats["by_org"] | null {
  const value = found.value?.[field];
  return typeof value === "object" && value !== null ? value : null;
}

function labelOf(name: Dimension, group: Group): string {
  if (name === "org") return group.key === null ? "No org" : shown(String(group.key));
  if (name === "repository") return shown(group.label ?? String(group.key));
  if (name === "status") return SECRET_STATUSES[group.key as SecretStatus];
  if (name === "tool") return TOOLS[group.key as ToolName];
  return shown(String(group.key));
}

function linkTo(name: Dimension, group: Group): { path: string; query: LocationQueryRaw } {
  const query: LocationQueryRaw = { ...triage.toRoute() };
  delete query.page;
  const key = String(group.key);
  if (name === "org") {
    delete query.org;
    delete query.noorg;
    if (group.key === null) query.noorg = "1";
    else query.org = [key];
  } else if (name === "repository") {
    query.repo = [key];
  } else if (name === "kind") {
    query.kind = [key];
  } else if (name === "status") {
    query.status = [key];
    delete query.not;
  } else {
    query.tool = [key];
  }
  return { path: "/secrets", query };
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}
</script>

<template>
  <AppPage title="Stats">
    <template #summary>
      <RouterLink :to="{ path: '/secrets', query: triage.toRoute() }" class="font-medium gm-link"
        >Back to the list</RouterLink
      >
    </template>
    <Message v-if="error" severity="error" size="small" role="alert">{{ error }}</Message>
    <template v-if="found">
      <PagePanel>
        <p class="text-2xl font-semibold tabular-nums" data-test="stats-totals">
          {{ plural(found.findings, "finding", "findings") }}, {{ found.unique }} unique
        </p>
      </PagePanel>
      <div class="grid gap-6 md:grid-cols-2">
        <PagePanel
          v-for="dimension in DIMENSIONS"
          :key="dimension.name"
          :title="dimension.title"
          flush
          class="min-w-0"
        >
          <DataTable
            :value="groupsOf(dimension.field)?.groups ?? []"
            size="small"
            striped-rows
            class="mt-3"
          >
            <Column :header="dimension.title">
              <template #body="{ data }">
                <RouterLink
                  :to="linkTo(dimension.name, data)"
                  class="gm-link"
                  :data-test="`group-${dimension.name}-${data.key === null ? 'none' : data.key}`"
                  >{{ labelOf(dimension.name, data) }}</RouterLink
                >
              </template>
            </Column>
            <Column field="findings" header="Findings" body-class="tabular-nums" />
            <Column field="unique" header="Unique" body-class="tabular-nums" />
          </DataTable>
          <p
            v-if="
              (groupsOf(dimension.field)?.total_groups ?? 0) >
              (groupsOf(dimension.field)?.groups.length ?? 0)
            "
            class="px-4 py-3 text-sm text-surface-500 sm:px-6 dark:text-surface-400"
            :data-test="`more-${dimension.name}`"
          >
            {{
              (groupsOf(dimension.field)?.total_groups ?? 0) -
              (groupsOf(dimension.field)?.groups.length ?? 0)
            }}
            more not shown
          </p>
        </PagePanel>
      </div>
    </template>
  </AppPage>
</template>
