<script setup lang="ts">
import Column from "primevue/column";
import Button from "primevue/button";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Dialog from "primevue/dialog";
import Tag from "primevue/tag";
import { useToast } from "primevue/usetoast";
import { computed, onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import { formatTime, messageFor, shown, shownName } from "@/format";
import { auditActionLabel, SUBJECT_KINDS } from "@/labels";
import { subjectPath, type Subject } from "@/stores/triage";

type AuditPage = components["schemas"]["AuditPageOut"];
type SubjectPage = components["schemas"]["AuditSubjectPageOut"];

const PER_PAGE = 50;
const toast = useToast();

const items = ref<AuditPage["items"]>([]);
const total = ref(0);
const first = ref(0);
const loading = ref(false);

async function load(page: number): Promise<void> {
  loading.value = true;
  try {
    const result = await api<AuditPage>(`/api/audit?page=${page}&per_page=${PER_PAGE}`);
    items.value = result.items;
    total.value = result.total;
    first.value = (page - 1) * PER_PAGE;
  } catch (failure) {
    items.value = [];
    toast.add({
      severity: "error",
      summary: "Audit log not loaded",
      detail: messageFor(failure),
      life: 6000,
    });
  } finally {
    loading.value = false;
  }
}

function onPage(event: DataTablePageEvent): void {
  void load(event.page + 1);
}

const SUBJECTS_PER_PAGE = 20;
const viewing = ref<AuditPage["items"][number] | null>(null);
const subjects = ref<SubjectPage["items"]>([]);
const subjectTotal = ref(0);
const subjectFirst = ref(0);
const subjectsLoading = ref(false);
const subjectRows = computed(() =>
  subjects.value.map((subject) => ({ ...subject, key: `${subject.kind}:${subject.id}` })),
);
let subjectRequest = 0;

async function loadSubjects(eventId: number, page: number): Promise<void> {
  const mine = ++subjectRequest;
  subjectsLoading.value = true;
  try {
    const result = await api<SubjectPage>(
      `/api/audit/${eventId}/subjects?page=${page}&per_page=${SUBJECTS_PER_PAGE}`,
    );
    if (mine !== subjectRequest) return;
    subjects.value = result.items;
    subjectTotal.value = result.total;
    subjectFirst.value = (page - 1) * SUBJECTS_PER_PAGE;
  } catch (failure) {
    if (mine !== subjectRequest) return;
    subjects.value = [];
    toast.add({
      severity: "error",
      summary: "Subjects not loaded",
      detail: messageFor(failure),
      life: 6000,
    });
  } finally {
    if (mine === subjectRequest) subjectsLoading.value = false;
  }
}

function openSubjects(event: AuditPage["items"][number]): void {
  viewing.value = event;
  subjects.value = [];
  subjectTotal.value = 0;
  subjectFirst.value = 0;
  void loadSubjects(event.id, 1);
}

function closeSubjects(): void {
  subjectRequest++;
  viewing.value = null;
}

function onSubjectPage(event: DataTablePageEvent): void {
  if (viewing.value) void loadSubjects(viewing.value.id, event.page + 1);
}

function subjectCount(detail: AuditPage["items"][number]["detail"]): number {
  const count = detail.subjects;
  return typeof count === "number" ? count : 0;
}

function subjectsLabel(detail: AuditPage["items"][number]["detail"]): string {
  const count = subjectCount(detail);
  return `${count} ${count === 1 ? "subject" : "subjects"}`;
}

function detailValue(value: unknown): string {
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  return shownName(JSON.stringify(value));
}

function carriedCount(detail: AuditPage["items"][number]["detail"]): number | null {
  const count = detail.carried;
  return typeof count === "number" ? count : null;
}

function describe(detail: AuditPage["items"][number]["detail"]): string {
  return Object.entries(detail)
    .filter(([key]) => key !== "subjects" && key !== "carried")
    .map(([key, value]) => `${key}=${detailValue(value)}`)
    .join(", ");
}

onMounted(() => load(1));
</script>

<template>
  <AppPage title="Audit log" fluid>
    <PagePanel flush>
      <DataTable
        :value="items"
        data-key="id"
        lazy
        paginator
        striped-rows
        :rows="PER_PAGE"
        :first="first"
        :total-records="total"
        :loading="loading"
        size="small"
        @page="onPage"
      >
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No events to show.
          </p></template
        >
        <Column header="Time">
          <template #body="{ data }">
            <time :datetime="data.at" class="whitespace-nowrap">{{ formatTime(data.at) }}</time>
          </template>
        </Column>
        <Column header="Action">
          <template #body="{ data }">{{ auditActionLabel(data.action, data.detail) }}</template>
        </Column>
        <Column header="Actor">
          <template #body="{ data }">{{ data.actor_username ?? "–" }}</template>
        </Column>
        <Column header="Target">
          <template #body="{ data }">{{ data.target_username ?? "–" }}</template>
        </Column>
        <Column header="IP">
          <template #body="{ data }">
            <span class="font-mono">{{ data.ip ?? "–" }}</span>
          </template>
        </Column>
        <Column header="Detail">
          <template #body="{ data }">
            <span class="text-surface-500 dark:text-surface-400">{{ describe(data.detail) }}</span>
            <span
              v-if="carriedCount(data.detail) !== null"
              class="ml-2 text-sm"
              :data-test="`carried-${data.id}`"
            >
              {{ carriedCount(data.detail) }} subjects, not named
            </span>
            <Button
              v-if="subjectCount(data.detail) > 0"
              :label="subjectsLabel(data.detail)"
              size="small"
              text
              @click="openSubjects(data)"
            />
          </template>
        </Column>
      </DataTable>
    </PagePanel>
    <Dialog
      :visible="viewing !== null"
      modal
      header="Subjects"
      class="w-full max-w-2xl"
      @update:visible="closeSubjects"
    >
      <DataTable
        :value="subjectRows"
        data-key="key"
        lazy
        paginator
        :rows="SUBJECTS_PER_PAGE"
        :first="subjectFirst"
        :total-records="subjectTotal"
        :loading="subjectsLoading"
        size="small"
        @page="onSubjectPage"
      >
        <template #empty>No subjects to show.</template>
        <Column header="Subject">
          <template #body="{ data }">
            <span v-if="data.removed" class="flex items-center gap-2" data-test="removed-subject">
              <span>{{ SUBJECT_KINDS[data.kind as Subject["kind"]] }} {{ data.id }}</span>
              <Tag value="Removed" severity="secondary" />
            </span>
            <RouterLink v-else :to="subjectPath(data)" class="gm-link">
              {{ SUBJECT_KINDS[data.kind as Subject["kind"]] }} {{ data.id }}
            </RouterLink>
          </template>
        </Column>
        <Column header="Type or rule">
          <template #body="{ data }">{{ shown(data.kind_label) }}</template>
        </Column>
      </DataTable>
    </Dialog>
  </AppPage>
</template>
