<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { onBeforeUnmount, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import { formatTime, messageFor } from "@/format";
import { SCAN_KINDS, SCAN_STATES, scanSeverity } from "@/labels";
import { useSay } from "@/notify";

type ScanPage = components["schemas"]["ScanPageOut"];
type Summary = ScanPage["items"][number];

const PER_PAGE = 50;
const say = useSay();
const route = useRoute();
const router = useRouter();
let gone = false;
const left = (): boolean => gone || route.path !== "/scans";

const items = ref<Summary[]>([]);
const total = ref(0);
const first = ref(0);
let shown = 0;
const loadError = ref("");
const loading = ref(false);

async function load(page: number): Promise<void> {
  loading.value = true;
  try {
    const result = await api<ScanPage>(`/api/scans?page=${page}&per_page=${PER_PAGE}`);
    items.value = result.items;
    total.value = result.total;
    shown = (page - 1) * PER_PAGE;
    first.value = shown;
    loadError.value = "";
  } catch (failure) {
    first.value = shown;
    loadError.value = messageFor(failure);
    say("error", "Scans not loaded", loadError.value);
  } finally {
    loading.value = false;
  }
}

function onPage(event: DataTablePageEvent): void {
  void load(event.page + 1);
}

const rereadNote = ref("");
const rereading = ref(false);

async function rereadStale(): Promise<void> {
  rereading.value = true;
  rereadNote.value = "";
  try {
    const made = await api<components["schemas"]["RereadOut"]>("/api/rereads", {
      method: "POST",
      body: { stale: true },
    });
    if (left()) return;
    if (made.scan_id === null) {
      rereadNote.value =
        "Nothing to re-read: every current run a parser judged was read by today's parsers.";
      return;
    }
    say(
      "success",
      "Re-read started",
      `Re-reading ${made.runs} ${made.runs === 1 ? "run" : "runs"}.`,
    );
    await router.push(`/scans/${made.scan_id}`);
  } catch (failure) {
    if (!left()) rereadNote.value = messageFor(failure);
  } finally {
    rereading.value = false;
  }
}

onMounted(() => load(1));
onBeforeUnmount(() => {
  gone = true;
});
</script>

<template>
  <AppPage title="Scans">
    <template #actions>
      <Button
        label="Re-read runs from older parsers"
        icon="pi pi-replay"
        size="small"
        severity="secondary"
        variant="outlined"
        :loading="rereading"
        :disabled="rereading"
        title="Reads again the stored output of every run a parser older than today's judged; no tool runs"
        data-test="reread-stale"
        @click="rereadStale"
      />
    </template>
    <Message
      v-if="rereadNote"
      severity="secondary"
      size="small"
      role="status"
      data-test="reread-note"
    >
      {{ rereadNote }}
    </Message>
    <PagePanel flush>
      <DataTable
        v-model:first="first"
        :value="items"
        data-key="id"
        lazy
        paginator
        :rows="PER_PAGE"
        :total-records="total"
        :loading="loading"
        size="small"
        striped-rows
        @page="onPage"
      >
        <template #empty>
          <p class="py-6 text-center text-surface-500 dark:text-surface-400">
            <template v-if="loadError">Scans not loaded: {{ loadError }}</template>
            <template v-else>
              No scans yet. Choose what to scan on the
              <RouterLink to="/repositories" class="font-medium gm-link">Repositories</RouterLink>
              page.
            </template>
          </p>
        </template>
        <Column header="Scan">
          <template #body="{ data }">
            <RouterLink :to="`/scans/${data.id}`" class="font-medium gm-link">
              Scan {{ data.id }}
            </RouterLink>
          </template>
        </Column>
        <Column header="Kind">
          <template #body="{ data }">
            <span data-test="kind">{{ SCAN_KINDS[data.kind as Summary["kind"]] }}</span>
          </template>
        </Column>
        <Column header="State">
          <template #body="{ data }">
            <Tag
              :value="SCAN_STATES[data.state as Summary['state']]"
              :severity="scanSeverity(data.state)"
            />
          </template>
        </Column>
        <Column header="Started by">
          <template #body="{ data }">{{ data.started_by ?? "–" }}</template>
        </Column>
        <Column header="Runs">
          <template #body="{ data }">{{ data.run_count }}</template>
        </Column>
        <Column header="Created">
          <template #body="{ data }">
            <time :datetime="data.created_at" class="whitespace-nowrap">
              {{ formatTime(data.created_at) }}
            </time>
          </template>
        </Column>
        <Column header="Finished">
          <template #body="{ data }">
            <time v-if="data.finished_at" :datetime="data.finished_at" class="whitespace-nowrap">
              {{ formatTime(data.finished_at) }}
            </time>
            <span v-else class="text-surface-500 dark:text-surface-400">–</span>
          </template>
        </Column>
      </DataTable>
    </PagePanel>
  </AppPage>
</template>
