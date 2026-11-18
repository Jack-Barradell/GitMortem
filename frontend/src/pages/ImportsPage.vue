<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { useConfirm } from "primevue/useconfirm";
import { computed, onBeforeUnmount, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import ImportForm from "@/components/ImportForm.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import RemovalDialog from "@/components/RemovalDialog.vue";
import { formatBytes, formatTime, messageFor, shown } from "@/format";
import {
  IMPORT_CHECK_COUNTS,
  IMPORT_FAILURES,
  IMPORT_SOURCES,
  IMPORT_STATES,
  REPOSITORY_KINDS,
  TOOLS,
  type Severity,
} from "@/labels";
import { confirmFirst } from "@/confirmFirst";
import { useSay } from "@/notify";
import { usePolling } from "@/poll";
import { importProblem } from "@/problems";
import { useSession } from "@/stores/session";

type Schemas = components["schemas"];
type Import = Schemas["ImportPageOut.ImportOut"];
type ImportPage = Schemas["ImportPageOut"];
type Check = NonNullable<Import["check"]>;
type Removal = Schemas["RemovalOut"];

const PER_PAGE = 20;
const STATE_SEVERITY: Record<Import["state"], Severity> = {
  uploading: "secondary",
  checking: "secondary",
  checked: "warn",
  recording: "secondary",
  recorded: "success",
  discarded: "secondary",
  removed: "secondary",
  failed: "danger",
};

const say = useSay();
const confirm = useConfirm();
const session = useSession();
const plural = (n: number, [one, many]: [string, string]): string => `${n} ${n === 1 ? one : many}`;

let gone = false;
const uploadingId = ref<number | null>(null);

const items = ref<Import[]>([]);
const total = ref(0);
const first = ref(0);
const listError = ref("");
const actionError = ref("");

const poll = usePolling(async () => {
  const page = first.value / PER_PAGE + 1;
  try {
    const found = await api<ImportPage>(`/api/imports?page=${page}&per_page=${PER_PAGE}`, {
      background: true,
    });
    if (page !== first.value / PER_PAGE + 1) return false;
    items.value = found.items;
    total.value = found.total;
    listError.value = "";
    return found.items.some((each) => each.state === "checking" || each.state === "recording");
  } catch (failure) {
    listError.value = messageFor(failure);
    return false;
  }
});
poll.start();

function reload(): void {
  poll.stop();
  poll.start();
}

function onPage(event: DataTablePageEvent): void {
  first.value = event.first;
  reload();
}

function mayEnd(each: Import): boolean {
  return each.mine || session.isAdmin;
}

function askStep(each: Import, done: "confirm" | "discard"): void {
  confirmFirst(confirm, {
    header: done === "confirm" ? "Confirm this import?" : "Discard this import?",
    message:
      done === "confirm"
        ? "Its findings are recorded and join the Secrets list."
        : "Its stored report is deleted and nothing is recorded.",
    acceptLabel: done === "confirm" ? "Confirm" : "Discard",
    danger: done === "discard",
    accept: () => step(each, done),
  });
}

async function step(each: Import, done: "confirm" | "discard"): Promise<void> {
  actionError.value = "";
  let refused: string | null = null;
  try {
    await api<Import>(`/api/imports/${each.id}/${done}`, { method: "POST" });
  } catch (failure) {
    refused = importProblem(failure);
  }
  if (gone) return;
  if (refused === null) {
    say(
      "success",
      done === "confirm" ? "Import confirmed" : "Import discarded",
      done === "confirm" ? "Its findings are being recorded." : "Its stored report is deleted.",
    );
  } else {
    actionError.value = refused;
  }
  reload();
}

const failureText = (failure: NonNullable<Import["failure"]>): string => IMPORT_FAILURES[failure];

function checkLines(check: Check): string[] {
  const count = (key: keyof Check) => plural(check[key], IMPORT_CHECK_COUNTS[key]);
  return [
    count("records"),
    count("values"),
    `${count("standalone")} (${count("redacted")})`,
    count("unknown_commits"),
    count("parse_issues"),
    count("reported_live"),
  ];
}

const removing = ref<Import | null>(null);
const removingName = computed(() =>
  removing.value === null
    ? ""
    : `Import ${removing.value.id}${removing.value.client_name === null ? "" : ` (${shown(removing.value.client_name)})`}`,
);

function removed(counts: Removal): void {
  say(
    "success",
    "Import removed",
    `${counts.findings} ${counts.findings === 1 ? "finding" : "findings"} and ${counts.secrets} ${counts.secrets === 1 ? "secret" : "secrets"} deleted.`,
  );
  removing.value = null;
  reload();
}

onBeforeUnmount(() => {
  gone = true;
});
</script>

<template>
  <AppPage title="Imports" fluid>
    <PagePanel>
      <ImportForm @changed="reload" @uploading="uploadingId = $event" />
    </PagePanel>

    <PagePanel title="Imports" flush>
      <div v-if="listError || actionError" class="flex flex-col gap-2 px-4 pt-2 sm:px-6">
        <Message v-if="listError" severity="error" size="small" role="alert" data-test="list-error">
          Imports not loaded: {{ listError }}
        </Message>
        <Message
          v-if="actionError"
          severity="error"
          size="small"
          role="alert"
          data-test="action-error"
        >
          {{ actionError }}
        </Message>
      </div>
      <DataTable
        v-model:first="first"
        :value="items"
        data-key="id"
        lazy
        :paginator="total > PER_PAGE"
        :rows="PER_PAGE"
        :total-records="total"
        size="small"
        striped-rows
        class="mt-3"
        @page="onPage"
      >
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No imports yet.
          </p></template
        >
        <Column header="Import">
          <template #body="{ data }">
            <span class="flex flex-col">
              <span :data-test="`import-${data.id}`" class="whitespace-nowrap"
                >Import {{ data.id }}</span
              >
              <RouterLink :to="`/scans/${data.scan_id}`" class="text-sm gm-link"
                >Scan {{ data.scan_id }}</RouterLink
              >
            </span>
          </template>
        </Column>
        <Column header="Tool">
          <template #body="{ data }">{{ TOOLS[data.tool as Import["tool"]] }}</template>
        </Column>
        <Column header="Repository">
          <template #body="{ data }">
            <span class="flex flex-col">
              <span class="font-mono break-all">{{ shown(data.repository) }}</span>
              <span
                v-if="!data.repository_on_disk"
                class="text-sm text-surface-500 dark:text-surface-400"
                >{{ REPOSITORY_KINDS.not_on_disk }}</span
              >
            </span>
          </template>
        </Column>
        <Column header="Report">
          <template #body="{ data }">
            <span class="flex flex-col">
              <span>{{ IMPORT_SOURCES[data.source as Import["source"]] }}</span>
              <span v-if="data.client_name !== null" class="font-mono text-sm break-all">{{
                shown(data.client_name)
              }}</span>
              <span v-if="data.server_path !== null" class="font-mono text-sm break-all">{{
                shown(data.server_path)
              }}</span>
              <span class="text-sm text-surface-500 dark:text-surface-400">
                {{ formatBytes(data.size_bytes) }}
                <template v-if="data.state === 'uploading'">
                  · {{ data.pieces_received }} of {{ data.pieces }} pieces
                </template>
              </span>
            </span>
          </template>
        </Column>
        <Column header="State">
          <template #body="{ data }">
            <Tag
              :value="IMPORT_STATES[data.state as Import['state']]"
              :severity="STATE_SEVERITY[data.state as Import['state']]"
            />
            <p
              v-if="data.failure"
              class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
            >
              {{ failureText(data.failure) }}
            </p>
            <p
              v-if="data.failure_reason"
              class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
            >
              {{ shown(data.failure_reason) }}
            </p>
            <p
              v-if="data.state === 'checked' && data.expires_at"
              class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
              :data-test="`expires-${data.id}`"
            >
              Discarded unconfirmed after
              <time :datetime="data.expires_at">{{ formatTime(data.expires_at) }}</time>
            </p>
          </template>
        </Column>
        <Column header="What it holds">
          <template #body="{ data }">
            <ul v-if="data.check" class="text-sm" :data-test="`check-${data.id}`">
              <li v-for="line in checkLines(data.check)" :key="line">{{ line }}</li>
            </ul>
            <span v-else class="text-surface-500">–</span>
          </template>
        </Column>
        <Column header="By">
          <template #body="{ data }">
            <span class="flex flex-col text-sm">
              <span>{{ data.created_by === null ? "–" : shown(data.created_by) }}</span>
              <time :datetime="data.created_at" class="whitespace-nowrap text-surface-500">{{
                formatTime(data.created_at)
              }}</time>
              <span v-if="data.removed_at" class="text-surface-500">
                Removed by {{ data.removed_by === null ? "–" : shown(data.removed_by) }}
              </span>
            </span>
          </template>
        </Column>
        <Column header="">
          <template #body="{ data }">
            <span class="flex flex-wrap gap-2">
              <Button
                v-if="data.state === 'checked' && mayEnd(data)"
                label="Confirm"
                size="small"
                :data-test="`confirm-${data.id}`"
                @click="askStep(data, 'confirm')"
              />
              <Button
                v-if="(data.state === 'checked' || data.state === 'uploading') && mayEnd(data)"
                label="Discard"
                size="small"
                severity="secondary"
                variant="outlined"
                :disabled="uploadingId === data.id"
                :data-test="`discard-${data.id}`"
                @click="askStep(data, 'discard')"
              />
              <Button
                v-if="data.removable"
                label="Remove"
                size="small"
                severity="danger"
                variant="outlined"
                :data-test="`remove-${data.id}`"
                @click="removing = data"
              />
            </span>
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <RemovalDialog
      :import-id="removing?.id ?? null"
      :name="removingName"
      @removed="removed"
      @close="removing = null"
    />
  </AppPage>
</template>
