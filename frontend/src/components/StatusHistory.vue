<script setup lang="ts">
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor, shown } from "@/format";
import { SECRET_STATUSES, statusSeverity } from "@/labels";
import { subjectKey, subjectPath, type Subject } from "@/stores/triage";

type History = components["schemas"]["HistoryOut"];
type Status = components["schemas"]["HistoryOut.SecretStatus"];

const props = defineProps<{ subject: Subject; refresh: number }>();

const items = ref<History["items"]>([]);
const loaded = ref(false);
const error = ref("");
let generation = 0;

async function reload(): Promise<void> {
  const mine = ++generation;
  try {
    const answer = await api<History>(`/api${subjectPath(props.subject)}/history`);
    if (mine !== generation) return;
    items.value = answer.items;
    loaded.value = true;
    error.value = "";
  } catch (failure) {
    if (mine === generation) error.value = messageFor(failure);
  }
}

watch(() => [subjectKey(props.subject), props.refresh], reload, { immediate: true });
</script>

<template>
  <div>
    <Message v-if="error" severity="error" size="small" role="alert">{{ error }}</Message>
    <p v-if="loaded && items.length === 0" class="text-sm text-surface-500">
      No status changes yet.
    </p>
    <DataTable v-if="items.length > 0" :value="items" size="small" striped-rows scrollable>
      <Column header="When">
        <template #body="{ data }">
          <time :datetime="data.at" class="whitespace-nowrap">{{ formatTime(data.at) }}</time>
        </template>
      </Column>
      <Column header="Who">
        <template #body="{ data }">{{ data.user === null ? "–" : shown(data.user) }}</template>
      </Column>
      <Column header="From">
        <template #body="{ data }">
          <Tag
            :value="SECRET_STATUSES[data.from_status as Status]"
            :severity="statusSeverity(data.from_status)"
          />
        </template>
      </Column>
      <Column header="To">
        <template #body="{ data }">
          <Tag
            :value="SECRET_STATUSES[data.to_status as Status]"
            :severity="statusSeverity(data.to_status)"
          />
        </template>
      </Column>
    </DataTable>
  </div>
</template>
