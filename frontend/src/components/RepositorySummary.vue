<script setup lang="ts">
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor, shown } from "@/format";
import { REPOSITORY_KINDS } from "@/labels";

type RepositoryPage = components["schemas"]["FootprintRepositoryPageOut"];

const props = defineProps<{ secretId: number }>();

const PER_PAGE = 20;

const rows = ref<RepositoryPage["items"]>([]);
const total = ref(0);
const first = ref(0);
const loading = ref(false);
const error = ref("");
let generation = 0;

watch(
  () => props.secretId,
  () => {
    generation += 1;
    rows.value = [];
    total.value = 0;
    first.value = 0;
    error.value = "";
    void load(1);
  },
  { immediate: true },
);

async function load(page: number): Promise<void> {
  const mine = generation;
  loading.value = true;
  try {
    const answer = await api<RepositoryPage>(
      `/api/secrets/${props.secretId}/repositories?page=${page}&per_page=${PER_PAGE}`,
    );
    if (mine !== generation) return;
    rows.value = answer.items;
    total.value = answer.total;
    first.value = (answer.page - 1) * answer.per_page;
    error.value = "";
  } catch (failure) {
    if (mine === generation) error.value = messageFor(failure);
  } finally {
    if (mine === generation) loading.value = false;
  }
}

function onPage(event: DataTablePageEvent): void {
  void load(event.page + 1);
}
</script>

<template>
  <div>
    <Tag
      v-if="total >= 2"
      :value="`Reused across ${total} repositories`"
      severity="warn"
      class="mt-2"
      data-test="reused"
    />
    <Message v-if="error" severity="error" size="small" class="mt-2" role="alert">
      {{ error }}
    </Message>
    <DataTable
      :value="rows"
      data-key="repository_id"
      lazy
      :paginator="total > PER_PAGE"
      :rows="PER_PAGE"
      :first="first"
      :total-records="total"
      :loading="loading"
      size="small"
      class="mt-2"
      data-test="repositories"
      @page="onPage"
    >
      <Column header="Repository">
        <template #body="{ data }">
          <span class="flex flex-col gap-1">
            <span>{{ shown(data.repo) }}</span>
            <span v-if="!data.repository_on_disk" class="text-sm text-surface-500">{{
              REPOSITORY_KINDS.not_on_disk
            }}</span>
          </span>
        </template>
      </Column>
      <Column field="places" header="Places" />
      <Column field="findings" header="Findings" />
      <Column header="First authored">
        <template #body="{ data }">
          <time v-if="data.first_authored_at" :datetime="data.first_authored_at">{{
            formatTime(data.first_authored_at)
          }}</time>
          <span v-else class="text-surface-500">unknown</span>
        </template>
      </Column>
      <Column header="Last authored">
        <template #body="{ data }">
          <time v-if="data.last_authored_at" :datetime="data.last_authored_at">{{
            formatTime(data.last_authored_at)
          }}</time>
          <span v-else class="text-surface-500">unknown</span>
        </template>
      </Column>
    </DataTable>
  </div>
</template>
