<script setup lang="ts">
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Dialog from "primevue/dialog";
import Tag from "primevue/tag";
import { computed, ref, watch } from "vue";
import type { components } from "@/api/schema";
import SubjectLabel from "@/components/SubjectLabel.vue";
import { formatTime } from "@/format";
import { SECRET_STATUSES, statusSeverity } from "@/labels";
import { subjectKey, type Row } from "@/stores/triage";

type Skipped = components["schemas"]["StatusOut.SkippedOut"];

const PER_PAGE = 50;

const props = defineProps<{ skipped: Skipped[]; total: number; seen: Map<string, Row> }>();
const emit = defineEmits<{ close: [] }>();

const rows = computed(() =>
  props.skipped.map((s) => ({ ...s, key: subjectKey(s), row: props.seen.get(subjectKey(s)) })),
);
const first = ref(0);
watch(
  () => props.skipped,
  () => (first.value = 0),
);
</script>

<template>
  <Dialog
    :visible="props.total > 0"
    modal
    header="Changed by someone else"
    class="w-full max-w-4xl"
    data-test="skipped"
    @update:visible="emit('close')"
  >
    <p class="text-sm">
      Someone changed these after this page loaded, so they were left as they are. Check each one,
      then set its status again if you still want to.
    </p>
    <p v-if="props.total > props.skipped.length" class="mt-2 text-sm" data-test="skipped-total">
      {{ props.total }} were changed by someone else in all. The first
      {{ props.skipped.length }} are listed here.
    </p>
    <DataTable
      v-model:first="first"
      :value="rows"
      data-key="key"
      :paginator="rows.length > PER_PAGE"
      :rows="PER_PAGE"
      size="small"
      class="mt-2"
    >
      <Column header="Subject">
        <template #body="{ data }">
          <SubjectLabel :subject="data" :row="data.row" />
        </template>
      </Column>
      <Column header="Now">
        <template #body="{ data }">
          <Tag
            :value="SECRET_STATUSES[data.status as Skipped['status']]"
            :severity="statusSeverity(data.status)"
          />
        </template>
      </Column>
      <Column header="Changed by">
        <template #body="{ data }">{{ data.changed_by ?? "–" }}</template>
      </Column>
      <Column header="When">
        <template #body="{ data }">
          <time :datetime="data.changed_at" class="whitespace-nowrap">
            {{ formatTime(data.changed_at) }}
          </time>
        </template>
      </Column>
    </DataTable>
  </Dialog>
</template>
