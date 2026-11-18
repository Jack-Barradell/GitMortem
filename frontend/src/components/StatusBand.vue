<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { SECRET_STATUSES, STATUS_DOT, STATUS_OPTIONS, TOOLS } from "@/labels";
import { useTriage, type SecretStatus } from "@/stores/triage";

const emit = defineEmits<{ change: [] }>();

const triage = useTriage();

type ToolName = keyof typeof TOOLS;
const OPEN: SecretStatus[] = ["unclassified", "to_review", "unsure"];

const counts = computed(() => {
  const unique = new Map(triage.byStatus.map((group) => [group.key, group.unique]));
  return STATUS_OPTIONS.filter((option) => (unique.get(option.value) ?? 0) > 0).map((option) => ({
    status: option.value,
    label: SECRET_STATUSES[option.value],
    unique: unique.get(option.value) ?? 0,
  }));
});
const total = computed(() => counts.value.reduce((sum, count) => sum + count.unique, 0));
const left = computed(() =>
  counts.value.filter((count) => OPEN.includes(count.status)).reduce((sum, c) => sum + c.unique, 0),
);
const tools = computed(() =>
  triage.byTool.map((group) => ({
    key: String(group.key),
    label: TOOLS[group.key as ToolName],
    findings: group.findings,
  })),
);
const statsLink = computed(() => ({ path: "/stats", query: triage.toRoute() }));

function only(status: SecretStatus): boolean {
  const filters = triage.query.filters;
  return (
    !filters.statusesNegated && filters.statuses.length === 1 && filters.statuses[0] === status
  );
}

function toggle(status: SecretStatus): void {
  triage.setFilters({ statuses: only(status) ? [] : [status], statusesNegated: false });
  emit("change");
}
</script>

<template>
  <div data-test="status-band">
    <div class="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
      <p data-test="band-left" class="text-sm text-surface-600 dark:text-surface-300">
        <template v-if="total > 0">
          <span class="text-lg font-semibold text-surface-900 tabular-nums dark:text-surface-50">{{
            left
          }}</span>
          of <span class="tabular-nums">{{ total }}</span> secrets still need a look
        </template>
        <template v-else>No secrets match yet</template>
      </p>
      <p
        class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-surface-500 dark:text-surface-400"
      >
        <span v-for="tool in tools" :key="tool.key" :data-test="`band-tool-${tool.key}`"
          >{{ tool.label }} <span class="tabular-nums">{{ tool.findings }}</span></span
        >
        <RouterLink :to="statsLink" class="font-medium gm-link" data-test="open-stats"
          >Stats</RouterLink
        >
      </p>
    </div>
    <div
      v-if="total > 0"
      class="mt-3 flex h-2 gap-px overflow-hidden rounded-full bg-surface-100 dark:bg-surface-800"
      aria-hidden="true"
    >
      <span
        v-for="count in counts"
        :key="count.status"
        data-test="band-segment"
        :data-status="count.status"
        :class="['basis-0', STATUS_DOT[count.status]]"
        :style="{ flexGrow: String(count.unique) }"
      />
    </div>
    <ul v-if="total > 0" class="mt-3 flex flex-wrap gap-1" aria-label="Filter by status">
      <li v-for="count in counts" :key="count.status">
        <button
          type="button"
          :data-test="`band-status-${count.status}`"
          :aria-pressed="only(count.status)"
          :class="[
            'flex items-center gap-2 rounded-md px-2 py-1 text-sm',
            only(count.status)
              ? 'bg-primary-50 font-medium text-primary-700 dark:bg-primary-950/40 dark:text-primary-300'
              : 'text-surface-700 hover:bg-surface-100 dark:text-surface-200 dark:hover:bg-surface-800',
          ]"
          @click="toggle(count.status)"
        >
          <span
            data-test="status-dot"
            :class="['inline-block h-2 w-2 rounded-full', STATUS_DOT[count.status]]"
            aria-hidden="true"
          />
          <span>{{ count.label }}</span>
          <span class="sr-only">: </span>
          <span class="text-surface-500 tabular-nums dark:text-surface-400">{{
            count.unique
          }}</span>
        </button>
      </li>
    </ul>
  </div>
</template>
