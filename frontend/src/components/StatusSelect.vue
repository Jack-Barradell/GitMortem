<script setup lang="ts">
import Select from "primevue/select";
import { SECRET_STATUSES, STATUS_DOT, STATUS_OPTIONS } from "@/labels";
import type { SecretStatus } from "@/stores/triage";

const props = defineProps<{
  status: SecretStatus;
  label: string;
  saving?: boolean;
  disabled?: boolean;
}>();
const emit = defineEmits<{ change: [status: SecretStatus] }>();

function picked(next: SecretStatus): void {
  if (next !== props.status) emit("change", next);
}
</script>

<template>
  <div data-test="row-status" :aria-busy="saving ? 'true' : undefined">
    <Select
      :model-value="status"
      :options="STATUS_OPTIONS"
      option-label="label"
      option-value="value"
      size="small"
      :aria-label="label"
      :disabled="saving || disabled"
      class="w-40"
      @update:model-value="picked"
    >
      <template #value>
        <span class="flex items-center gap-2">
          <span
            data-test="status-dot"
            :class="['inline-block h-2 w-2 shrink-0 rounded-full', STATUS_DOT[status]]"
            aria-hidden="true"
          />
          <span>{{ SECRET_STATUSES[status] }}</span>
        </span>
      </template>
      <template #option="{ option }">
        <span class="flex items-center gap-2">
          <span
            :class="[
              'inline-block h-2 w-2 shrink-0 rounded-full',
              STATUS_DOT[option.value as SecretStatus],
            ]"
            aria-hidden="true"
          />
          <span>{{ option.label }}</span>
        </span>
      </template>
    </Select>
  </div>
</template>
