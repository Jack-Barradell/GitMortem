<script setup lang="ts">
import { ref, useId } from "vue";
import { formatBytes } from "@/format";

const props = defineProps<{
  label: string;
  action: string;
  testId: string;
  accept?: string;
  disabled?: boolean;
  inputId?: string;
}>();

const emit = defineEmits<{ pick: [file: File | null] }>();

const id = props.inputId ?? useId();
const labelId = useId();
const chosenId = useId();
const chosen = ref<File | null>(null);

function changed(event: Event): void {
  const input = event.target as HTMLInputElement;
  chosen.value = input.files?.[0] ?? null;
  input.value = "";
  emit("pick", chosen.value);
}
</script>

<template>
  <div class="flex flex-col gap-1">
    <span :id="labelId" class="text-sm font-medium">{{ label }}</span>
    <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
      <label
        class="inline-flex cursor-pointer items-center gap-2 rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-base font-medium text-surface-700 has-enabled:hover:bg-surface-100 has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-primary has-disabled:cursor-not-allowed has-disabled:opacity-60 dark:border-surface-600 dark:bg-surface-900 dark:text-surface-100 dark:has-enabled:hover:bg-surface-800"
        :data-test="`${testId}-button`"
      >
        <input
          :id="id"
          type="file"
          class="sr-only"
          :accept="accept"
          :disabled="disabled"
          :aria-labelledby="labelId"
          :aria-describedby="chosenId"
          :data-test="testId"
          @change="changed"
        />
        <i class="pi pi-upload" aria-hidden="true" />
        <span>{{ action }}</span>
      </label>
      <span
        :id="chosenId"
        class="min-w-0 text-sm break-all"
        :class="chosen === null ? 'text-surface-500' : 'text-surface-700 dark:text-surface-200'"
        :data-test="`${testId}-chosen`"
        >{{
          chosen === null ? "No file chosen" : `${chosen.name} (${formatBytes(chosen.size)})`
        }}</span
      >
    </div>
  </div>
</template>
