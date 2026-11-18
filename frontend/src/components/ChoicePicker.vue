<script setup lang="ts">
import AutoComplete from "primevue/autocomplete";
import { ref, watch } from "vue";
import { messageFor, shown } from "@/format";
import type { PickerOption, PickerSource, PickerValue } from "@/pickers";

const props = defineProps<{
  source: PickerSource;
  modelValue: PickerValue[];
  inputId: string;
  test: string;
  placeholder: string;
}>();
const emit = defineEmits<{ "update:modelValue": [PickerValue[]] }>();

const suggestions = ref<PickerValue[]>([]);
const labels = ref(new Map<PickerValue, string>());
const counts = ref(new Map<PickerValue, string>());
const error = ref("");
let asked = 0;
let named = 0;

function remember(found: PickerOption[]): void {
  const nextLabels = new Map(labels.value);
  const nextCounts = new Map(counts.value);
  for (const option of found) {
    nextLabels.set(option.value, option.label);
    nextCounts.set(option.value, option.count);
  }
  labels.value = nextLabels;
  counts.value = nextCounts;
}

function labelOf(value: PickerValue): string {
  return labels.value.get(value) ?? props.source.fallback(value);
}

async function suggest(typed: string): Promise<void> {
  const mine = ++asked;
  try {
    const found = await props.source.ask(typed);
    if (mine !== asked) return;
    error.value = "";
    remember(found);
    suggestions.value = found
      .map((option) => option.value)
      .filter((value) => !props.modelValue.includes(value));
  } catch (failure) {
    if (mine !== asked) return;
    suggestions.value = [];
    error.value = messageFor(failure);
  }
}

async function nameChosen(chosen: PickerValue[]): Promise<void> {
  const name = props.source.name;
  if (name === undefined) return;
  const missing = chosen.filter((value) => !labels.value.has(value));
  if (missing.length === 0) return;
  const mine = ++named;
  try {
    const found = await name(missing);
    if (mine === named) remember(found);
  } catch (failure) {
    if (mine === named) error.value = messageFor(failure);
  }
}

watch(() => props.modelValue, nameChosen, { immediate: true });

function pick(picked: PickerValue[] | null): void {
  emit("update:modelValue", [...new Set(picked ?? [])]);
}
</script>

<template>
  <AutoComplete
    :input-id="inputId"
    :model-value="modelValue"
    :suggestions="suggestions"
    multiple
    fluid
    complete-on-focus
    :delay="200"
    :placeholder="placeholder"
    :pt="{ input: { spellcheck: 'false', autocomplete: 'off' } }"
    :data-test="test"
    @complete="suggest($event.query)"
    @update:model-value="pick($event)"
  >
    <template #option="{ option }">
      <span class="flex w-full min-w-0 items-baseline justify-between gap-3">
        <span class="text-xs break-all">{{ shown(labelOf(option)) }}</span>
        <span class="shrink-0 text-xs text-surface-500 dark:text-surface-400">{{
          counts.get(option)
        }}</span>
      </span>
    </template>
    <template #chip="{ value, removeCallback }">
      <span
        class="inline-flex max-w-full items-center gap-1 rounded-md bg-surface-100 px-2 py-0.5 dark:bg-surface-700"
        :data-test="`${test}-chip`"
      >
        <span class="text-xs break-all">{{ shown(labelOf(value)) }}</span>
        <button
          type="button"
          class="flex shrink-0 items-center text-surface-500 hover:text-surface-800 dark:text-surface-400 dark:hover:text-surface-100"
          :aria-label="`Remove ${shown(labelOf(value))}`"
          @click="removeCallback($event)"
        >
          <i class="pi pi-times-circle text-xs" aria-hidden="true" />
        </button>
      </span>
    </template>
  </AutoComplete>
  <span v-if="error" class="text-xs text-red-600 dark:text-red-400" role="alert">{{ error }}</span>
</template>
