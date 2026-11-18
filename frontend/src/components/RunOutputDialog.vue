<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import { computed, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { formatBytes, messageFor } from "@/format";

type Output = components["schemas"]["RunOutputOut"];

const props = defineProps<{ scanId: number; runId: number | null; title: string }>();
const emit = defineEmits<{ close: [] }>();

const output = ref<Output | null>(null);
const error = ref("");
const loading = ref(false);
let asked = 0;

const shown = computed(() =>
  output.value === null ? 0 : new TextEncoder().encode(output.value.text).length,
);

watch(
  () => [props.scanId, props.runId] as const,
  async ([scanId, runId]) => {
    asked += 1;
    const mine = asked;
    output.value = null;
    error.value = "";
    loading.value = runId !== null;
    if (runId === null) return;
    try {
      const found = await api<Output>(`/api/scans/${scanId}/runs/${runId}/output`);
      if (mine === asked) output.value = found;
    } catch (failure) {
      if (mine === asked) error.value = messageFor(failure);
    } finally {
      if (mine === asked) loading.value = false;
    }
  },
  { immediate: true },
);
</script>

<template>
  <Dialog
    :visible="props.runId !== null"
    modal
    :header="props.title"
    class="w-full max-w-4xl"
    data-test="run-output"
    @update:visible="emit('close')"
  >
    <p v-if="loading" class="text-sm" data-test="output-loading">Reading the tool's output…</p>
    <Message v-else-if="error" severity="error" :closable="false" data-test="output-error">
      {{ error }}
    </Message>
    <template v-else-if="output">
      <p v-if="output.text === ''" class="text-sm" data-test="output-empty">
        The tool wrote nothing to its error output.
      </p>
      <template v-else>
        <p
          v-if="output.cut"
          class="text-sm text-surface-500 dark:text-surface-400"
          data-test="output-cut"
        >
          The last {{ formatBytes(shown) }} of {{ formatBytes(output.size) }}, from the start of a
          line.
        </p>
        <pre
          tabindex="0"
          aria-label="The tool's error output"
          class="mt-2 max-h-[60vh] overflow-auto rounded-md bg-surface-50 p-3 font-mono text-sm break-all whitespace-pre-wrap dark:bg-surface-800"
          data-test="output-text"
          >{{ output.text }}</pre>
      </template>
    </template>
    <div class="mt-4 flex justify-end">
      <Button label="Close" data-test="close-output" @click="emit('close')" />
    </div>
  </Dialog>
</template>
