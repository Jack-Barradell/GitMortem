<script setup lang="ts">
import Message from "primevue/message";
import { computed, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import MarkedSegments from "@/components/MarkedSegments.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import { messageFor } from "@/format";
import { UNAVAILABLE } from "@/labels";

type Context = components["schemas"]["ContextOut"];
type Lines = components["schemas"]["ContextOut.ContextLinesOut"];

const props = defineProps<{ findingId: number }>();

const context = ref<Context | null>(null);
const error = ref("");
let generation = 0;

watch(
  () => props.findingId,
  async (id) => {
    const mine = ++generation;
    context.value = null;
    error.value = "";
    try {
      const answer = await api<Context>(`/api/findings/${id}/context`);
      if (mine === generation) context.value = answer;
    } catch (failure) {
      if (mine === generation) error.value = messageFor(failure);
    }
  },
  { immediate: true },
);

const lines = computed((): Lines | null =>
  context.value !== null && "lines" in context.value ? context.value : null,
);
const unavailable = computed(() =>
  context.value !== null && "unavailable" in context.value ? context.value.unavailable : null,
);
</script>

<template>
  <div data-test="context">
    <p v-if="context === null && error === ''" class="text-sm text-surface-500">
      Reading the lines…
    </p>
    <Message v-if="error" severity="error" size="small" role="alert">{{ error }}</Message>
    <Message v-if="unavailable" severity="secondary" size="small" data-test="unavailable">
      {{ UNAVAILABLE[unavailable] }}
    </Message>
    <template v-if="lines">
      <Message v-if="lines.integrity_failed" severity="warn" size="small" data-test="integrity">
        This repo failed its integrity check; the lines shown may not be what was committed.
      </Message>
      <MarksDroppedNote v-if="lines.marks_dropped" />
      <p v-if="lines.lines.length === 0" class="text-sm text-surface-500">No lines to show here.</p>
      <table v-else class="mt-1 w-full border-collapse font-mono text-sm">
        <tbody>
          <tr
            v-for="line in lines.lines"
            :key="line.number"
            :class="{ 'bg-highlight': line.is_match }"
          >
            <td
              class="w-px pr-3 text-right align-top whitespace-nowrap text-surface-500 select-none"
            >
              {{ line.number }}
            </td>
            <td class="break-all whitespace-pre-wrap">
              <MarkedSegments :segments="line.segments" /><span
                v-if="line.cut"
                class="text-surface-500"
                title="The line goes on"
                >…</span
              >
            </td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>
