<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import { ref, watch } from "vue";
import { api, reasonIn, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { importProblem } from "@/problems";

type Removal = components["schemas"]["RemovalOut"];

const props = defineProps<{ importId: number | null; name: string }>();
const emit = defineEmits<{ removed: [counts: Removal]; close: [] }>();

const counts = ref<Removal | null>(null);
const error = ref("");
const removing = ref(false);
let generation = 0;

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

function triaged(found: Removal): string {
  const n = found.with_triage;
  if (n === 0) return "None of them has a status change or a note.";
  return `${n} of them ${n === 1 ? "has" : "have"} a status change or a note, deleted with them.`;
}

async function readCounts(id: number, mine: number): Promise<void> {
  try {
    const found = await api<Removal>(`/api/imports/${id}/removal`);
    if (mine === generation) counts.value = found;
  } catch (failure) {
    if (mine === generation) error.value = importProblem(failure);
  }
}

watch(
  () => props.importId,
  async (id) => {
    const mine = ++generation;
    counts.value = null;
    error.value = "";
    removing.value = false;
    if (id === null) return;
    await readCounts(id, mine);
  },
  { immediate: true },
);

async function remove(): Promise<void> {
  const id = props.importId;
  if (id === null || counts.value === null) return;
  const mine = generation;
  removing.value = true;
  error.value = "";
  try {
    const done = await api<Removal>(`/api/imports/${id}/remove`, {
      method: "POST",
      body: { digest: counts.value.digest },
    });
    if (mine === generation) emit("removed", done);
  } catch (failure) {
    if (mine !== generation) return;
    error.value = importProblem(failure);
    if (failure instanceof ApiError && reasonIn(failure.body) === "removal_changed") {
      counts.value = null;
      await readCounts(id, mine);
    }
  } finally {
    if (mine === generation) removing.value = false;
  }
}
</script>

<template>
  <Dialog
    :visible="props.importId !== null"
    modal
    header="Remove an import"
    class="w-full max-w-lg"
    data-test="removal-dialog"
    @update:visible="emit('close')"
  >
    <div class="flex flex-col gap-3 text-sm">
      <p>
        Removing <span class="font-semibold">{{ props.name }}</span> deletes what no other run saw,
        and its stored report. Its scan stays, listed.
      </p>
      <template v-if="counts">
        <p data-test="removal-counts">
          It deletes {{ plural(counts.findings, "finding", "findings") }} and
          {{ plural(counts.secrets, "secret", "secrets") }}.
        </p>
        <p data-test="removal-triage">{{ triaged(counts) }}</p>
      </template>
      <p v-else-if="!error" class="text-surface-500">Counting what it would delete…</p>
      <Message v-if="error" severity="error" size="small" role="alert" data-test="removal-error">
        {{ error }}
      </Message>
      <div class="flex justify-end gap-2">
        <Button
          label="Cancel"
          severity="secondary"
          variant="outlined"
          data-test="removal-cancel"
          @click="emit('close')"
        />
        <Button
          label="Remove import"
          severity="danger"
          :loading="removing"
          :disabled="counts === null || removing"
          data-test="removal-confirm"
          @click="remove"
        />
      </div>
    </div>
  </Dialog>
</template>
