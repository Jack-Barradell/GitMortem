<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Select from "primevue/select";
import Textarea from "primevue/textarea";
import { useConfirm } from "primevue/useconfirm";
import { onBeforeUnmount, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, statusReport } from "@/format";
import { STATUS_OPTIONS } from "@/labels";
import { MAX_NOTE_CHARS } from "@/notes";
import { useSay } from "@/notify";
import { askAcross, SpanDeclined, withAcross } from "@/spans";
import { subjectKey, type SecretStatus, type Subject } from "@/stores/triage";

type StatusOut = components["schemas"]["StatusOut"];

const props = defineProps<{ subject: Subject; seen: number }>();
const emit = defineEmits<{ changed: [result: StatusOut, noted: boolean] }>();
const say = useSay();
const confirm = useConfirm();

const statusChoice = ref<SecretStatus | null>(null);
const statusNote = ref("");
const statusError = ref("");
const changing = ref(false);

let generation = 0;

function forget(): void {
  generation += 1;
  statusChoice.value = null;
  statusNote.value = "";
  statusError.value = "";
  changing.value = false;
}

watch(() => subjectKey(props.subject), forget);
onBeforeUnmount(forget);

async function changeStatus(): Promise<void> {
  const status = statusChoice.value;
  if (status === null || changing.value) return;
  const at = props.subject;
  const note = statusNote.value;
  const text = note.trim();
  const mine = generation;
  changing.value = true;
  statusError.value = "";
  let result: StatusOut;
  try {
    ({ result } = await withAcross(
      (across) =>
        api<StatusOut>("/api/triage/status", {
          method: "POST",
          body: {
            target: { subjects: [{ kind: at.kind, id: at.id }] },
            status,
            seen_change_id: props.seen,
            note: text === "" ? null : text,
            across_repositories: across,
          },
        }),
      (repositories) => askAcross(confirm, repositories),
    ));
  } catch (failure) {
    if (mine === generation) {
      statusError.value = failure instanceof SpanDeclined ? "" : messageFor(failure);
      changing.value = false;
    }
    return;
  }
  const report = statusReport(result, note);
  say(report.severity, "Status set", report.detail);
  if (mine !== generation) return;
  changing.value = false;
  statusChoice.value = null;
  const noted = text !== "" && result.changed > 0;
  if (result.changed > 0) statusNote.value = "";
  emit("changed", result, noted);
}
</script>

<template>
  <form
    class="mt-4 flex max-w-xl flex-col gap-2"
    data-test="status-form"
    @submit.prevent="changeStatus"
  >
    <div class="flex flex-col gap-1">
      <label id="subject-status-label" for="subject-status" class="text-sm font-medium"
        >Set status</label
      >
      <Select
        v-model="statusChoice"
        input-id="subject-status"
        aria-labelledby="subject-status-label"
        :options="STATUS_OPTIONS"
        option-label="label"
        option-value="value"
        placeholder="Choose a status"
        data-test="status-choice"
      />
    </div>
    <div class="flex flex-col gap-1">
      <label for="subject-status-note" class="text-sm font-medium">Note (optional)</label>
      <Textarea
        id="subject-status-note"
        v-model="statusNote"
        rows="2"
        :maxlength="MAX_NOTE_CHARS"
        spellcheck="false"
        autocomplete="off"
      />
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <Button
        type="submit"
        label="Set status"
        size="small"
        :disabled="statusChoice === null || changing"
        data-test="apply-status"
      />
    </div>
    <Message v-if="statusError" severity="error" size="small" role="alert" data-test="status-error">
      {{ statusError }}
    </Message>
  </form>
</template>
