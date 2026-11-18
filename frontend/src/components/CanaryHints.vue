<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import { useConfirm } from "primevue/useconfirm";
import { computed, onBeforeUnmount, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, shown, statusReport } from "@/format";
import { CANARY_FIELDS } from "@/labels";
import { useSay } from "@/notify";
import { askAcross, SpanDeclined, withAcross } from "@/spans";
import type { SecretStatus, Subject } from "@/stores/triage";

type Schemas = components["schemas"];
type Hint = Schemas["FindingOut.CanaryHintOut"];
type StatusOut = Schemas["StatusOut"];

const props = defineProps<{
  subject: Subject;
  hints: Hint[];
  more: boolean;
  unchecked: boolean;
  status: SecretStatus;
  seen: number;
}>();
const emit = defineEmits<{ changed: [result: StatusOut] }>();
const say = useSay();
const confirm = useConfirm();

const planted = computed(() => props.status === "canary");
const asking = ref(props.hints.length > 0 && !planted.value);
const changing = ref(false);
const error = ref("");
let generation = 0;

onBeforeUnmount(() => {
  generation += 1;
});

const reasons = computed(() =>
  props.hints.map((hint) => ({
    key: `${hint.finding_id}:${hint.field}`,
    field: CANARY_FIELDS[hint.field],
    word: hint.word,
    where: `${shown(hint.repo)} · ${shown(hint.display_path)} · ${shown(hint.commit.slice(0, 8))}`,
  })),
);

async function setCanary(): Promise<void> {
  if (changing.value || planted.value) return;
  asking.value = false;
  const at = props.subject;
  const mine = generation;
  changing.value = true;
  error.value = "";
  let result: StatusOut;
  try {
    ({ result } = await withAcross(
      (across) =>
        api<StatusOut>("/api/triage/status", {
          method: "POST",
          body: {
            target: { subjects: [{ kind: at.kind, id: at.id }] },
            status: "canary",
            seen_change_id: props.seen,
            note: null,
            across_repositories: across,
          },
        }),
      (repositories) => askAcross(confirm, repositories),
    ));
  } catch (failure) {
    if (mine === generation) {
      error.value = failure instanceof SpanDeclined ? "" : messageFor(failure);
      changing.value = false;
    }
    return;
  }
  if (mine !== generation) return;
  changing.value = false;
  const report = statusReport(result, "");
  say(report.severity, "Set to Canary", report.detail);
  emit("changed", result);
}
</script>

<template>
  <Message v-if="unchecked" severity="secondary" size="small" data-test="canary-unchecked">
    Its findings were not checked for canary words: there are too many, or GitMortem was busy.
    Reload to try again.
  </Message>
  <template v-if="hints.length > 0">
    <Message severity="info" data-test="canary-banner">
      <div class="flex flex-col gap-2">
        <p class="font-semibold">
          {{ planted ? "Marked as a canary" : "This looks like a canary" }}
        </p>
        <p v-if="!planted" class="text-sm">
          A word your team uses for planted tokens appears where it was found. If it is one of
          yours, set its status to Canary.
        </p>
        <ul class="flex flex-col gap-1 text-sm" data-test="canary-reasons">
          <li v-for="reason in reasons" :key="reason.key" data-test="canary-reason">
            {{ reason.field }} holds "{{ reason.word }}":
            <span class="font-mono break-all">{{ reason.where }}</span>
          </li>
        </ul>
        <p v-if="more" class="text-sm" data-test="canary-more">
          Only the first {{ hints.length }} reasons are listed.
        </p>
        <div v-if="!planted">
          <Button
            label="Set to Canary"
            size="small"
            :loading="changing"
            data-test="canary-set"
            @click="setCanary"
          />
        </div>
        <p v-if="error" class="text-sm" role="alert" data-test="canary-error">{{ error }}</p>
      </div>
    </Message>
    <Dialog
      v-model:visible="asking"
      modal
      header="Possible canary"
      class="w-full max-w-lg"
      data-test="canary-dialog"
    >
      <p class="text-sm">
        A canary word appears where this was found, so it may be a token your team planted.
      </p>
      <ul class="mt-2 flex flex-col gap-1 text-sm">
        <li v-for="reason in reasons.slice(0, 5)" :key="reason.key">
          {{ reason.field }} holds "{{ reason.word }}"
        </li>
      </ul>
      <template #footer>
        <Button
          label="Not now"
          severity="secondary"
          variant="text"
          data-test="canary-dialog-close"
          @click="asking = false"
        />
        <Button label="Set to Canary" data-test="canary-dialog-set" @click="setCanary" />
      </template>
    </Dialog>
  </template>
</template>
