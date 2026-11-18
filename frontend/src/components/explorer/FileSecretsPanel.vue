<script setup lang="ts">
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import Message from "primevue/message";
import Select from "primevue/select";
import Tag from "primevue/tag";
import { useConfirm } from "primevue/useconfirm";
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import StatusSelect from "@/components/StatusSelect.vue";
import { messageFor, shown, statusReport } from "@/format";
import { SECRET_STATUSES, STATUS_OPTIONS } from "@/labels";
import { useSay } from "@/notify";
import { askAcross, SpanDeclined, withAcross } from "@/spans";
import { MAX_OWN_BATCHES, type SecretStatus } from "@/stores/triage";

type Schemas = components["schemas"];
type MarkedSubject = Schemas["FileOut.MarkedSubjectOut"];
type FirstFound = Schemas["FileOut.FirstFoundOut"];
type StatusOut = Schemas["StatusOut"];

interface Undoable {
  previous: Map<string, SecretStatus>;
  bulk: boolean;
}

const props = defineProps<{
  subjects: MarkedSubject[];
  seen: number;
  picked: string | null;
  unchecked: boolean;
  cut: boolean;
  linesUnchecked: boolean;
  dropped: boolean;
}>();

const emit = defineEmits<{
  line: [line: number];
  open: [found: FirstFound];
}>();

const say = useSay();
const confirm = useConfirm();

const statuses = ref(new Map<string, SecretStatus>());
const ownBatches = ref<string[]>([]);
const changing = ref<string | null>(null);
const undoable = ref<Undoable | null>(null);
const ticked = ref(new Set<string>());
const bulkStatus = ref<SecretStatus | null>(null);
const error = ref("");
const entries = new Map<string, HTMLElement>();
const BULK = "bulk";
let generation = 0;

function reset(): void {
  generation += 1;
  statuses.value = new Map(props.subjects.map((s) => [s.key, s.status as SecretStatus]));
  changing.value = null;
  undoable.value = null;
  ticked.value = new Set();
  bulkStatus.value = null;
  error.value = "";
}

watch(() => props.subjects, reset, { immediate: true });
onBeforeUnmount(() => {
  generation += 1;
});

watch(
  () => props.picked,
  async (key) => {
    if (key === null) return;
    await nextTick();
    entries.get(key)?.scrollIntoView({ block: "nearest" });
  },
);

const allTicked = computed(
  () => props.subjects.length > 0 && ticked.value.size === props.subjects.length,
);
const someTicked = computed(() => ticked.value.size > 0 && !allTicked.value);

function statusOf(subject: MarkedSubject): SecretStatus {
  return statuses.value.get(subject.key) ?? (subject.status as SecretStatus);
}

function pagePath(subject: MarkedSubject): string {
  return subject.kind === "secret" ? `/secrets/${subject.id}` : `/findings/${subject.id}`;
}

function held(key: string, element: unknown): void {
  if (element instanceof HTMLElement) entries.set(key, element);
  else entries.delete(key);
}

function tick(subject: MarkedSubject, on: boolean): void {
  const next = new Set(ticked.value);
  if (on) next.add(subject.key);
  else next.delete(subject.key);
  ticked.value = next;
}

function tickAll(on: boolean): void {
  ticked.value = on ? new Set(props.subjects.map((s) => s.key)) : new Set();
}

async function send(
  chosen: MarkedSubject[],
  status: SecretStatus,
  busy: string,
): Promise<StatusOut | null> {
  const mine = generation;
  changing.value = busy;
  error.value = "";
  let result: StatusOut;
  try {
    ({ result } = await withAcross(
      (across) =>
        api<StatusOut>("/api/triage/status", {
          method: "POST",
          body: {
            target: { subjects: chosen.map((s) => ({ kind: s.kind, id: s.id })) },
            status,
            seen_change_id: props.seen,
            own_batches: ownBatches.value,
            note: null,
            across_repositories: across,
          },
        }),
      (repositories) => askAcross(confirm, repositories),
    ));
  } catch (failure) {
    if (mine === generation) {
      error.value = failure instanceof SpanDeclined ? "" : messageFor(failure);
      changing.value = null;
    }
    return null;
  }
  if (mine !== generation) return null;
  changing.value = null;
  const next = new Map(statuses.value);
  const skipped = new Set(result.skipped.map((s) => `${s.kind}:${s.id}`));
  for (const each of result.skipped)
    next.set(`${each.kind}:${each.id}`, each.status as SecretStatus);
  if (result.changed > 0) {
    for (const subject of chosen) if (!skipped.has(subject.key)) next.set(subject.key, status);
    ownBatches.value = [...ownBatches.value, result.batch_id].slice(-MAX_OWN_BATCHES);
  }
  statuses.value = next;
  if (result.skipped_total > 0) {
    const them = chosen.length === 1 ? "it" : "them";
    say(
      "warn",
      "Changed by someone else",
      `Someone changed ${them} after this file was read. Reload the file to change ${them} again.`,
    );
  }
  return result;
}

async function change(subject: MarkedSubject, status: SecretStatus): Promise<void> {
  const previous = statusOf(subject);
  if (status === previous || changing.value !== null) return;
  undoable.value = null;
  const result = await send([subject], status, subject.key);
  if (result === null) return;
  const moved = result.changed > 0 && result.skipped_total === 0;
  undoable.value = moved ? { previous: new Map([[subject.key, previous]]), bulk: false } : null;
  if (result.skipped_total === 0) {
    const report = statusReport(result, "");
    say(report.severity, `Set to ${SECRET_STATUSES[status]}`, report.detail);
  }
}

async function changeTicked(): Promise<void> {
  const status = bulkStatus.value;
  if (status === null || changing.value !== null) return;
  const chosen = props.subjects.filter((s) => ticked.value.has(s.key));
  undoable.value = null;
  const before = new Map(chosen.map((s) => [s.key, statusOf(s)]));
  const result = await send(chosen, status, BULK);
  if (result === null) return;
  const skipped = new Set(result.skipped.map((s) => `${s.kind}:${s.id}`));
  const previous = new Map([...before].filter(([key, was]) => was !== status && !skipped.has(key)));
  undoable.value = result.changed > 0 && previous.size > 0 ? { previous, bulk: true } : null;
  ticked.value = new Set();
  bulkStatus.value = null;
  const report = statusReport(result, "");
  say(report.severity, `Set ${chosen.length} to ${SECRET_STATUSES[status]}`, report.detail);
}

async function undo(): Promise<void> {
  const last = undoable.value;
  if (last === null || changing.value !== null) return;
  undoable.value = null;
  const byStatus = new Map<SecretStatus, MarkedSubject[]>();
  for (const subject of props.subjects) {
    const was = last.previous.get(subject.key);
    if (was !== undefined) byStatus.set(was, [...(byStatus.get(was) ?? []), subject]);
  }
  for (const [status, chosen] of byStatus) {
    const result = await send(chosen, status, BULK);
    if (result === null) return;
  }
  say("success", "Set back");
}
</script>

<template>
  <aside
    class="flex min-w-0 flex-col gap-3"
    aria-label="Secrets in this file"
    data-test="file-secrets"
  >
    <h3 class="text-sm font-semibold">Secrets in this file</h3>
    <p
      v-if="subjects.length === 0 && dropped"
      class="text-sm text-surface-500 dark:text-surface-400"
      data-test="file-secrets-not-looked"
    >
      Known values were not looked for in this file: there were too many.
    </p>
    <p
      v-else-if="subjects.length === 0"
      class="text-sm text-surface-500 dark:text-surface-400"
      data-test="file-secrets-none"
    >
      No known secret appears in this file.
    </p>
    <p
      v-if="cut"
      class="text-sm text-surface-500 dark:text-surface-400"
      data-test="file-secrets-cut"
    >
      Only the first 10,000 are listed.
    </p>
    <p
      v-if="linesUnchecked"
      class="text-sm text-surface-500 dark:text-surface-400"
      data-test="file-secrets-lines-unchecked"
    >
      Secrets found in this file at other commits were not all checked: there were too many.
    </p>
    <Message
      v-if="unchecked && subjects.length > 0"
      severity="secondary"
      size="small"
      data-test="file-secrets-unchecked"
    >
      These were not checked for canary words: they have too many findings, or GitMortem was busy.
      Reload the file to try again.
    </Message>
    <Message v-if="error" severity="error" size="small" role="alert" data-test="file-secrets-error">
      {{ error }}
    </Message>
    <div
      v-if="subjects.length > 0"
      class="flex flex-col gap-2 rounded-md bg-surface-50 p-2 dark:bg-surface-800"
      data-test="file-secrets-bulk"
    >
      <div class="flex items-center gap-2">
        <Checkbox
          binary
          input-id="file-secrets-all"
          :model-value="allTicked"
          :indeterminate="someTicked"
          :disabled="changing !== null"
          data-test="file-secrets-all"
          @update:model-value="tickAll($event)"
        />
        <label for="file-secrets-all" class="text-sm">
          {{ ticked.size > 0 ? `${ticked.size} selected` : "Select all in this file" }}
        </label>
        <Button
          v-if="undoable?.bulk"
          label="Undo"
          text
          size="small"
          class="ml-auto"
          data-test="file-secrets-undo"
          @click="undo"
        />
      </div>
      <div v-if="ticked.size > 0" class="flex flex-wrap items-center gap-2">
        <Select
          v-model="bulkStatus"
          :options="STATUS_OPTIONS"
          option-label="label"
          option-value="value"
          placeholder="Choose a status"
          size="small"
          aria-label="Status for the selected secrets"
          class="min-w-0 flex-1"
          data-test="file-secrets-status"
        />
        <Button
          label="Set status"
          size="small"
          :disabled="bulkStatus === null || changing !== null"
          :loading="changing === BULK"
          data-test="file-secrets-set"
          @click="changeTicked"
        />
      </div>
    </div>
    <ul v-if="subjects.length > 0" class="flex flex-col gap-3">
      <li
        v-for="subject in subjects"
        :key="subject.key"
        :ref="(element) => held(subject.key, element)"
        :class="[
          'flex flex-col gap-1.5 rounded-md border p-2',
          picked === subject.key
            ? 'border-primary-500 ring-1 ring-primary-500'
            : 'border-surface-200 dark:border-surface-700',
        ]"
        :data-key="subject.key"
        data-test="file-subject"
      >
        <div class="flex items-center justify-between gap-2">
          <span class="flex min-w-0 items-center gap-2">
            <Checkbox
              binary
              :model-value="ticked.has(subject.key)"
              :aria-label="`Select ${shown(subject.type)} ${subject.kind} ${subject.id}`"
              :disabled="changing !== null"
              data-test="file-subject-tick"
              @update:model-value="tick(subject, $event)"
            />
            <span class="text-sm font-medium break-all">{{ shown(subject.type) }}</span>
          </span>
          <RouterLink class="gm-link shrink-0 text-sm" :to="pagePath(subject)">Open</RouterLink>
        </div>
        <Tag
          v-if="subject.possible_canary && statusOf(subject) !== 'canary'"
          value="Possible canary"
          severity="info"
          class="self-start"
          title="A canary word appears in its commit message, file path, line or author"
          data-test="file-subject-canary"
        />
        <code class="block truncate font-mono text-xs" data-test="file-subject-value"
          >{{ shown(subject.value) }}{{ subject.value_cut ? "…" : "" }}</code
        >
        <p
          v-if="!subject.in_text"
          class="text-xs text-surface-500 dark:text-surface-400"
          data-test="file-subject-not-as-written"
        >
          Found here, but not as written: decoded or in another form.
        </p>
        <div
          v-if="subject.line !== null || subject.first_found !== null"
          class="flex flex-wrap items-center gap-x-2"
        >
          <Button
            v-if="subject.line !== null"
            :label="`Line ${subject.line}`"
            text
            size="small"
            data-test="file-subject-line"
            @click="emit('line', subject.line)"
          />
          <Button
            v-if="subject.first_found !== null"
            :label="`First found at ${subject.first_found.commit.slice(0, 7)}`"
            :title="subject.first_found.commit"
            text
            size="small"
            data-test="file-subject-first"
            @click="emit('open', subject.first_found)"
          />
        </div>
        <div class="flex items-center gap-2">
          <StatusSelect
            :status="statusOf(subject)"
            :label="`Status of ${shown(subject.type)} ${subject.kind} ${subject.id}`"
            :saving="changing === subject.key"
            :disabled="changing !== null && changing !== subject.key"
            @change="(status) => change(subject, status)"
          />
          <Button
            v-if="undoable && !undoable.bulk && undoable.previous.has(subject.key)"
            label="Undo"
            text
            size="small"
            data-test="file-subject-undo"
            @click="undo"
          />
        </div>
      </li>
    </ul>
  </aside>
</template>
