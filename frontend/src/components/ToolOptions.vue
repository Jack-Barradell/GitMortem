<script setup lang="ts">
import Button from "primevue/button";
import InputNumber from "primevue/inputnumber";
import Message from "primevue/message";
import MultiSelect from "primevue/multiselect";
import ToggleSwitch from "primevue/toggleswitch";
import { useConfirm } from "primevue/useconfirm";
import { computed, ref, watch } from "vue";
import { ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { optionLabel, type OptionLabel } from "@/labels";

type Tool = components["schemas"]["ToolListOut.ToolOut"];
type Descriptor = components["schemas"]["OptionDescriptorListOut.OptionDescriptorOut"];
type Value = Tool["options"][string];

const props = defineProps<{
  tool: Tool;
  descriptors: Descriptor[];
  save: (options: Record<string, Value>) => Promise<void>;
  busy?: boolean;
}>();

const confirm = useConfirm();

function start(): Record<string, Value> {
  return Object.fromEntries(
    props.descriptors.map((d) => [d.name, props.tool.options[d.name] ?? d.default]),
  );
}

const form = ref<Record<string, Value | null>>(start());
const problems = ref<string[]>([]);
const sameValue = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
watch(
  () => props.tool.options,
  (now, before) => {
    if (sameValue(now, before)) return;
    form.value = start();
    problems.value = [];
  },
);

const labelOf = (name: string) => optionLabel(name)?.label ?? name;
const helpOf = (name: string) => optionLabel(name)?.help ?? "";

function hidesBy(
  found: OptionLabel | undefined,
  was: Value,
  now: Value | null | undefined,
): boolean {
  if (found === undefined) return !sameValue(was, now);
  const size = (value: Value | null | undefined): number | null =>
    typeof value !== "number" ? null : value === found.noLimit ? Infinity : value;
  switch (found.hidesWhen) {
    case "on":
      return now === true && was !== true;
    case "off":
      return now === false && was !== false;
    case "added":
      return (
        Array.isArray(now) && now.some((item) => !(Array.isArray(was) ? was : []).includes(item))
      );
    case "higher":
    case "lower": {
      const before = size(was);
      const after = size(now);
      if (before === null || after === null) return false;
      return found.hidesWhen === "higher" ? after > before : after < before;
    }
  }
}

const hides = computed(() =>
  props.descriptors.some((d) =>
    hidesBy(optionLabel(d.name), props.tool.options[d.name] ?? d.default, form.value[d.name]),
  ),
);

function reasonsOf(failure: unknown): string[] {
  const body = failure instanceof ApiError ? failure.body : undefined;
  const found =
    typeof body === "object" && body !== null && "detail" in body
      ? (body.detail as { json?: Record<string, unknown> } | null)?.json
      : undefined;
  if (typeof found !== "object" || found === null) return [messageFor(failure)];
  const lines = Object.entries(found).flatMap(([where, messages]) =>
    (Array.isArray(messages) ? messages : []).map(
      (message) => `${labelOf(where.replace(/^options\./, ""))}: ${String(message)}`,
    ),
  );
  return lines.length > 0 ? lines : [messageFor(failure)];
}

async function send(options: Record<string, Value>): Promise<void> {
  problems.value = [];
  try {
    await props.save(options);
  } catch (failure) {
    problems.value = reasonsOf(failure);
  }
}

function complete(): Record<string, Value> | null {
  const empty = props.descriptors.filter((d) => form.value[d.name] === null);
  if (empty.length > 0) {
    problems.value = empty.map((d) => {
      const bounds = d.min !== null && d.max !== null ? ` between ${d.min} and ${d.max}` : "";
      return `${labelOf(d.name)}: enter a number${bounds}.`;
    });
    return null;
  }
  return form.value as Record<string, Value>;
}

function submit(): void {
  if (props.busy) return;
  const options = complete();
  if (options === null) return;
  const whole = { ...options };
  if (!hides.value) {
    void send(whole);
    return;
  }
  confirm.require({
    header: `Hide results from ${props.tool.name}?`,
    message: "This hides results the tool finds. Every change is audited.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Save options",
    rejectLabel: "Cancel",
    acceptProps: { severity: "danger" },
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: () => void send(whole),
  });
}

function setBool(name: string, value: boolean): void {
  form.value = { ...form.value, [name]: value };
}
function setNumber(name: string, value: number | null): void {
  form.value = { ...form.value, [name]: value };
}
function setChoices(name: string, value: string[]): void {
  form.value = { ...form.value, [name]: value };
}
const asNumber = (value: Value | null | undefined): number | null =>
  typeof value === "number" ? value : null;
const asChoices = (value: Value | null | undefined): string[] =>
  Array.isArray(value) ? value : [];
</script>

<template>
  <form class="flex flex-col gap-3" @submit.prevent="submit">
    <div v-for="d in descriptors" :key="d.name" class="flex flex-col gap-1">
      <div v-if="d.kind === 'bool'" class="flex items-center gap-2">
        <ToggleSwitch
          :model-value="form[d.name] === true"
          :input-id="`option-${tool.name}-${d.name}`"
          :data-test="`option-${d.name}`"
          :disabled="busy"
          @update:model-value="setBool(d.name, $event)"
        />
        <label :for="`option-${tool.name}-${d.name}`" class="text-sm font-medium">
          {{ labelOf(d.name) }}
        </label>
      </div>
      <template v-else>
        <label :for="`option-${tool.name}-${d.name}`" class="text-sm font-medium">
          {{ labelOf(d.name) }}
        </label>
        <InputNumber
          v-if="d.kind === 'int' || d.kind === 'float'"
          :model-value="asNumber(form[d.name])"
          :input-id="`option-${tool.name}-${d.name}`"
          :data-test="`option-${d.name}`"
          :min="d.min ?? undefined"
          :max="d.max ?? undefined"
          :min-fraction-digits="0"
          :max-fraction-digits="d.kind === 'float' ? 2 : 0"
          :use-grouping="false"
          :disabled="busy"
          size="small"
          input-class="w-28"
          @update:model-value="setNumber(d.name, $event)"
        />
        <MultiSelect
          v-else
          :model-value="asChoices(form[d.name])"
          :input-id="`option-${tool.name}-${d.name}`"
          :data-test="`option-${d.name}`"
          :options="d.choices ?? []"
          :disabled="busy"
          filter
          :max-selected-labels="3"
          placeholder="None"
          class="w-full max-w-md"
          @update:model-value="setChoices(d.name, $event)"
        />
      </template>
      <p v-if="helpOf(d.name)" class="text-xs text-surface-500">{{ helpOf(d.name) }}</p>
    </div>
    <Message v-if="problems.length > 0" severity="error" size="small" role="alert">
      <p v-for="line in problems" :key="line">{{ line }}</p>
    </Message>
    <div>
      <Button
        type="submit"
        label="Save options"
        size="small"
        severity="secondary"
        variant="outlined"
        :loading="busy"
        :disabled="busy"
      />
    </div>
  </form>
</template>
