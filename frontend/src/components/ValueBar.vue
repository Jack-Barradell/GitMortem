<script setup lang="ts">
import Button from "primevue/button";
import { onBeforeUnmount, ref, watch } from "vue";
import { copyText } from "@/clipboard";
import ManualCopyDialog from "@/components/ManualCopyDialog.vue";
import { shown } from "@/format";
import { useSay } from "@/notify";

const props = defineProps<{ value: string }>();
const say = useSay();

const manualCopy = ref<string | null>(null);

let generation = 0;

function forget(): void {
  generation += 1;
  manualCopy.value = null;
}

watch(() => props.value, forget);
onBeforeUnmount(forget);

async function copy(): Promise<void> {
  const mine = generation;
  const value = props.value;
  if ((await copyText(value)) === "copied") say("success", "Copied the value");
  else if (mine === generation) manualCopy.value = value;
}
</script>

<template>
  <section class="flex flex-wrap items-center gap-x-4 gap-y-2" aria-label="Value">
    <span class="text-sm font-medium">Value</span>
    <span class="font-mono break-all whitespace-pre-wrap" data-test="value">{{
      shown(props.value)
    }}</span>
    <span class="ml-auto flex gap-2">
      <Button
        label="Copy"
        icon="pi pi-copy"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="copy"
        @click="copy"
      />
    </span>
  </section>
  <ManualCopyDialog :text="manualCopy" :count="1" @close="manualCopy = null" />
</template>
