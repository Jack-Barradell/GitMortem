<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Textarea from "primevue/textarea";
import { computed } from "vue";

const props = defineProps<{
  text: string | null;
  count: number;
  header?: string;
  note?: string;
  label?: string;
}>();
const emit = defineEmits<{ close: [] }>();

const many = computed(() => props.count !== 1);

function selectAll(event: FocusEvent): void {
  (event.target as HTMLTextAreaElement).select();
}
</script>

<template>
  <Dialog
    :visible="props.text !== null"
    modal
    :header="props.header ?? 'Copy by hand'"
    class="w-full max-w-2xl"
    data-test="manual-copy"
    @update:visible="emit('close')"
  >
    <p v-if="props.note !== undefined" class="text-sm">{{ props.note }}</p>
    <p v-else class="text-sm">
      Your browser did not allow copying from this page.
      <template v-if="many">
        Select the values and copy them yourself; closing this forgets them.
      </template>
      <template v-else>Select the value and copy it yourself; closing this forgets it.</template>
    </p>
    <Textarea
      :model-value="props.text ?? ''"
      readonly
      spellcheck="false"
      autocomplete="off"
      :rows="many ? 8 : 4"
      :aria-label="props.label ?? (many ? 'Values to copy' : 'Value to copy')"
      class="mt-2 w-full font-mono"
      @focus="selectAll"
    />
    <div class="mt-4 flex justify-end">
      <Button label="Close" data-test="close-copy" @click="emit('close')" />
    </div>
  </Dialog>
</template>
