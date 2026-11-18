<script setup lang="ts">
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import SelectButton from "primevue/selectbutton";
import { computed, ref, watch } from "vue";
import { download } from "@/api/client";
import { saveBlob } from "@/download";
import { messageFor } from "@/format";
import { useTriage, type ExportFormat } from "@/stores/triage";

const props = defineProps<{ visible: boolean }>();
const emit = defineEmits<{ close: [] }>();

const triage = useTriage();
const FORMATS: { value: ExportFormat; label: string }[] = [
  { value: "csv", label: "CSV" },
  { value: "xlsx", label: "Excel" },
  { value: "json", label: "JSON" },
  { value: "txt", label: "Text" },
];
const format = ref<ExportFormat>("csv");
const includeValues = ref(true);
const busy = ref(false);
const error = ref("");

watch(
  () => props.visible,
  (shown) => {
    if (shown) {
      includeValues.value = true;
      error.value = "";
    }
  },
);

const what = computed(() => {
  const count = triage.query.view === "unique" ? triage.totalUnique : triage.totalFindings;
  const rows = triage.query.view === "unique" ? "subjects" : "findings";
  return `${count} ${count === 1 ? rows.slice(0, -1) : rows}, as the list shows them now`;
});
const searched = computed(() => triage.query.filters.text !== "" || triage.valueSearch !== null);

async function save(): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    const { blob, filename } = await download(
      "/api/triage/export",
      triage.exportBody(format.value, includeValues.value),
    );
    saveBlob(blob, filename);
    emit("close");
  } catch (failure) {
    error.value = messageFor(failure);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog
    :visible="props.visible"
    modal
    header="Export"
    class="w-full max-w-lg"
    data-test="export-dialog"
    @update:visible="emit('close')"
  >
    <div class="flex flex-col gap-3 text-sm">
      <p data-test="export-what">{{ what }}.</p>
      <p v-if="searched" class="text-surface-500">
        Your search applies too; its text is not written into the file.
      </p>
      <SelectButton
        v-model="format"
        :options="FORMATS"
        option-label="label"
        option-value="value"
        :allow-empty="false"
        aria-label="Format"
        data-test="export-format"
      />
      <label class="flex items-center gap-2">
        <Checkbox
          v-model="includeValues"
          binary
          input-id="export-values"
          data-test="export-values"
        />
        Include values
      </label>
      <Message v-if="includeValues" severity="warn" size="small" data-test="export-values-warning">
        The file will hold the values, live secrets in plain text, on your disk. The export is
        logged with what it carried.
      </Message>
      <ul class="list-disc pl-5 text-surface-500" data-test="export-notes">
        <li>
          CSV and Excel put a <code>'</code> before any cell that starts like a formula, values
          included; JSON and Text keep every value exactly.
        </li>
        <li>
          Excel leaves out a value too long for a cell and says so; JSON and Text keep it whole.
        </li>
        <li v-if="!includeValues" data-test="export-redacted">
          A value GitMortem knows in a commit message is written [value].
        </li>
        <li>Notes go out as written, even without values.</li>
      </ul>
      <Message v-if="error" severity="error" size="small" role="alert" data-test="export-error">{{
        error
      }}</Message>
    </div>
    <template #footer>
      <Button
        label="Cancel"
        severity="secondary"
        text
        data-test="export-cancel"
        @click="emit('close')"
      />
      <Button
        label="Export"
        icon="pi pi-download"
        :loading="busy"
        data-test="export-save"
        @click="save"
      />
    </template>
  </Dialog>
</template>
