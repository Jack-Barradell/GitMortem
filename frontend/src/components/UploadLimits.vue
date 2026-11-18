<script setup lang="ts">
import Button from "primevue/button";
import InputNumber from "primevue/inputnumber";
import Message from "primevue/message";
import { onMounted, reactive, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { useSay } from "@/notify";

type Limits = components["schemas"]["UploadLimitsOut"];
type Field = "upload_bytes" | "zip_entries" | "unpacked_bytes" | "ratio" | "import_bytes";

const FIELDS: { field: Field; label: string; unit: number; suffix: string }[] = [
  { field: "upload_bytes", label: "Largest zip", unit: 1 << 30, suffix: "GiB" },
  { field: "zip_entries", label: "Entries in a zip", unit: 1, suffix: "" },
  { field: "unpacked_bytes", label: "Unpacked size of a zip", unit: 1 << 30, suffix: "GiB" },
  { field: "ratio", label: "Unpacked to packed ratio", unit: 1, suffix: ": 1" },
  { field: "import_bytes", label: "Largest imported report", unit: 1 << 20, suffix: "MiB" },
];

const say = useSay();
const limits = ref<Limits | null>(null);
const typed = reactive<Partial<Record<Field, number | null>>>({});
const error = ref<string | null>(null);
const busy = ref(false);

function show(found: Limits): void {
  limits.value = found;
  for (const { field, unit } of FIELDS) typed[field] = Math.floor(found[field] / unit);
}

onMounted(async () => {
  try {
    show(await api<Limits>("/api/settings/uploads"));
  } catch (failure) {
    error.value = messageFor(failure);
  }
});

async function save(): Promise<void> {
  if (limits.value === null || busy.value) return;
  const body: Partial<Record<Field, number>> = {};
  for (const { field, unit } of FIELDS) {
    const value = typed[field];
    if (value !== null && value !== undefined) body[field] = value * unit;
  }
  busy.value = true;
  error.value = null;
  try {
    show(await api<Limits>("/api/settings/uploads", { method: "PATCH", body }));
    say("success", "Upload limits saved", "They apply to the next upload or import.");
  } catch (failure) {
    error.value = messageFor(failure);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <form class="flex flex-col gap-3" data-test="upload-limits" @submit.prevent="save">
    <template v-if="limits">
      <label
        v-for="{ field, label, unit, suffix } in FIELDS"
        :key="field"
        class="flex items-center gap-3"
      >
        <span class="w-56 text-sm">{{ label }}</span>
        <InputNumber
          v-model="typed[field]"
          :data-test="`limit-${field}`"
          :min="1"
          :max="Math.floor(limits.ceilings[field] / unit)"
          :use-grouping="false"
        />
        <span class="text-sm"
          >{{ suffix }} (at most {{ Math.floor(limits.ceilings[field] / unit) }})</span
        >
      </label>
      <Button
        type="submit"
        label="Save limits"
        class="self-start"
        data-test="limits-save"
        :disabled="busy"
      />
    </template>
    <Message v-if="error" severity="error">{{ error }}</Message>
  </form>
</template>
