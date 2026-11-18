<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import { computed, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, shownName } from "@/format";
import { LEFT_REASONS } from "@/labels";
import { reasonOf } from "@/problems";

type Schemas = components["schemas"];
type Preview = Schemas["DeletionPreviewOut"];

const props = defineProps<{ ids: number[]; visible: boolean }>();
const emit = defineEmits<{ "update:visible": [value: boolean]; deleted: [] }>();

const preview = ref<Preview | null>(null);
const typed = ref("");
const busy = ref(false);
const error = ref<string | null>(null);

const confirmed = computed(
  () => preview.value !== null && typed.value.trim() === String(preview.value.repositories),
);

async function load(): Promise<void> {
  preview.value = null;
  typed.value = "";
  try {
    preview.value = await api<Preview>("/api/repositories/deletion-preview", {
      method: "POST",
      body: { ids: props.ids },
    });
  } catch (failure) {
    error.value = messageFor(failure);
  }
}

watch(
  () => [props.visible, props.ids] as const,
  async ([visible]) => {
    if (!visible) return;
    error.value = null;
    await load();
  },
  { immediate: true },
);

async function remove(): Promise<void> {
  if (!confirmed.value || preview.value === null || busy.value) return;
  busy.value = true;
  error.value = null;
  try {
    await api("/api/repositories/delete", {
      method: "POST",
      body: { ids: props.ids, confirm: preview.value.repositories, digest: preview.value.digest },
    });
    emit("deleted");
    emit("update:visible", false);
  } catch (failure) {
    error.value = messageFor(failure);
    if (reasonOf(failure) === "plan_changed") await load();
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    header="Delete repositories"
    class="w-[40rem] max-w-full"
    @update:visible="emit('update:visible', $event)"
  >
    <div class="flex flex-col gap-3" data-test="delete-dialog">
      <p v-if="!preview && !error">Reading what this deletes…</p>
      <template v-if="preview">
        <p data-test="delete-counts">
          This deletes {{ preview.repositories }} repositories, {{ preview.findings }} findings and
          {{ preview.secrets }} secrets found nowhere else, {{ preview.with_triage }} of them with
          statuses or notes. Secrets also found in a repository that is kept keep their triage.
        </p>
        <p v-if="preview.added_nested.length > 0" data-test="delete-nested">
          {{ preview.added_nested.length }} more repositories inside the chosen folders are deleted
          with them.
        </p>
        <Message severity="warn">
          Every copy on disk is deleted, a working copy's uncommitted files included. A scan root
          folder itself is never deleted. This cannot be undone.
        </Message>
        <div v-if="preview.delete_folders.length > 0">
          <p class="text-sm font-semibold">Folders deleted ({{ preview.delete_folders_total }})</p>
          <ul class="max-h-40 overflow-auto font-mono text-xs" data-test="delete-folders">
            <li v-for="folder in preview.delete_folders" :key="folder" class="break-all">
              {{ shownName(folder) }}
            </li>
          </ul>
        </div>
        <div v-if="preview.left.length > 0">
          <p class="text-sm font-semibold">Folders left on disk</p>
          <ul class="max-h-40 overflow-auto text-xs" data-test="delete-left">
            <li v-for="left in preview.left" :key="left.folder" class="break-all">
              <span class="font-mono">{{ shownName(left.folder) }}</span
              >: {{ LEFT_REASONS[left.reason] }}
            </li>
          </ul>
        </div>
        <label class="flex flex-col gap-1">
          <span class="text-sm">Type {{ preview.repositories }} to confirm</span>
          <InputText
            v-model="typed"
            data-test="delete-confirm"
            inputmode="numeric"
            autocomplete="off"
            spellcheck="false"
          />
        </label>
      </template>
      <Message v-if="error" severity="error" data-test="delete-error">{{ error }}</Message>
      <div class="flex justify-end gap-2">
        <Button label="Cancel" severity="secondary" @click="emit('update:visible', false)" />
        <Button
          label="Delete"
          severity="danger"
          data-test="delete-go"
          :disabled="!confirmed || busy"
          @click="remove"
        />
      </div>
    </div>
  </Dialog>
</template>
