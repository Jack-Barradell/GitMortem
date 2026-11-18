<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import { ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { useSay } from "@/notify";
import FolderBrowser from "./FolderBrowser.vue";

type Root = components["schemas"]["ScanRootOut"];

const emit = defineEmits<{ added: [root: Root] }>();
const say = useSay();

const newPath = ref("");
const addError = ref("");
const adding = ref(false);
const browsed = ref(0);

async function add(path: string, typed: boolean): Promise<void> {
  adding.value = true;
  addError.value = "";
  try {
    const root = await api<Root>("/api/scan-roots", {
      method: "POST",
      body: { path },
    });
    if (typed) newPath.value = "";
    browsed.value += 1;
    say("success", "Scan root added", root.path);
    emit("added", root);
  } catch (failure) {
    addError.value = messageFor(failure);
  } finally {
    adding.value = false;
  }
}
</script>

<template>
  <FolderBrowser :key="browsed" class="mb-4" @add="add($event, false)" />
  <form data-test="add-root" @submit.prevent="add(newPath, true)">
    <label
      for="root-path"
      class="mb-1.5 block text-sm font-semibold text-surface-700 dark:text-surface-300"
      >Or type a folder path</label
    >
    <div class="flex gap-2">
      <InputText
        id="root-path"
        v-model="newPath"
        name="path"
        autocomplete="off"
        spellcheck="false"
        required
        class="flex-1 font-mono"
      />
      <Button type="submit" label="Add root" :loading="adding" :disabled="adding" />
    </div>
    <Message v-if="addError" severity="error" size="small" class="mt-2" role="alert">
      {{ addError }}
    </Message>
  </form>
</template>
