<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Textarea from "primevue/textarea";
import { onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { useSay } from "@/notify";

type Words = components["schemas"]["CanaryWordsOut"];

const say = useSay();
const words = ref<Words | null>(null);
const typed = ref("");
const error = ref<string | null>(null);
const busy = ref(false);

function show(found: Words): void {
  words.value = found;
  typed.value = found.words.join("\n");
}

onMounted(async () => {
  try {
    show(await api<Words>("/api/settings/canary-words"));
  } catch (failure) {
    error.value = messageFor(failure);
  }
});

function listed(text: string): string[] {
  return text
    .split("\n")
    .map((word) => word.trim())
    .filter((word) => word !== "");
}

async function save(): Promise<void> {
  if (words.value === null || busy.value) return;
  busy.value = true;
  error.value = null;
  try {
    show(
      await api<Words>("/api/settings/canary-words", {
        method: "PATCH",
        body: { words: listed(typed.value) },
      }),
    );
    say("success", "Canary words saved", "The Secrets list and each secret's page use them now.");
  } catch (failure) {
    error.value = messageFor(failure);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <form class="flex max-w-xl flex-col gap-3" data-test="canary-words" @submit.prevent="save">
    <template v-if="words">
      <p class="text-sm">
        A secret is marked as a possible canary when one of these words appears in its commit
        message, file path, line or author, in any case. Always used:
        <span data-test="canary-built-in">{{ words.built_in.join(", ") }}</span
        >.
      </p>
      <label for="canary-words-own" class="text-sm font-medium">Your own words, one a line</label>
      <Textarea
        id="canary-words-own"
        v-model="typed"
        rows="5"
        spellcheck="false"
        autocomplete="off"
        data-test="canary-words-own"
      />
      <p class="text-xs text-surface-500 dark:text-surface-400">
        Up to {{ words.most }} words, each {{ words.shortest }} to {{ words.longest }} characters.
        They are stored encrypted, and the audit log records only how many there are.
      </p>
      <Button
        type="submit"
        label="Save words"
        class="self-start"
        data-test="canary-words-save"
        :disabled="busy"
      />
    </template>
    <Message v-if="error" severity="error" role="alert">{{ error }}</Message>
  </form>
</template>
