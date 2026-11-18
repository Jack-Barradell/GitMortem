<script setup lang="ts">
import Message from "primevue/message";
import { onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";

type Bases = components["schemas"]["ScanRootBasesOut"];

const props = withDefaults(defineProps<{ none?: string }>(), { none: "no scan root can be added" });
const bases = ref<string[]>([]);
const loaded = ref(false);
const basesError = ref("");

onMounted(async () => {
  try {
    bases.value = (await api<Bases>("/api/scan-roots/bases")).bases;
  } catch (failure) {
    basesError.value = messageFor(failure);
  } finally {
    loaded.value = true;
  }
});
</script>

<template>
  <Message v-if="basesError" severity="error" size="small" class="mt-2" role="alert">
    {{ basesError }}
  </Message>
  <ul v-else-if="bases.length" class="mt-2 text-sm" data-test="bases">
    <li v-for="base in bases" :key="base" class="font-mono">{{ base }}</li>
  </ul>
  <p v-else-if="loaded" class="mt-2 text-sm" data-test="bases">
    No bases: start GitMortem with <code class="font-mono">--scan-root-base &lt;folder&gt;</code>;
    until then, {{ props.none }}.
  </p>
</template>
