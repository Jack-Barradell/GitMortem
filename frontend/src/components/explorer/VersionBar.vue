<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Select from "primevue/select";
import { computed, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { UPLOAD_REPO_OUTCOMES } from "@/labels";

type Schemas = components["schemas"];
type Version = Schemas["RepositoryOut.VersionOut"];
type Updates = Schemas["UpdatesPageOut"];

const props = defineProps<{
  repositoryId: number;
  versions: Version[];
  version: number | null;
}>();
const emit = defineEmits<{ choose: [version: number | null] }>();

const log = ref<Updates | null>(null);
const showLog = ref(false);
const error = ref<string | null>(null);

function shownDate(at: string): string {
  return new Date(at).toLocaleString();
}

const options = computed(() =>
  props.versions.map((v) => ({
    value: v.current ? null : v.id,
    label: v.current
      ? `Current, uploaded ${shownDate(v.created_at)}`
      : `Uploaded ${shownDate(v.created_at)}`,
  })),
);

async function toggleLog(): Promise<void> {
  showLog.value = !showLog.value;
  if (!showLog.value || log.value !== null) return;
  try {
    log.value = await api<Updates>(`/api/repositories/${props.repositoryId}/updates?per_page=200`);
  } catch (failure) {
    error.value = messageFor(failure);
  }
}
</script>

<template>
  <div class="flex flex-col gap-2" data-test="version-bar">
    <Message v-if="versions.length > 1" severity="warn" data-test="version-notice">
      This repository has {{ versions.length }} versions: a newer upload lacked something an older
      one held, so both are kept. Scans read every version.
    </Message>
    <div class="flex flex-wrap items-center gap-2">
      <label v-if="versions.length > 1" class="flex items-center gap-2 text-sm">
        <span>Version</span>
        <Select
          :model-value="version"
          :options="options"
          option-label="label"
          option-value="value"
          data-test="version-picker"
          @update:model-value="emit('choose', $event)"
        />
      </label>
      <Button
        :label="showLog ? 'Hide update log' : 'Update log'"
        size="small"
        severity="secondary"
        data-test="version-log-toggle"
        @click="toggleLog"
      />
    </div>
    <ul v-if="showLog && log" class="text-sm" data-test="version-log">
      <li v-for="entry in log.items" :key="entry.upload_id">
        {{ shownDate(entry.at) }}: {{ UPLOAD_REPO_OUTCOMES[entry.outcome] }} from
        {{ entry.client_name }}, by {{ entry.by ?? "a removed user" }}
      </li>
    </ul>
    <Message v-if="error" severity="error">{{ error }}</Message>
  </div>
</template>
