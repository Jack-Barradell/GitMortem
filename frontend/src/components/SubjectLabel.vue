<script setup lang="ts">
import { shown } from "@/format";
import { SUBJECT_KINDS } from "@/labels";
import type { Row, Subject } from "@/stores/triage";

const props = defineProps<{ subject: Subject; row: Row | undefined }>();
</script>

<template>
  <span v-if="props.row" class="flex flex-col">
    <span>
      {{ props.row.org === null ? "" : `${shown(props.row.org)}/` }}{{ shown(props.row.repo_name) }}
    </span>
    <span class="font-mono break-all">{{ shown(props.row.display_path) }}</span>
    <span class="text-surface-500">{{ shown(props.row.kind_label) }}</span>
  </span>
  <span v-else>{{ SUBJECT_KINDS[props.subject.kind] }} {{ props.subject.id }}</span>
</template>
