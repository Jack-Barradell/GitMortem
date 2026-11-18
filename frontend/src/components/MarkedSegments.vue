<script setup lang="ts">
import type { components } from "@/api/schema";
import { shown } from "@/format";

type Segment = components["schemas"]["ContextOut.ContextLineOut"]["segments"][number];

defineProps<{ segments: Segment[] }>();
</script>

<template>
  <template v-for="(segment, index) in segments" :key="index">
    <mark
      v-if="segment.mark === 'own'"
      class="segment-mark-own"
      title="This secret's value"
      data-mark="own"
      >{{ shown(segment.text) }}</mark
    >
    <mark
      v-else-if="segment.mark === 'other'"
      class="segment-mark-other"
      title="Another value found here"
      data-mark="other"
      >{{ shown(segment.text) }}</mark
    >
    <template v-else>{{ shown(segment.text) }}</template>
  </template>
</template>
