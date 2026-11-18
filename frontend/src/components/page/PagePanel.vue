<script setup lang="ts">
import { useId } from "vue";

withDefaults(defineProps<{ title?: string; flush?: boolean; as?: "section" | "div" }>(), {
  title: undefined,
  as: "section",
});

const headingId = useId();
</script>

<template>
  <component
    :is="as"
    :aria-labelledby="title ? headingId : undefined"
    :class="[
      'rounded-lg bg-surface-0 shadow-sm dark:bg-surface-900',
      flush ? 'overflow-hidden' : 'p-4 sm:p-6',
    ]"
  >
    <div
      v-if="title || $slots.actions"
      :class="[
        'flex flex-wrap items-center justify-between gap-3',
        flush ? 'px-4 pt-4 sm:px-6' : 'mb-4',
      ]"
    >
      <h2
        v-if="title"
        :id="headingId"
        class="text-sm font-semibold text-surface-900 dark:text-surface-50"
      >
        {{ title }}
      </h2>
      <div
        v-if="$slots.actions"
        data-test="panel-actions"
        class="flex flex-wrap items-center gap-2"
      >
        <slot name="actions" />
      </div>
    </div>
    <slot />
  </component>
</template>
