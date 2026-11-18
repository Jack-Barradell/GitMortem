<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { groupOf } from "@/components/shell/sidebar";

const props = defineProps<{ title: string; eyebrow?: string; fluid?: boolean }>();

const route = useRoute();
const shownEyebrow = computed(() => props.eyebrow ?? groupOf(route.path));
const width = computed(() => (props.fluid ? "max-w-none" : "max-w-7xl"));
</script>

<template>
  <main class="flex min-w-0 flex-1 flex-col">
    <header class="bg-surface-0 shadow-sm dark:bg-surface-900">
      <div :class="['mx-auto px-4 py-5 sm:px-6 lg:px-8', width]">
        <div class="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
          <div class="min-w-0">
            <p
              v-if="shownEyebrow"
              data-test="eyebrow"
              class="text-xs font-semibold tracking-wide text-surface-500 uppercase dark:text-surface-400"
            >
              {{ shownEyebrow }}
            </p>
            <h1 class="truncate text-2xl font-bold text-surface-900 dark:text-surface-50">
              <slot name="title">{{ title }}</slot>
            </h1>
            <div
              v-if="$slots.summary"
              data-test="page-summary"
              class="mt-1 text-sm text-surface-500 dark:text-surface-400"
            >
              <slot name="summary" />
            </div>
          </div>
          <div
            v-if="$slots.actions"
            data-test="page-actions"
            class="flex flex-wrap items-center gap-2"
          >
            <slot name="actions" />
          </div>
        </div>
      </div>
    </header>
    <div
      data-test="page-body"
      :class="['mx-auto flex w-full flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8', width]"
    >
      <slot />
    </div>
  </main>
</template>
