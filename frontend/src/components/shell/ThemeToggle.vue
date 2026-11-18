<script setup lang="ts">
import { useTheme, type ThemeChoice } from "@/theme";

defineProps<{ vertical?: boolean }>();

const theme = useTheme();

const CHOICES: { choice: ThemeChoice; label: string; icon: string }[] = [
  { choice: "system", label: "Use the system's colours", icon: "pi pi-desktop" },
  { choice: "light", label: "Light", icon: "pi pi-sun" },
  { choice: "dark", label: "Dark", icon: "pi pi-moon" },
];
</script>

<template>
  <div
    data-test="theme"
    role="group"
    aria-label="Colours"
    :class="[
      'inline-flex rounded-md bg-surface-100 p-0.5 dark:bg-surface-800',
      vertical ? 'flex-col' : '',
    ]"
  >
    <button
      v-for="option in CHOICES"
      :key="option.choice"
      type="button"
      :aria-label="option.label"
      :title="option.label"
      :aria-pressed="theme.choice.value === option.choice"
      :class="[
        'flex h-7 w-7 items-center justify-center rounded text-xs',
        theme.choice.value === option.choice
          ? 'bg-surface-0 text-surface-900 shadow-sm dark:bg-surface-700 dark:text-surface-0'
          : 'text-surface-500 hover:text-surface-900 dark:text-surface-400 dark:hover:text-surface-0',
      ]"
      @click="theme.set(option.choice)"
    >
      <i :class="option.icon" aria-hidden="true" />
    </button>
  </div>
</template>
