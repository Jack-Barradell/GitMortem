<script setup lang="ts">
defineProps<{ for: string }>();
</script>

<template>
  <label
    :for="$props.for"
    class="mb-1.5 block text-sm font-semibold text-surface-700 dark:text-surface-300"
  >
    <slot />
  </label>
</template>
