<script setup lang="ts">
import { ref } from "vue";
import AccountBlock from "./AccountBlock.vue";
import NavLinks from "./NavLinks.vue";
import { readCollapsed, writeCollapsed } from "./sidebar";

const collapsed = ref(readCollapsed());

function toggle(): void {
  collapsed.value = !collapsed.value;
  writeCollapsed(collapsed.value);
}
</script>

<template>
  <aside
    :class="[
      'sticky top-0 h-screen shrink-0 flex-col border-e border-surface-200 bg-surface-0 dark:border-surface-700 dark:bg-surface-900',
      collapsed ? 'w-16' : 'w-64',
    ]"
  >
    <div :class="['flex h-16 items-center gap-2 px-4', collapsed ? 'justify-center px-2' : '']">
      <span v-if="!collapsed" class="flex min-w-0 flex-1 items-center gap-2">
        <i class="pi pi-key text-primary" aria-hidden="true" />
        <span class="truncate text-base font-semibold tracking-tight">GitMortem</span>
      </span>
      <button
        type="button"
        data-test="collapse-nav"
        :aria-expanded="!collapsed"
        :aria-label="collapsed ? 'Expand the sidebar' : 'Collapse the sidebar'"
        :title="collapsed ? 'Expand the sidebar' : 'Collapse the sidebar'"
        class="flex h-8 w-8 items-center justify-center rounded-md text-surface-500 hover:bg-surface-100 hover:text-surface-900 dark:text-surface-400 dark:hover:bg-surface-800 dark:hover:text-surface-0"
        @click="toggle"
      >
        <i
          :class="collapsed ? 'pi pi-angle-double-right' : 'pi pi-angle-double-left'"
          aria-hidden="true"
        />
      </button>
    </div>
    <div class="min-h-0 flex-1 overflow-y-auto px-2 pb-4">
      <NavLinks :collapsed="collapsed" />
    </div>
    <AccountBlock :collapsed="collapsed" />
  </aside>
</template>
