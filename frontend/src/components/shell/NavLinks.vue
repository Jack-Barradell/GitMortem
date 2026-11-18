<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { useSession } from "@/stores/session";
import { currentOf, isUnder, NAV_GROUPS } from "./sidebar";

const props = defineProps<{ collapsed?: boolean }>();

const session = useSession();
const route = useRoute();

const groups = computed(() => NAV_GROUPS.filter((group) => !group.adminOnly || session.isAdmin));

function linkClass(to: string): string[] {
  const active = isUnder(route.path, to);
  return [
    "flex min-h-9 items-center gap-3 rounded-md px-2 py-1.5 text-sm",
    props.collapsed ? "justify-center" : "",
    active
      ? "bg-primary-50 font-medium text-primary-700 dark:bg-primary-950/40 dark:text-primary-300"
      : "text-surface-700 hover:bg-surface-100 dark:text-surface-200 dark:hover:bg-surface-800",
  ];
}
</script>

<template>
  <nav aria-label="Main" class="flex flex-col gap-1">
    <div v-for="group in groups" :key="group.label" data-test="nav-group" class="flex flex-col">
      <span
        data-test="nav-group-label"
        :class="
          collapsed
            ? 'sr-only'
            : 'px-2 pt-4 pb-1 text-xs font-semibold tracking-wide text-surface-500 uppercase dark:text-surface-400'
        "
      >
        {{ group.label }}
      </span>
      <div v-if="collapsed" class="mx-3 my-2 border-t border-surface-200 dark:border-surface-700" />
      <RouterLink
        v-for="link in group.links"
        :key="link.to"
        :to="link.to"
        :aria-current="currentOf(route.path, link.to)"
        :class="linkClass(link.to)"
        :title="collapsed ? link.label : undefined"
      >
        <i :class="[link.icon, 'text-surface-400 dark:text-surface-500']" aria-hidden="true" />
        <span :class="collapsed ? 'sr-only' : ''">{{ link.label }}</span>
      </RouterLink>
    </div>
  </nav>
</template>
