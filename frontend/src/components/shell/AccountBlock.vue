<script setup lang="ts">
import Button from "primevue/button";
import { useToast } from "primevue/usetoast";
import { useId } from "vue";
import { useRoute, useRouter } from "vue-router";
import { messageFor } from "@/format";
import { ROLE_LABELS } from "@/labels";
import { useSession } from "@/stores/session";
import { currentOf, isUnder } from "./sidebar";
import ThemeToggle from "./ThemeToggle.vue";

defineProps<{ collapsed?: boolean }>();

const session = useSession();
const route = useRoute();
const router = useRouter();
const toast = useToast();
const noteId = useId();

async function signOut(): Promise<void> {
  try {
    await session.logout();
  } catch (failure) {
    toast.add({
      severity: "warn",
      summary: "Sign-out may not have completed",
      detail: messageFor(failure),
      life: 8000,
    });
  }
  await router.push("/login");
}
</script>

<template>
  <nav
    aria-label="Account"
    data-test="account"
    class="flex flex-col gap-2 border-t border-surface-200 px-2 py-3 dark:border-surface-700"
  >
    <div v-if="!collapsed" class="flex items-center justify-between gap-2 px-2">
      <div class="min-w-0">
        <p class="truncate text-sm font-medium">{{ session.user?.username }}</p>
        <p v-if="session.user" class="text-xs text-surface-500 dark:text-surface-400">
          {{ ROLE_LABELS[session.user.role] }}
        </p>
      </div>
      <ThemeToggle />
    </div>
    <ThemeToggle v-else vertical class="mx-auto" />
    <RouterLink
      to="/account"
      :aria-current="currentOf(route.path, '/account')"
      :title="collapsed ? 'Account' : undefined"
      :class="[
        'flex min-h-9 items-center gap-3 rounded-md px-2 py-1.5 text-sm',
        collapsed ? 'justify-center' : '',
        isUnder(route.path, '/account')
          ? 'bg-primary-50 font-medium text-primary-700 dark:bg-primary-950/40 dark:text-primary-300'
          : 'text-surface-700 hover:bg-surface-100 dark:text-surface-200 dark:hover:bg-surface-800',
      ]"
    >
      <i class="pi pi-user text-surface-400 dark:text-surface-500" aria-hidden="true" />
      <span :class="collapsed ? 'sr-only' : ''">Account</span>
    </RouterLink>
    <Button
      :label="collapsed ? undefined : 'Sign out'"
      icon="pi pi-sign-out"
      size="small"
      severity="secondary"
      variant="text"
      :class="collapsed ? '' : 'justify-start'"
      title="Signs you out everywhere"
      aria-label="Sign out"
      :aria-describedby="noteId"
      data-test="sign-out"
      @click="signOut"
    />
    <span :id="noteId" class="sr-only">Signs you out everywhere</span>
  </nav>
</template>
