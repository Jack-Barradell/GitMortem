<script setup lang="ts">
import Drawer from "primevue/drawer";
import { ref, watch } from "vue";
import { useRoute } from "vue-router";
import AccountBlock from "@/components/shell/AccountBlock.vue";
import AppSidebar from "@/components/shell/AppSidebar.vue";
import NavLinks from "@/components/shell/NavLinks.vue";

const route = useRoute();
const drawerOpen = ref(false);

watch(
  () => route.fullPath,
  () => {
    drawerOpen.value = false;
  },
);
</script>

<template>
  <div class="flex min-h-screen">
    <AppSidebar class="hidden lg:flex" />
    <div class="flex min-w-0 flex-1 flex-col">
      <header
        class="flex h-14 items-center gap-3 border-b border-surface-200 bg-surface-0 px-4 lg:hidden dark:border-surface-700 dark:bg-surface-900"
      >
        <button
          type="button"
          data-test="open-nav"
          aria-label="Open navigation"
          class="flex h-10 w-10 items-center justify-center rounded-md text-surface-600 hover:bg-surface-100 dark:text-surface-300 dark:hover:bg-surface-800"
          @click="drawerOpen = true"
        >
          <i class="pi pi-bars" aria-hidden="true" />
        </button>
        <i class="pi pi-key text-primary" aria-hidden="true" />
        <span class="text-base font-semibold tracking-tight">GitMortem</span>
      </header>
      <Drawer v-model:visible="drawerOpen" header="GitMortem" class="!w-72">
        <div class="flex h-full flex-col">
          <div class="flex-1">
            <NavLinks />
          </div>
          <AccountBlock />
        </div>
      </Drawer>
      <RouterView />
    </div>
  </div>
</template>
