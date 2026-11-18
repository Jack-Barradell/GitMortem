<script setup lang="ts">
import ConfirmDialog from "primevue/confirmdialog";
import Toast from "primevue/toast";
import { useRoute } from "vue-router";
import PasswordPrompt from "@/components/PasswordPrompt.vue";
import AppShell from "@/layouts/AppShell.vue";
import { useSession } from "@/stores/session";

const session = useSession();
const route = useRoute();
</script>

<template>
  <Toast />
  <ConfirmDialog class="max-w-lg" />
  <PasswordPrompt />
  <AppShell v-if="session.user && !route.meta.public" />
  <RouterView v-else />
</template>
