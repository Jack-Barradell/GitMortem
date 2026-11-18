<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import Password from "primevue/password";
import { ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ApiError } from "@/api/client";
import FieldLabel from "@/components/page/FieldLabel.vue";
import { useSession } from "@/stores/session";

const session = useSession();
const route = useRoute();
const router = useRouter();

const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);

function messageFor(failure: unknown): string {
  if (!(failure instanceof ApiError)) {
    return "Could not reach the server. Check that GitMortem is running.";
  }
  if (failure.status === 429 && failure.retryAfter !== null) {
    const minutes = Math.ceil(failure.retryAfter / 60);
    return `Too many failed attempts. Try again in ${minutes} ${minutes === 1 ? "minute" : "minutes"}.`;
  }
  return failure.message;
}

function safeNext(): string {
  const next = route.query.next;
  if (typeof next !== "string" || !next.startsWith("/") || next.startsWith("//")) return "/secrets";
  return router.resolve(next).meta.public ? "/secrets" : next;
}

async function submit(): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    await session.login(username.value, password.value);
    await router.push(safeNext());
  } catch (failure) {
    error.value = messageFor(failure);
  } finally {
    password.value = "";
    busy.value = false;
  }
}
</script>

<template>
  <main
    class="flex min-h-screen items-center justify-center bg-surface-100 p-4 dark:bg-surface-950"
  >
    <form
      class="w-full max-w-sm rounded-lg bg-surface-0 p-8 shadow-sm dark:bg-surface-900"
      @submit.prevent="submit"
    >
      <p
        data-test="brand"
        class="mb-6 flex items-center gap-2 text-lg font-semibold tracking-tight"
      >
        <i class="pi pi-key text-primary" aria-hidden="true" />
        GitMortem
      </p>
      <h1 class="text-2xl font-bold">Sign in</h1>
      <p class="mt-1 mb-6 text-sm text-surface-500 dark:text-surface-400">
        Sign in to work through exposed secrets.
      </p>

      <Message v-if="error" severity="error" size="small" class="mb-4" role="alert">
        {{ error }}
      </Message>

      <div class="mb-4">
        <FieldLabel for="username">Username</FieldLabel>
        <InputText
          id="username"
          v-model="username"
          name="username"
          autocomplete="username"
          autofocus
          required
          fluid
        />
      </div>
      <div class="mb-6">
        <FieldLabel for="password">Password</FieldLabel>
        <Password
          v-model="password"
          input-id="password"
          :input-props="{ name: 'password', autocomplete: 'current-password', required: true }"
          :feedback="false"
          toggle-mask
          fluid
        />
      </div>
      <Button type="submit" label="Sign in" :loading="busy" :disabled="busy" fluid />
    </form>
  </main>
</template>
