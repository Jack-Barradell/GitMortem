<script setup lang="ts">
import Button from "primevue/button";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import Password from "primevue/password";
import { onBeforeUnmount, onMounted, ref } from "vue";
import { api, setPasswordPrompter } from "@/api/client";
import FieldLabel from "@/components/page/FieldLabel.vue";
import { messageFor } from "@/format";

const visible = ref(false);
const password = ref("");
const error = ref("");
const busy = ref(false);
let answer: ((confirmed: boolean) => void) | null = null;

function ask(): Promise<boolean> {
  password.value = "";
  error.value = "";
  visible.value = true;
  return new Promise<boolean>((resolve) => {
    answer = resolve;
  });
}

function settle(confirmed: boolean): void {
  const resolve = answer;
  answer = null;
  visible.value = false;
  password.value = "";
  resolve?.(confirmed);
}

async function submit(): Promise<void> {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    await api<void>("/api/auth/confirm", { method: "POST", body: { password: password.value } });
    settle(true);
  } catch (failure) {
    error.value = messageFor(failure);
    password.value = "";
  } finally {
    busy.value = false;
  }
}

function hidden(open: boolean): void {
  if (!open && answer !== null) settle(false);
}

onMounted(() => setPasswordPrompter(ask));
onBeforeUnmount(() => {
  setPasswordPrompter(() => Promise.resolve(false));
  if (answer !== null) settle(false);
});
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    header="Enter your password"
    class="w-full max-w-sm"
    data-test="password-prompt"
    @update:visible="hidden"
  >
    <form @submit.prevent="submit">
      <p class="mb-4 text-sm text-surface-600 dark:text-surface-300">
        This change needs your password again. It is not asked for again for ten minutes.
      </p>
      <Message v-if="error" severity="error" size="small" class="mb-4" role="alert">
        {{ error }}
      </Message>
      <div class="mb-6 flex flex-col gap-1">
        <FieldLabel for="prompt-password">Password</FieldLabel>
        <Password
          v-model="password"
          input-id="prompt-password"
          :input-props="{ name: 'password', autocomplete: 'current-password', required: true }"
          :feedback="false"
          toggle-mask
          fluid
        />
      </div>
      <div class="flex justify-end gap-2">
        <Button
          type="button"
          label="Cancel"
          severity="secondary"
          variant="outlined"
          @click="settle(false)"
        />
        <Button type="submit" label="Continue" :loading="busy" :disabled="busy" />
      </div>
    </form>
  </Dialog>
</template>
