<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Password from "primevue/password";
import { useToast } from "primevue/usetoast";
import { ref } from "vue";
import { api, rememberSessionKey } from "@/api/client";
import AppPage from "@/components/page/AppPage.vue";
import FieldLabel from "@/components/page/FieldLabel.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import { messageFor } from "@/format";
import { ROLE_LABELS } from "@/labels";
import { useSession } from "@/stores/session";

const session = useSession();
const toast = useToast();

const current = ref("");
const next = ref("");
const error = ref("");
const busy = ref(false);

async function submit(): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    const changed = await api<{ session_key: string }>("/api/auth/password", {
      method: "POST",
      body: { current_password: current.value, new_password: next.value },
    });
    if (typeof changed?.session_key === "string") rememberSessionKey(changed.session_key);
    session.passwordChanged();
    toast.add({
      severity: "success",
      summary: "Password changed",
      detail: "Your other sessions were signed out.",
      life: 6000,
    });
  } catch (failure) {
    error.value = messageFor(failure);
    toast.add({
      severity: "error",
      summary: "Password not changed",
      detail: error.value,
      life: 6000,
    });
  } finally {
    current.value = "";
    next.value = "";
    busy.value = false;
  }
}
</script>

<template>
  <AppPage title="Account">
    <div class="grid max-w-4xl gap-6 md:grid-cols-[1fr_1.4fr]">
      <PagePanel title="You">
        <dl v-if="session.user" class="grid grid-cols-[7rem_1fr] gap-y-3 text-sm">
          <dt class="text-surface-500 dark:text-surface-400">Username</dt>
          <dd class="font-medium">{{ session.user.username }}</dd>
          <dt class="text-surface-500 dark:text-surface-400">Role</dt>
          <dd>{{ ROLE_LABELS[session.user.role] }}</dd>
        </dl>
      </PagePanel>

      <PagePanel title="Change password">
        <form class="flex flex-col gap-4" @submit.prevent="submit">
          <Message
            v-if="session.user?.must_change_password"
            severity="warn"
            size="small"
            data-test="must-change"
          >
            An admin set your password. Choose a new one before you go on.
          </Message>
          <Message v-if="error" severity="error" size="small" role="alert">
            {{ error }}
          </Message>
          <div>
            <FieldLabel for="current_password">Current password</FieldLabel>
            <Password
              v-model="current"
              input-id="current_password"
              :input-props="{
                name: 'current_password',
                autocomplete: 'current-password',
                required: true,
              }"
              :feedback="false"
              toggle-mask
              fluid
            />
          </div>
          <div>
            <FieldLabel for="new_password">New password</FieldLabel>
            <Password
              v-model="next"
              input-id="new_password"
              :input-props="{
                name: 'new_password',
                autocomplete: 'new-password',
                required: true,
                'aria-describedby': 'new-password-hint',
              }"
              :feedback="false"
              toggle-mask
              fluid
            />
            <small id="new-password-hint" class="mt-1 block text-surface-500 dark:text-surface-400"
              >15–128 characters</small
            >
          </div>
          <div>
            <Button type="submit" label="Change password" :loading="busy" :disabled="busy" />
          </div>
        </form>
      </PagePanel>
    </div>
  </AppPage>
</template>
