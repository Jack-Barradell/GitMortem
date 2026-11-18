<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import Password from "primevue/password";
import Select from "primevue/select";
import Tag from "primevue/tag";
import InputText from "primevue/inputtext";
import { useConfirm } from "primevue/useconfirm";
import { useToast } from "primevue/usetoast";
import { confirmFirst } from "@/confirmFirst";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { api, resetCsrfToken, type Role } from "@/api/client";
import type { components } from "@/api/schema";
import AppPage from "@/components/page/AppPage.vue";
import FieldLabel from "@/components/page/FieldLabel.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import { formatTime, messageFor } from "@/format";
import { ROLE_LABELS } from "@/labels";
import { useSession } from "@/stores/session";

type User = components["schemas"]["UserOut"];

const ROLES: Role[] = ["analyst", "admin"];
const ROLE_OPTIONS = ROLES.map((role) => ({ value: role, label: ROLE_LABELS[role] }));

const session = useSession();
const router = useRouter();
const toast = useToast();
const confirm = useConfirm();

const users = ref<User[]>([]);
const loading = ref(false);

function say(severity: "success" | "error", summary: string, detail?: string): void {
  toast.add({ severity, summary, detail, life: 6000 });
}

async function load(): Promise<void> {
  loading.value = true;
  try {
    users.value = await api<User[]>("/api/users");
  } catch (failure) {
    say("error", "Users not loaded", messageFor(failure));
  } finally {
    loading.value = false;
  }
}

const isSelf = (user: User): boolean => user.id === session.user?.id;

async function leave(): Promise<void> {
  session.clear();
  resetCsrfToken();
  await router.push("/login");
}

const creating = ref(false);
const newUsername = ref("");
const newPassword = ref("");
const newRole = ref<Role>("analyst");
const createError = ref("");
const createBusy = ref(false);

function startCreate(): void {
  newUsername.value = "";
  newPassword.value = "";
  newRole.value = "analyst";
  createError.value = "";
  creating.value = true;
}

async function create(): Promise<void> {
  createBusy.value = true;
  createError.value = "";
  try {
    await api<User>("/api/users", {
      method: "POST",
      body: { username: newUsername.value, password: newPassword.value, role: newRole.value },
    });
    creating.value = false;
    say("success", "User created", newUsername.value);
    await load();
  } catch (failure) {
    createError.value = messageFor(failure);
  } finally {
    newPassword.value = "";
    createBusy.value = false;
  }
}

const selectEpoch = ref(0);

async function patch(
  user: User,
  body: { role?: Role; is_active?: boolean },
  done: string,
): Promise<boolean> {
  try {
    await api<User>(`/api/users/${user.id}`, { method: "PATCH", body });
    say("success", done, user.username);
    return true;
  } catch (failure) {
    say("error", "Not changed", messageFor(failure));
    return false;
  }
}

async function apply(user: User, body: { role?: Role; is_active?: boolean }, done: string) {
  const ok = await patch(user, body, done);
  if (ok && isSelf(user)) {
    if (body.is_active === false) return leave();
    await session.load();
    return router.push("/account");
  }
  if (!ok) selectEpoch.value++;
  return load();
}

function changeRole(user: User, role: Role): void {
  if (role === user.role) return;
  if (!isSelf(user)) {
    void apply(user, { role }, "Role changed");
    return;
  }
  confirm.require({
    header: "Change your own role?",
    message: "You will lose admin access.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Change role",
    rejectLabel: "Cancel",
    acceptProps: { severity: "danger" },
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: () => apply(user, { role }, "Role changed"),
    reject: () => {
      selectEpoch.value++;
    },
  });
}

function toggleActive(user: User): void {
  if (!user.is_active) {
    confirmFirst(confirm, {
      header: `Activate ${user.username}?`,
      message: "They can sign in again with their password.",
      acceptLabel: "Activate",
      accept: () => apply(user, { is_active: true }, "User activated"),
    });
    return;
  }
  confirmFirst(confirm, {
    header: `Deactivate ${user.username}?`,
    message: isSelf(user)
      ? "You will be signed out. Their sessions end now and they cannot sign in until activated."
      : "Their sessions end now and they cannot sign in until activated.",
    acceptLabel: "Deactivate",
    danger: true,
    accept: () => apply(user, { is_active: false }, "User deactivated"),
  });
}

const resetting = ref<User | null>(null);
const resetPassword = ref("");
const ownPassword = ref("");
const resetError = ref("");
const resetBusy = ref(false);
const resetVisible = computed({
  get: () => resetting.value !== null,
  set: (open: boolean) => {
    if (!open) resetting.value = null;
  },
});

function startReset(user: User): void {
  resetPassword.value = "";
  ownPassword.value = "";
  resetError.value = "";
  resetting.value = user;
}

async function reset(): Promise<void> {
  const target = resetting.value;
  if (target === null) return;
  resetBusy.value = true;
  resetError.value = "";
  try {
    await api<void>(`/api/users/${target.id}/password`, {
      method: "POST",
      body: { current_password: ownPassword.value, new_password: resetPassword.value },
    });
    resetting.value = null;
    say("success", "Password reset", target.username);
    if (isSelf(target)) await leave();
  } catch (failure) {
    resetError.value = messageFor(failure);
  } finally {
    resetPassword.value = "";
    ownPassword.value = "";
    resetBusy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <AppPage title="Users">
    <template #actions>
      <Button
        label="New user"
        icon="pi pi-plus"
        size="small"
        data-test="new-user"
        @click="startCreate"
      />
    </template>

    <PagePanel flush>
      <DataTable
        :value="users"
        data-key="id"
        :loading="loading"
        size="small"
        striped-rows
        scrollable
      >
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No users.
          </p></template
        >
        <Column header="Username">
          <template #body="{ data }">
            <span class="font-medium">{{ data.username }}</span>
            <Tag v-if="isSelf(data)" value="you" severity="secondary" class="ml-2" />
          </template>
        </Column>
        <Column header="Role">
          <template #body="{ data }">
            <Select
              :key="`${data.id}-${selectEpoch}`"
              :model-value="data.role"
              :options="ROLE_OPTIONS"
              option-label="label"
              option-value="value"
              :aria-label="`Role for ${data.username}`"
              size="small"
              @update:model-value="changeRole(data, $event)"
            />
          </template>
        </Column>
        <Column header="Status">
          <template #body="{ data }">
            <Tag
              :value="data.is_active ? 'Active' : 'Deactivated'"
              :severity="data.is_active ? 'success' : 'secondary'"
            />
          </template>
        </Column>
        <Column header="Created">
          <template #body="{ data }">
            <time :datetime="data.created_at" class="whitespace-nowrap">
              {{ formatTime(data.created_at) }}
            </time>
          </template>
        </Column>
        <Column header="Last sign-in">
          <template #body="{ data }">
            <time
              v-if="data.last_login_at"
              :datetime="data.last_login_at"
              class="whitespace-nowrap"
            >
              {{ formatTime(data.last_login_at) }}
            </time>
            <span v-else class="text-surface-500 dark:text-surface-400">Never</span>
          </template>
        </Column>
        <Column header="Actions">
          <template #body="{ data }">
            <div class="flex gap-2">
              <Button
                :label="data.is_active ? 'Deactivate' : 'Activate'"
                :aria-label="`${data.is_active ? 'Deactivate' : 'Activate'} ${data.username}`"
                size="small"
                severity="secondary"
                variant="outlined"
                data-test="toggle-active"
                @click="toggleActive(data)"
              />
              <Button
                label="Reset password"
                :aria-label="`Reset password for ${data.username}`"
                size="small"
                severity="secondary"
                variant="outlined"
                data-test="reset-password"
                @click="startReset(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <Dialog v-model:visible="creating" modal header="New user" class="w-full max-w-sm">
      <form data-test="new-user-form" @submit.prevent="create">
        <Message v-if="createError" severity="error" size="small" class="mb-4" role="alert">
          {{ createError }}
        </Message>
        <div class="mb-4 flex flex-col gap-1">
          <FieldLabel for="new-username">Username</FieldLabel>
          <InputText
            id="new-username"
            v-model="newUsername"
            name="username"
            autocomplete="off"
            required
            fluid
          />
        </div>
        <div class="mb-4 flex flex-col gap-1">
          <FieldLabel for="new-user-password">Password</FieldLabel>
          <Password
            v-model="newPassword"
            input-id="new-user-password"
            :input-props="{ name: 'password', autocomplete: 'new-password', required: true }"
            :feedback="false"
            toggle-mask
            fluid
          />
          <small class="text-surface-500 dark:text-surface-400">15–128 characters</small>
        </div>
        <div class="mb-6 flex flex-col gap-1">
          <FieldLabel for="new-user-role">Role</FieldLabel>
          <Select
            v-model="newRole"
            input-id="new-user-role"
            :options="ROLE_OPTIONS"
            option-label="label"
            option-value="value"
            fluid
          />
        </div>
        <div class="flex justify-end gap-2">
          <Button
            type="button"
            label="Cancel"
            severity="secondary"
            variant="outlined"
            @click="creating = false"
          />
          <Button type="submit" label="Create user" :loading="createBusy" :disabled="createBusy" />
        </div>
      </form>
    </Dialog>

    <Dialog
      v-model:visible="resetVisible"
      modal
      :header="`Reset password for ${resetting?.username ?? ''}`"
      class="w-full max-w-sm"
    >
      <form data-test="reset-form" @submit.prevent="reset">
        <Message v-if="resetting && isSelf(resetting)" severity="warn" size="small" class="mb-4">
          You will be signed out. Sign in again with the new password.
        </Message>
        <Message v-if="resetError" severity="error" size="small" class="mb-4" role="alert">
          {{ resetError }}
        </Message>
        <div class="mb-4 flex flex-col gap-1">
          <FieldLabel for="reset-own-password">Your password</FieldLabel>
          <Password
            v-model="ownPassword"
            input-id="reset-own-password"
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
        <div class="mb-6 flex flex-col gap-1">
          <FieldLabel for="reset-password">New password</FieldLabel>
          <Password
            v-model="resetPassword"
            input-id="reset-password"
            :input-props="{ name: 'new_password', autocomplete: 'new-password', required: true }"
            :feedback="false"
            toggle-mask
            fluid
          />
          <small class="text-surface-500 dark:text-surface-400">15–128 characters</small>
        </div>
        <div class="flex justify-end gap-2">
          <Button
            type="button"
            label="Cancel"
            severity="secondary"
            variant="outlined"
            @click="resetVisible = false"
          />
          <Button type="submit" label="Reset password" :loading="resetBusy" :disabled="resetBusy" />
        </div>
      </form>
    </Dialog>
  </AppPage>
</template>
