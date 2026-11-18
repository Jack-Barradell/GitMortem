<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import DeleteReposDialog from "@/components/DeleteReposDialog.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import UploadForm from "@/components/UploadForm.vue";
import UploadRepos from "@/components/UploadRepos.vue";
import { messageFor } from "@/format";
import { UPLOAD_FAILURES, UPLOAD_STATES } from "@/labels";
import { useSession } from "@/stores/session";

type Schemas = components["schemas"];
type Upload = Schemas["UploadPageOut.UploadOut"];
type Page = Schemas["UploadPageOut"];
type Detail = Schemas["UploadDetailOut"];

const POLL_MS = 2000;

const session = useSession();
const uploads = ref<Upload[]>([]);
const details = ref<Record<number, Detail>>({});
const open = ref<number | null>(null);
const error = ref<string | null>(null);
let timer: ReturnType<typeof setInterval> | null = null;
const deleteOpen = ref(false);
const deleteIds = computed(() =>
  (opened.value?.repos ?? []).flatMap((r) => (r.repository_id === null ? [] : [r.repository_id])),
);
let gone = false;

const opened = computed(() => (open.value === null ? undefined : details.value[open.value]));
const working = computed(() =>
  uploads.value.some((u) => u.state === "queued" || u.state === "processing"),
);

async function load(): Promise<void> {
  try {
    const page = await api<Page>("/api/uploads?per_page=200", { background: true });
    if (gone) return;
    uploads.value = page.items;
    if (open.value !== null) await show(open.value);
  } catch (failure) {
    if (!gone) error.value = messageFor(failure);
  }
}

async function show(id: number): Promise<void> {
  const detail = await api<Detail>(`/api/uploads/${id}`, { background: true });
  if (!gone) details.value = { ...details.value, [id]: detail };
}

async function toggle(id: number): Promise<void> {
  if (open.value === id) {
    open.value = null;
    return;
  }
  open.value = id;
  try {
    await show(id);
  } catch (failure) {
    error.value = messageFor(failure);
  }
}

async function discard(upload: Upload): Promise<void> {
  try {
    await api(`/api/uploads/${upload.id}/discard`, { method: "POST" });
    await load();
  } catch (failure) {
    error.value = messageFor(failure);
  }
}

const DISCARDABLE: ReadonlySet<Upload["state"]> = new Set([
  "uploading",
  "queued",
  "processing",
  "waiting",
]);

function canDiscard(upload: Upload): boolean {
  return (upload.mine || session.isAdmin) && DISCARDABLE.has(upload.state);
}

onMounted(async () => {
  await load();
  timer = setInterval(() => {
    if (working.value) void load();
  }, POLL_MS);
});
onBeforeUnmount(() => {
  gone = true;
  if (timer !== null) clearInterval(timer);
});
</script>

<template>
  <AppPage title="Uploads">
    <PagePanel title="Upload a zip">
      <UploadForm @changed="load" />
    </PagePanel>
    <Message v-if="error" severity="error">{{ error }}</Message>
    <PagePanel title="Uploads" flush>
      <div class="mt-3 overflow-x-auto">
        <table class="w-full text-sm" data-test="uploads">
          <thead>
            <tr
              class="border-y border-surface-200 bg-surface-50 text-left text-xs font-semibold text-surface-600 dark:border-surface-700 dark:bg-surface-800 dark:text-surface-300"
            >
              <th class="px-4 py-2 sm:px-6">File</th>
              <th class="px-4 py-2">State</th>
              <th class="px-4 py-2">By</th>
              <th class="px-4 py-2">Pieces</th>
              <th class="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="uploads.length === 0">
              <td colspan="5" class="py-6 text-center text-surface-500 dark:text-surface-400">
                No uploads yet.
              </td>
            </tr>
            <template v-for="upload in uploads" :key="upload.id">
              <tr
                data-test="upload-row"
                class="border-b border-surface-100 dark:border-surface-800"
              >
                <td class="px-4 py-2 font-mono break-all sm:px-6">{{ upload.client_name }}</td>
                <td class="px-4 py-2">
                  <span data-test="upload-state">{{ UPLOAD_STATES[upload.state] }}</span>
                  <span v-if="upload.failure" class="text-surface-500 dark:text-surface-400">
                    : {{ UPLOAD_FAILURES[upload.failure] }}
                  </span>
                </td>
                <td class="px-4 py-2">{{ upload.created_by ?? "a removed user" }}</td>
                <td class="px-4 py-2 tabular-nums">
                  {{ upload.pieces_received }} / {{ upload.pieces }}
                </td>
                <td class="px-4 py-2">
                  <div class="flex justify-end gap-2">
                    <Button
                      :label="open === upload.id ? 'Hide' : 'Repositories'"
                      size="small"
                      severity="secondary"
                      variant="outlined"
                      data-test="upload-open"
                      @click="toggle(upload.id)"
                    />
                    <Button
                      v-if="canDiscard(upload)"
                      label="Discard"
                      size="small"
                      severity="danger"
                      variant="text"
                      data-test="upload-discard"
                      @click="discard(upload)"
                    />
                  </div>
                </td>
              </tr>
              <tr
                v-if="open === upload.id && opened"
                class="border-b border-surface-100 bg-surface-50 dark:border-surface-800 dark:bg-surface-800/50"
              >
                <td colspan="5" class="px-4 py-3 sm:px-6">
                  <UploadRepos :upload="opened" @changed="load" />
                  <Button
                    v-if="session.isAdmin && deleteIds.length > 0"
                    label="Delete these repositories"
                    size="small"
                    severity="danger"
                    variant="outlined"
                    class="mt-2"
                    data-test="upload-delete-repos"
                    @click="deleteOpen = true"
                  />
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </PagePanel>
    <DeleteReposDialog
      v-if="session.isAdmin"
      v-model:visible="deleteOpen"
      :ids="deleteIds"
      @deleted="load"
    />
  </AppPage>
</template>
