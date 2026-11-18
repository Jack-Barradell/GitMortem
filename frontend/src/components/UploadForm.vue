<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import ProgressBar from "primevue/progressbar";
import { onBeforeUnmount, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import FilePicker from "@/components/FilePicker.vue";
import { messageFor } from "@/format";
import { useSay } from "@/notify";

type Schemas = components["schemas"];
type Upload = Schemas["UploadOut"];
type UploadPage = Schemas["UploadPageOut"];

const props = withDefaults(
  defineProps<{
    retryDelays?: number[];
  }>(),
  { retryDelays: () => [1000, 2000, 4000] },
);
const emit = defineEmits<{
  changed: [];
}>();

const PIECE_BYTES = 262_144;
const NAME_CHARS = 100;

const say = useSay();
const org = ref("");
const fileKey = ref(0);
const busy = ref(false);
const error = ref<string | null>(null);
const progress = ref<{ sent: number; pieces: number } | null>(null);
let file: File | null = null;
let cancelled = false;
let gone = false;
onBeforeUnmount(() => {
  gone = true;
});

function pick(chosen: File | null): void {
  file = chosen;
  error.value = null;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return btoa(binary);
}

function wait(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}

async function send(id: number, seq: number, data: string): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await api<Upload>(`/api/uploads/${id}/pieces`, { method: "POST", body: { seq, data } });
      return;
    } catch (failure) {
      if (attempt >= props.retryDelays.length || cancelled || gone) throw failure;
      await wait(props.retryDelays[attempt] ?? 0);
    }
  }
}

async function resumable(chosen: File): Promise<Upload | null> {
  const page = await api<UploadPage>("/api/uploads?per_page=200");
  return (
    page.items.find(
      (u) =>
        u.mine &&
        u.state === "uploading" &&
        u.client_name === chosen.name &&
        u.size_bytes === chosen.size &&
        u.last_modified_ms === chosen.lastModified,
    ) ?? null
  );
}

async function start(): Promise<void> {
  const chosen = file;
  if (chosen === null || busy.value) return;
  busy.value = true;
  cancelled = false;
  error.value = null;
  try {
    let upload = await resumable(chosen);
    if (upload === null) {
      const typed = org.value.trim();
      upload = await api<Upload>("/api/uploads", {
        method: "POST",
        body: {
          client_name: chosen.name,
          size_bytes: chosen.size,
          last_modified_ms: chosen.lastModified,
          org: typed === "" ? null : typed,
        },
      });
    }
    if (gone) return;
    emit("changed");
    progress.value = { sent: upload.pieces_received, pieces: upload.pieces };
    for (let seq = upload.pieces_received + 1; seq <= upload.pieces; seq += 1) {
      if (cancelled || gone) break;
      const piece = chosen.slice((seq - 1) * PIECE_BYTES, seq * PIECE_BYTES);
      const data = toBase64(new Uint8Array(await piece.arrayBuffer()));
      await send(upload.id, seq, data);
      progress.value = { sent: seq, pieces: upload.pieces };
    }
    if (gone) return;
    if (cancelled) {
      say("warn", "Upload paused", "Pick the same file again to resume it within a day.");
    } else {
      await api<Upload>(`/api/uploads/${upload.id}/finish`, { method: "POST" });
      if (gone) return;
      say("success", "Zip uploaded", "Its repositories are being rebuilt and scanned.");
      file = null;
      fileKey.value += 1;
      progress.value = null;
    }
    emit("changed");
  } catch (failure) {
    if (!gone) error.value = messageFor(failure);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <form class="flex flex-col gap-3" @submit.prevent="start">
    <div class="flex flex-wrap items-end gap-3">
      <FilePicker
        :key="fileKey"
        label="Zip of repositories"
        action="Choose a zip"
        accept=".zip,application/zip"
        :disabled="busy"
        test-id="upload-file"
        @pick="pick"
      />
      <label class="flex flex-col gap-1">
        <span class="text-sm">Org for its repositories (optional)</span>
        <InputText
          v-model="org"
          data-test="upload-org"
          :maxlength="NAME_CHARS"
          spellcheck="false"
          autocomplete="off"
          :disabled="busy"
        />
      </label>
      <Button type="submit" label="Upload" data-test="upload-start" :disabled="busy" />
      <Button
        v-if="busy"
        type="button"
        label="Pause"
        severity="secondary"
        data-test="upload-pause"
        @click="cancelled = true"
      />
    </div>
    <div v-if="progress" data-test="upload-progress" class="flex items-center gap-3">
      <ProgressBar
        class="w-64"
        :value="Math.round((100 * progress.sent) / Math.max(progress.pieces, 1))"
      />
      <span class="text-sm">{{ progress.sent }} of {{ progress.pieces }} pieces</span>
    </div>
    <Message v-if="error" severity="error" data-test="upload-error">{{ error }}</Message>
  </form>
</template>
