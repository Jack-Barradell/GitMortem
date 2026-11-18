<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import Listbox from "primevue/listbox";
import Message from "primevue/message";
import ProgressBar from "primevue/progressbar";
import SelectButton from "primevue/selectbutton";
import { onBeforeUnmount, reactive, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import FilePicker from "@/components/FilePicker.vue";
import ScanRootBases from "@/components/ScanRootBases.vue";
import { messageFor, shown } from "@/format";
import { IMPORT_TOOLS, REPOSITORY_KINDS } from "@/labels";
import { useSay } from "@/notify";
import { importProblem } from "@/problems";
import { useSession } from "@/stores/session";

type Schemas = components["schemas"];
type Import = Schemas["ImportPageOut.ImportOut"];
type Tool = Schemas["UploadIn"]["tool"];
type Target = Schemas["UploadIn"]["target"];
type Repo = Schemas["RepositoryPageOut.RepositoryOut"];

const emit = defineEmits<{
  changed: [];
  uploading: [id: number | null];
}>();

const PIECE_BYTES = 262_144;
const REPORT_MIB = 256;
const CLIENT_NAME_CHARS = 255;
const NAME_CHARS = 100;
const SERVER_PATH_CHARS = 4096;
const SEARCH_CHARS = 256;
const MATCHES = 20;

const session = useSession();
const say = useSay();
const options = <T extends string>(labels: Record<T, string>) =>
  (Object.entries(labels) as [T, string][]).map(([value, label]) => ({ value, label }));

const tool = ref<Tool | null>(null);
const toolOptions = options(IMPORT_TOOLS);
const source = ref<"upload" | "server">("upload");
const sourceOptions = options({ upload: "Upload a file", server: "A file on the server" });
const targetKind = ref<"known" | "not_on_disk">("known");
const targetOptions = options({
  known: "A repository GitMortem knows",
  not_on_disk: REPOSITORY_KINDS.not_on_disk,
});
const search = ref("");
const matches = ref<Repo[]>([]);
const searched = ref(false);
const searchError = ref("");
const targetId = ref<number | null>(null);
const org = ref("");
const name = ref("");
const serverPath = ref("");
const formError = ref("");
const formNote = ref("");
let finding = 0;

const matchLabel = (repo: Repo): string =>
  repo.kind === "not_on_disk"
    ? `${shown(repo.display_path)} (${REPOSITORY_KINDS.not_on_disk.toLowerCase()})`
    : shown(repo.display_path);

async function find(): Promise<void> {
  const text = search.value;
  const asked = ++finding;
  targetId.value = null;
  searchError.value = "";
  if (text.trim() === "") {
    matches.value = [];
    searched.value = false;
    return;
  }
  try {
    const page = await api<Schemas["RepositoryPageOut"]>(
      `/api/repositories?q=${encodeURIComponent(text)}&per_page=${MATCHES}`,
    );
    if (asked !== finding) return;
    matches.value = page.items;
    searched.value = true;
  } catch (failure) {
    if (asked === finding) searchError.value = messageFor(failure);
  }
}

function target(): Target | null {
  if (targetKind.value === "known") {
    return targetId.value === null ? null : { repository_id: targetId.value };
  }
  if (org.value.trim() === "" || name.value.trim() === "") return null;
  return { org: org.value, name: name.value };
}

let file: File | null = null;
const fileKey = ref(0);
const uploading = ref<{ id: number; sent: number; pieces: number } | null>(null);
let cancelled = false;
let gone = false;
const busy = ref(false);

function pick(chosen: File | null): void {
  file = chosen;
}

function clientName(text: string): string | null {
  const chars = [...text].length;
  return chars >= 1 && chars <= CLIENT_NAME_CHARS && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(text)
    ? text
    : null;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return btoa(binary);
}

function forgetFile(): void {
  file = null;
  fileKey.value += 1;
}

watch(source, forgetFile);

async function upload(chosen: Tool, where: Target, report: File): Promise<void> {
  cancelled = false;
  let made: Import;
  try {
    made = await api<Import>("/api/imports", {
      method: "POST",
      body: {
        tool: chosen,
        target: where,
        client_name: clientName(report.name),
        size_bytes: report.size,
      },
    });
  } catch (failure) {
    if (!gone) formError.value = importProblem(failure);
    return;
  }
  if (gone) return;
  const progress = reactive({ id: made.id, sent: 0, pieces: made.pieces });
  uploading.value = progress;
  emit("uploading", made.id);
  emit("changed");
  try {
    for (let seq = 1; seq <= made.pieces && !cancelled && !gone; seq += 1) {
      const piece = report.slice((seq - 1) * PIECE_BYTES, seq * PIECE_BYTES);
      const data = toBase64(new Uint8Array(await piece.arrayBuffer()));
      if (cancelled || gone) break;
      await api<Import>(`/api/imports/${made.id}/pieces`, { method: "POST", body: { seq, data } });
      progress.sent = seq;
    }
    if (gone) return;
    if (cancelled) {
      formNote.value = "Upload stopped. Discard it below, or upload the file again.";
    } else {
      await api<Import>(`/api/imports/${made.id}/finish`, { method: "POST" });
      if (gone) return;
      say(
        "success",
        "Report uploaded",
        "Its check has started; nothing is recorded until you confirm.",
      );
      forgetFile();
    }
  } catch (failure) {
    if (!gone) formError.value = importProblem(failure);
  } finally {
    if (!gone) {
      uploading.value = null;
      emit("uploading", null);
      emit("changed");
    }
  }
}

function cancelUpload(): void {
  cancelled = true;
}

async function fromServer(chosen: Tool, where: Target): Promise<void> {
  let refused: string | null = null;
  try {
    await api<Import>("/api/imports/server-file", {
      method: "POST",
      body: { tool: chosen, target: where, path: serverPath.value },
    });
  } catch (failure) {
    refused = importProblem(failure);
  }
  if (gone) return;
  if (refused === null) {
    say(
      "success",
      "Import started",
      "Its check reads the file; nothing is recorded until you confirm.",
    );
    serverPath.value = "";
  } else {
    formError.value = refused;
  }
  emit("changed");
}

async function submit(): Promise<void> {
  if (busy.value) return;
  formError.value = "";
  formNote.value = "";
  const where = target();
  if (tool.value === null || where === null) {
    formError.value = "Choose the tool and the repository first.";
    return;
  }
  const chosen = tool.value;
  const server = session.isAdmin && source.value === "server";
  const report = file;
  if (!server && report === null) {
    formError.value = "Choose the report file to upload.";
    return;
  }
  busy.value = true;
  try {
    await (server || report === null ? fromServer(chosen, where) : upload(chosen, where, report));
  } finally {
    busy.value = false;
  }
}

onBeforeUnmount(() => {
  gone = true;
  cancelled = true;
  file = null;
});
</script>

<template>
  <form class="flex max-w-3xl flex-col gap-4" data-test="import-form" @submit.prevent="submit">
    <h2 class="text-sm font-semibold">Import a report</h2>
    <div class="flex flex-col gap-1">
      <span id="import-tool-label" class="text-sm font-medium">Tool that wrote it</span>
      <SelectButton
        v-model="tool"
        :options="toolOptions"
        option-label="label"
        option-value="value"
        :allow-empty="false"
        :disabled="busy"
        aria-labelledby="import-tool-label"
        data-test="import-tool"
      />
    </div>

    <div class="flex flex-col gap-2">
      <span id="target-kind-label" class="text-sm font-medium">Repository it scanned</span>
      <SelectButton
        v-model="targetKind"
        :options="targetOptions"
        option-label="label"
        option-value="value"
        :allow-empty="false"
        :disabled="busy"
        aria-labelledby="target-kind-label"
        data-test="target-kind"
      />
      <template v-if="targetKind === 'known'">
        <div class="flex gap-2">
          <InputText
            id="target-search"
            v-model="search"
            aria-label="Part of the repository's path"
            placeholder="Part of its path"
            autocomplete="off"
            spellcheck="false"
            :maxlength="SEARCH_CHARS"
            class="w-80"
            :disabled="busy"
            data-test="target-search"
            @keydown.enter.prevent="find"
          />
          <Button
            label="Find"
            severity="secondary"
            :disabled="busy"
            data-test="target-find"
            @click="find"
          />
        </div>
        <Listbox
          v-if="matches.length > 0"
          v-model="targetId"
          :options="matches"
          :option-label="matchLabel"
          option-value="id"
          aria-label="Matching repositories"
          class="w-full max-w-xl font-mono"
          :disabled="busy"
          data-test="target-matches"
        />
        <p v-else-if="searched" class="text-sm text-surface-500">
          No repository's path holds that.
        </p>
        <Message v-if="searchError" severity="error" size="small" role="alert">
          {{ searchError }}
        </Message>
      </template>
      <div v-else class="flex flex-wrap gap-4">
        <div class="flex flex-col gap-1">
          <label for="target-org" class="text-sm">Org</label>
          <InputText
            id="target-org"
            v-model="org"
            :maxlength="NAME_CHARS"
            autocomplete="off"
            spellcheck="false"
            :disabled="busy"
          />
        </div>
        <div class="flex flex-col gap-1">
          <label for="target-name" class="text-sm">Name</label>
          <InputText
            id="target-name"
            v-model="name"
            :maxlength="NAME_CHARS"
            autocomplete="off"
            spellcheck="false"
            :disabled="busy"
          />
        </div>
        <p class="w-full text-sm text-surface-500">
          Its findings are built from the report alone: no lines to read and nothing to explore.
          Every import naming the same org and name shares the one repository.
        </p>
      </div>
    </div>

    <div v-if="session.isAdmin" class="flex flex-col gap-1">
      <span id="import-source-label" class="text-sm font-medium">Where the report is</span>
      <SelectButton
        v-model="source"
        :options="sourceOptions"
        option-label="label"
        option-value="value"
        :allow-empty="false"
        :disabled="busy"
        aria-labelledby="import-source-label"
        data-test="import-source"
      />
    </div>

    <div v-if="!session.isAdmin || source === 'upload'" class="flex flex-col gap-1">
      <FilePicker
        :key="fileKey"
        label="Report file"
        action="Choose a report"
        input-id="import-file"
        :disabled="busy"
        test-id="import-file"
        @pick="pick"
      />
      <span class="text-sm text-surface-500"> Max {{ REPORT_MIB }}MB </span>
    </div>
    <div v-else class="flex flex-col gap-1">
      <label for="server-path" class="text-sm font-medium">Path on the server</label>
      <InputText
        id="server-path"
        v-model="serverPath"
        type="text"
        :maxlength="SERVER_PATH_CHARS"
        autocomplete="off"
        spellcheck="false"
        class="w-full font-mono"
      />
      <span class="text-sm text-surface-500">An absolute path inside one of these bases:</span>
      <ScanRootBases none="no file on the server can be imported" />
    </div>

    <div class="flex items-center gap-2">
      <Button type="submit" label="Import" :disabled="busy" data-test="import-submit" />
    </div>
    <div v-if="uploading" class="flex flex-col gap-2" data-test="upload-progress">
      <ProgressBar
        :value="Math.round((100 * uploading.sent) / uploading.pieces)"
        :show-value="false"
        class="h-2"
      />
      <div class="flex items-center gap-2 text-sm">
        <span>{{ uploading.sent }} of {{ uploading.pieces }} pieces sent</span>
        <Button
          label="Cancel upload"
          size="small"
          severity="secondary"
          variant="outlined"
          data-test="upload-cancel"
          @click="cancelUpload"
        />
      </div>
    </div>
    <Message v-if="formError" severity="error" size="small" role="alert" data-test="import-error">
      {{ formError }}
    </Message>
    <Message
      v-if="formNote"
      severity="secondary"
      size="small"
      role="status"
      data-test="import-note"
    >
      {{ formNote }}
    </Message>
  </form>
</template>
