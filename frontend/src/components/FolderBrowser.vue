<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { computed, onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, shown } from "@/format";
import { ROOT_REFUSALS, ROOT_STATES } from "@/labels";

type Listing = components["schemas"]["RootFoldersOut"];
type Folder = components["schemas"]["RootFoldersOut.RootFolderOut"];

const emit = defineEmits<{ add: [path: string] }>();

const listing = ref<Listing | null>(null);
const error = ref("");
const reading = ref(false);
let asked = 0;

async function read(path: string | null): Promise<void> {
  const mine = (asked += 1);
  reading.value = true;
  error.value = "";
  try {
    const answer = await api<Listing>("/api/scan-roots/folders", {
      method: "POST",
      body: path === null ? {} : { path },
    });
    if (mine === asked) listing.value = answer;
  } catch (failure) {
    if (mine === asked) error.value = messageFor(failure);
  } finally {
    if (mine === asked) reading.value = false;
  }
}

onMounted(() => void read(null));

interface Crumb {
  label: string;
  path: string;
}

const crumbs = computed((): Crumb[] => {
  const at = listing.value;
  if (at === null || at.path === null || at.base === null) return [];
  const separator = at.base.includes("\\") && !at.base.includes("/") ? "\\" : "/";
  const steps: Crumb[] = [{ label: at.base, path: at.base }];
  const rest = at.path
    .slice(at.base.length)
    .split(separator)
    .filter((part) => part !== "");
  let path = at.base;
  for (const part of rest) {
    path = path.endsWith(separator) ? `${path}${part}` : `${path}${separator}${part}`;
    steps.push({ label: part, path });
  }
  return steps;
});

function holds(folder: Folder): string {
  if (!folder.readable) return "Cannot be read";
  if (folder.is_repository === true) return "A repository";
  if (folder.repositories === null) return "Not counted";
  if (folder.repositories === 0) return "No repositories";
  const more = folder.repositories_more ? "+" : "";
  return `${folder.repositories}${more} ${folder.repositories === 1 && !more ? "repository" : "repositories"}`;
}
</script>

<template>
  <div data-test="folder-browser">
    <nav
      aria-label="Folder"
      class="mb-2 flex flex-wrap items-center gap-1 text-sm"
      data-test="folder-crumbs"
    >
      <Button
        label="Bases"
        size="small"
        variant="text"
        severity="secondary"
        data-test="crumb-bases"
        @click="read(null)"
      />
      <template v-for="(crumb, index) in crumbs" :key="crumb.path">
        <span class="text-surface-400" aria-hidden="true">/</span>
        <Button
          :label="shown(crumb.label)"
          size="small"
          variant="text"
          severity="secondary"
          class="font-mono"
          :disabled="index === crumbs.length - 1"
          data-test="crumb"
          @click="read(crumb.path)"
        />
      </template>
    </nav>

    <Message v-if="error" severity="error" size="small" role="alert" data-test="folders-error">
      {{ error }}
    </Message>
    <p v-else-if="reading && listing === null" class="text-sm text-surface-500">
      Reading the folders…
    </p>
    <template v-else-if="listing !== null">
      <p v-if="listing.folders.length === 0" class="text-sm text-surface-500">No folders here.</p>
      <ul class="flex flex-col divide-y divide-surface-200 dark:divide-surface-700">
        <li
          v-for="folder in listing.folders"
          :key="folder.path"
          class="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5"
          data-test="folder"
        >
          <span class="min-w-0 flex-1 font-mono text-sm break-all" data-test="folder-name">{{
            shown(folder.name)
          }}</span>
          <span class="text-sm text-surface-500" data-test="folder-holds">{{ holds(folder) }}</span>
          <Tag
            v-if="ROOT_STATES[folder.root]"
            :value="ROOT_STATES[folder.root] ?? ''"
            severity="secondary"
            data-test="folder-root"
          />
          <Button
            label="Open"
            icon="pi pi-folder-open"
            size="small"
            severity="secondary"
            variant="text"
            :disabled="!folder.readable"
            :aria-label="`Open ${shown(folder.name)}`"
            data-test="folder-open"
            @click="read(folder.path)"
          />
          <Button
            label="Add"
            icon="pi pi-plus"
            size="small"
            severity="secondary"
            variant="outlined"
            :disabled="folder.refusal !== null"
            :title="folder.refusal === null ? 'Add as a scan root' : ROOT_REFUSALS[folder.refusal]"
            :aria-label="`Add ${shown(folder.name)} as a scan root`"
            data-test="folder-add"
            @click="emit('add', folder.path)"
          />
        </li>
      </ul>
      <p
        v-if="listing.truncated"
        class="mt-2 text-sm text-surface-500"
        data-test="folders-truncated"
      >
        Only the first {{ listing.folders.length.toLocaleString("en-US") }} folders are listed.
      </p>
      <p v-if="listing.partial" class="mt-2 text-sm text-surface-500" data-test="folders-partial">
        Some folders were not counted in time.
      </p>
    </template>
  </div>
</template>
