<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Tag from "primevue/tag";
import { useConfirm } from "primevue/useconfirm";
import { onMounted, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import AddRootForm from "@/components/AddRootForm.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import ScanRootBases from "@/components/ScanRootBases.vue";
import { formatTime, messageFor } from "@/format";
import { useSay } from "@/notify";

type Root = components["schemas"]["ScanRootOut"];

const say = useSay();
const confirm = useConfirm();

const roots = ref<Root[]>([]);
const loading = ref(false);

async function loadRoots(): Promise<void> {
  loading.value = true;
  try {
    roots.value = await api<Root[]>("/api/scan-roots");
  } catch (failure) {
    say("error", "Scan roots not loaded", messageFor(failure));
  } finally {
    loading.value = false;
  }
}

function remove(root: Root): void {
  confirm.require({
    header: `Remove ${root.path}?`,
    message: "Its repositories and findings are kept, and it can be added again.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Remove",
    rejectLabel: "Cancel",
    acceptProps: { severity: "danger" },
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: async () => {
      try {
        await api<void>(`/api/scan-roots/${root.id}/remove`, { method: "POST" });
        say("success", "Scan root removed", root.path);
      } catch (failure) {
        say("error", "Scan root not removed", messageFor(failure));
      }
      await loadRoots();
    },
  });
}

onMounted(loadRoots);
</script>

<template>
  <AppPage title="Scan roots">
    <div class="grid gap-6 lg:grid-cols-2">
      <PagePanel title="Bases">
        <p class="text-sm text-surface-500 dark:text-surface-400">
          A scan root must be inside one of these.
        </p>
        <ScanRootBases />
      </PagePanel>

      <PagePanel title="Add a scan root">
        <AddRootForm @added="loadRoots" />
      </PagePanel>
    </div>

    <PagePanel flush>
      <DataTable :value="roots" data-key="id" :loading="loading" size="small" striped-rows>
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No scan roots yet.
          </p></template
        >
        <Column header="Path">
          <template #body="{ data }">
            <span class="font-mono text-sm">{{ data.path }}</span>
          </template>
        </Column>
        <Column header="Status">
          <template #body="{ data }">
            <Tag
              :value="data.usable ? 'Usable' : 'Unusable'"
              :severity="data.usable ? 'success' : 'warn'"
            />
            <p v-if="!data.usable" class="mt-1 text-sm text-surface-500 dark:text-surface-400">
              Gone, or no longer inside a base the operator allowed. Discovery and scans refuse it
              until it is back; it is kept.
            </p>
          </template>
        </Column>
        <Column header="Added by">
          <template #body="{ data }">{{ data.added_by ?? "–" }}</template>
        </Column>
        <Column header="Added">
          <template #body="{ data }">
            <time :datetime="data.added_at" class="whitespace-nowrap">
              {{ formatTime(data.added_at) }}
            </time>
          </template>
        </Column>
        <Column header="Actions">
          <template #body="{ data }">
            <Button
              label="Remove"
              :aria-label="`Remove ${data.path}`"
              size="small"
              severity="danger"
              variant="text"
              data-test="remove-root"
              @click="remove(data)"
            />
          </template>
        </Column>
      </DataTable>
    </PagePanel>
  </AppPage>
</template>
