<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import InputNumber from "primevue/inputnumber";
import Message from "primevue/message";
import Tag from "primevue/tag";
import ToggleSwitch from "primevue/toggleswitch";
import { useConfirm } from "primevue/useconfirm";
import { onMounted, ref } from "vue";
import { api } from "@/api/client";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import ToolOptions from "@/components/ToolOptions.vue";
import UploadLimits from "@/components/UploadLimits.vue";
import CanaryWords from "@/components/CanaryWords.vue";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { toolStatusLabel, type Severity } from "@/labels";
import { confirmFirst } from "@/confirmFirst";
import { useSay } from "@/notify";

type Tool = components["schemas"]["ToolListOut.ToolOut"];
type ToolSettings = components["schemas"]["ToolSettingsOut"];
type ScanSettings = components["schemas"]["ScanSettingsOut"];
type Descriptor = components["schemas"]["OptionDescriptorListOut.OptionDescriptorOut"];

const TIMEOUT = { min: 10, max: 86400 };
const WORKERS = { min: 1, max: 8 };

const STATUS_SEVERITY: Record<NonNullable<Tool["status"]>, Severity> = {
  found: "success",
  unrecognised: "warn",
  missing: "danger",
  not_executable: "danger",
  shadowed: "danger",
  untested: "warn",
  unsupported: "danger",
  unsafe_folder: "danger",
};

const say = useSay();
const confirm = useConfirm();

const tools = ref<Tool[]>([]);
const toolsError = ref("");
const loading = ref(false);
const timeouts = ref<Record<string, number | null>>({});
const timeoutErrors = ref<Record<string, string>>({});
const switchEpoch = ref(0);
const saving = ref(new Set<string>());

function begin(name: string): boolean {
  if (saving.value.has(name)) return false;
  saving.value = new Set(saving.value).add(name);
  return true;
}

function end(name: string): void {
  const next = new Set(saving.value);
  next.delete(name);
  saving.value = next;
}

const descriptors = ref<Record<string, Descriptor[]>>({});
const descriptorErrors = ref<Record<string, string>>({});

async function loadDescriptors(found: Tool[]): Promise<void> {
  await Promise.all(
    found
      .filter((t) => t.name !== "custom-rules" && descriptors.value[t.name] === undefined)
      .map(async (t) => {
        try {
          const list = await api<Descriptor[]>(`/api/tools/${t.name}/options`);
          descriptors.value = { ...descriptors.value, [t.name]: list };
          descriptorErrors.value = { ...descriptorErrors.value, [t.name]: "" };
        } catch (failure) {
          descriptorErrors.value = { ...descriptorErrors.value, [t.name]: messageFor(failure) };
        }
      }),
  );
}

function show(found: Tool[]): void {
  tools.value = found;
  timeouts.value = Object.fromEntries(found.map((t) => [t.name, t.timeout_seconds]));
  timeoutErrors.value = {};
}

async function loadTools(): Promise<void> {
  loading.value = true;
  try {
    const found = await api<Tool[]>("/api/tools");
    show(found);
    await loadDescriptors(found);
  } catch (failure) {
    toolsError.value = messageFor(failure);
  } finally {
    loading.value = false;
  }
}

const detecting = ref(false);

async function detect(): Promise<void> {
  detecting.value = true;
  try {
    const found = await api<Tool[]>("/api/tools/detect", { method: "POST" });
    show(found);
    toolsError.value = "";
    await loadDescriptors(found);
    say("success", "Detection finished");
  } catch (failure) {
    say("error", "Detection failed", messageFor(failure));
  } finally {
    detecting.value = false;
  }
}

function statusSeverity(tool: Tool): Severity {
  return tool.status === null ? "secondary" : STATUS_SEVERITY[tool.status];
}

function foundVersion(tool: Tool): string | null {
  if (tool.identity === null) return null;
  const prefix = `${tool.name} `;
  return tool.identity.startsWith(prefix) ? tool.identity.slice(prefix.length) : tool.identity;
}

function testedClause(tool: Tool): string {
  return tool.tested_version === null ? "" : ` (tested ${tool.tested_version})`;
}

function reason(tool: Tool): string {
  switch (tool.status) {
    case null:
      return "Not detected yet. Detect again to look for it.";
    case "found":
      return "";
    case "unrecognised":
      return "GitMortem has not measured this build. It runs, but its results are unproven.";
    case "missing":
      return "Not found. The operator names its file with --tool-path at start-up, or puts it on PATH.";
    case "not_executable":
      return "The file cannot be run or read. The operator checks its permissions.";
    case "shadowed":
      return (
        `git's exec-path holds a different ${tool.name}, and git would run that one instead, so ` +
        "this one is refused. The operator removes that copy, or names it with --tool-path."
      );
    case "untested":
      return (
        `Found version ${foundVersion(tool) ?? "unknown"}${testedClause(tool)}. GitMortem has ` +
        "not tested this version. It runs, but its results are unproven."
      );
    case "unsupported":
      return foundVersion(tool) === null
        ? `It reported no version${testedClause(tool)}, or none GitMortem can read, and its ` +
            "version may be older than GitMortem supports, so it is refused. The operator installs " +
            "a supported version."
        : `Found version ${foundVersion(tool)}${testedClause(tool)}, which is older than ` +
            "GitMortem supports, so it is refused. The operator installs a supported version.";
    case "unsafe_folder":
      return (
        "It is in GitMortem's tools folder, which another user owns or others can write, so " +
        "anyone who can change that folder could swap it, and it is refused. The operator " +
        "makes the folder their own and not writable by others, then runs install-scanners."
      );
  }
}

function rulesText(tool: Tool): string {
  const count = tool.enabled_rules ?? 0;
  if (count === 0) return "No rule is enabled, so a scan runs nothing for it.";
  return `${count} ${count === 1 ? "rule" : "rules"} enabled. Each rule has its own switch.`;
}

function replace(saved: ToolSettings): void {
  tools.value = tools.value.map((t) =>
    t.name === saved.name
      ? {
          ...t,
          enabled: saved.enabled,
          timeout_seconds: saved.timeout_seconds,
          options: saved.options,
        }
      : t,
  );
}

async function saveOptions(tool: Tool, options: ToolSettings["options"]): Promise<void> {
  if (!begin(tool.name)) return;
  try {
    replace(
      await api<ToolSettings>(`/api/tools/${tool.name}`, { method: "PATCH", body: { options } }),
    );
    say("success", "Options saved", tool.name);
  } finally {
    end(tool.name);
  }
}

function askEnabled(tool: Tool, enabled: boolean): void {
  confirmFirst(confirm, {
    header: `${enabled ? "Enable" : "Disable"} ${tool.name}?`,
    message: enabled
      ? "Scans run it from the next scan on."
      : "Scans skip it until it is enabled again.",
    acceptLabel: enabled ? "Enable" : "Disable",
    danger: !enabled,
    accept: () => setEnabled(tool, enabled),
    reject: () => switchEpoch.value++,
  });
}

async function setEnabled(tool: Tool, enabled: boolean): Promise<void> {
  if (!begin(tool.name)) return;
  try {
    replace(
      await api<ToolSettings>(`/api/tools/${tool.name}`, { method: "PATCH", body: { enabled } }),
    );
    say("success", enabled ? "Tool enabled" : "Tool disabled", tool.name);
  } catch (failure) {
    switchEpoch.value++;
    say("error", "Not changed", messageFor(failure));
  } finally {
    end(tool.name);
  }
}

async function saveTimeout(tool: Tool): Promise<void> {
  const seconds = timeouts.value[tool.name] ?? null;
  timeoutErrors.value = { ...timeoutErrors.value, [tool.name]: "" };
  if (seconds === null) {
    timeoutErrors.value[tool.name] =
      `Enter a timeout between ${TIMEOUT.min} and ${TIMEOUT.max} seconds.`;
    return;
  }
  if (!begin(tool.name)) return;
  try {
    replace(
      await api<ToolSettings>(`/api/tools/${tool.name}`, {
        method: "PATCH",
        body: { timeout_seconds: seconds },
      }),
    );
    say("success", "Timeout saved", tool.name);
  } catch (failure) {
    timeoutErrors.value[tool.name] = messageFor(failure);
  } finally {
    end(tool.name);
  }
}

const workers = ref<number | null>(null);
const workersLoaded = ref(false);
const workersError = ref("");
const savingWorkers = ref(false);

async function loadWorkers(): Promise<void> {
  try {
    workers.value = (await api<ScanSettings>("/api/settings/scanning")).scan_workers;
    workersLoaded.value = true;
  } catch (failure) {
    say("error", "Scan settings not loaded", messageFor(failure));
  }
}

async function saveWorkers(): Promise<void> {
  workersError.value = "";
  if (workers.value === null) {
    workersError.value = `Enter a number of workers between ${WORKERS.min} and ${WORKERS.max}.`;
    return;
  }
  if (savingWorkers.value) return;
  savingWorkers.value = true;
  try {
    const saved = await api<ScanSettings>("/api/settings/scanning", {
      method: "PATCH",
      body: { scan_workers: workers.value },
    });
    workers.value = saved.scan_workers;
    say("success", "Scan workers saved", String(saved.scan_workers));
  } catch (failure) {
    workersError.value = messageFor(failure);
  } finally {
    savingWorkers.value = false;
  }
}

onMounted(() => Promise.all([loadTools(), loadWorkers()]));
</script>

<template>
  <AppPage title="Tools" fluid>
    <template #actions>
      <Button
        label="Detect again"
        icon="pi pi-refresh"
        size="small"
        :loading="detecting"
        :disabled="detecting"
        data-test="detect"
        @click="detect"
      />
    </template>

    <Message v-if="toolsError" severity="error" size="small" role="alert" data-test="tools-error">
      {{ toolsError }}
    </Message>

    <PagePanel flush>
      <DataTable
        :value="tools"
        data-key="name"
        :loading="loading"
        size="small"
        striped-rows
        scrollable
      >
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No tools to show.
          </p></template
        >
        <Column header="Tool">
          <template #body="{ data }">
            <span class="font-semibold whitespace-nowrap">{{ data.name }}</span>
          </template>
        </Column>
        <Column header="Status">
          <template #body="{ data }">
            <Tag :value="toolStatusLabel(data.status)" :severity="statusSeverity(data)" />
            <p
              v-if="reason(data)"
              class="mt-1 max-w-sm text-sm text-surface-500 dark:text-surface-400"
            >
              {{ reason(data) }}
            </p>
            <p
              v-if="data.name === 'custom-rules'"
              class="mt-1 max-w-sm text-sm text-surface-500 dark:text-surface-400"
              data-test="custom-rules-count"
            >
              {{ rulesText(data) }}
              <RouterLink to="/rules" class="font-medium gm-link" data-test="manage-rules">
                Manage rules
              </RouterLink>
            </p>
          </template>
        </Column>
        <Column header="Build">
          <template #body="{ data }">
            <div>{{ data.identity ?? "–" }}</div>
            <div
              v-if="data.sha256"
              class="font-mono text-xs break-all text-surface-500 dark:text-surface-400"
            >
              SHA-256 {{ data.sha256 }}
            </div>
            <div v-if="data.git_version" class="text-xs text-surface-500 dark:text-surface-400">
              git {{ data.git_version }}
            </div>
          </template>
        </Column>
        <Column header="Path">
          <template #body="{ data }">
            <span class="inline-block min-w-48 font-mono text-sm wrap-anywhere">{{
              data.path ?? "–"
            }}</span>
          </template>
        </Column>
        <Column header="Enabled">
          <template #body="{ data }">
            <ToggleSwitch
              :key="`${data.name}-${switchEpoch}`"
              :model-value="data.enabled"
              :disabled="saving.has(data.name)"
              :aria-label="`Enable ${data.name}`"
              @update:model-value="askEnabled(data, $event)"
            />
          </template>
        </Column>
        <Column>
          <template #header>
            <span
              class="p-datatable-column-title"
              title="Applies to each step of one repository's run"
              data-test="timeout-header"
              >Timeout per repository</span
            >
          </template>
          <template #body="{ data }">
            <form
              class="flex items-center gap-2"
              data-test="timeout-form"
              @submit.prevent="saveTimeout(data)"
            >
              <label :for="`timeout-${data.name}`" class="sr-only">
                Timeout for {{ data.name }}, in seconds
              </label>
              <InputNumber
                v-model="timeouts[data.name]"
                :input-id="`timeout-${data.name}`"
                :min="TIMEOUT.min"
                :max="TIMEOUT.max"
                :use-grouping="false"
                suffix=" s"
                size="small"
                input-class="w-24"
              />
              <Button
                type="submit"
                label="Save"
                size="small"
                severity="secondary"
                variant="outlined"
                :loading="saving.has(data.name)"
                :disabled="saving.has(data.name)"
              />
            </form>
            <Message
              v-if="timeoutErrors[data.name]"
              severity="error"
              size="small"
              class="mt-1"
              role="alert"
            >
              {{ timeoutErrors[data.name] }}
            </Message>
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <PagePanel title="Options">
      <template v-for="t in tools" :key="t.name">
        <div
          v-if="descriptors[t.name] !== undefined"
          class="mt-5 max-w-3xl border-t border-surface-200 pt-4 dark:border-surface-700"
          :data-test="`options-${t.name}`"
        >
          <h3 class="text-sm font-semibold">{{ t.name }}</h3>
          <ToolOptions
            class="mt-2"
            :tool="t"
            :descriptors="descriptors[t.name] ?? []"
            :busy="saving.has(t.name)"
            :save="(options) => saveOptions(t, options)"
          />
        </div>
        <Message
          v-else-if="descriptorErrors[t.name]"
          severity="error"
          size="small"
          class="mt-4"
          role="alert"
          :data-test="`options-error-${t.name}`"
        >
          {{ t.name }}: {{ descriptorErrors[t.name] }}
        </Message>
      </template>
    </PagePanel>

    <div class="grid gap-6 lg:grid-cols-2">
      <PagePanel title="Scan workers">
        <p class="text-sm text-surface-500 dark:text-surface-400">How many tool runs go at once</p>
        <form
          v-if="workersLoaded"
          class="mt-3"
          data-test="workers-form"
          @submit.prevent="saveWorkers"
        >
          <label for="scan-workers" class="sr-only">Scan workers</label>
          <div class="flex items-center gap-2">
            <InputNumber
              v-model="workers"
              input-id="scan-workers"
              :min="WORKERS.min"
              :max="WORKERS.max"
              :use-grouping="false"
              size="small"
              input-class="w-16"
            />
            <Button
              type="submit"
              label="Save"
              size="small"
              severity="secondary"
              variant="outlined"
              :loading="savingWorkers"
              :disabled="savingWorkers"
            />
          </div>
          <Message v-if="workersError" severity="error" size="small" class="mt-2" role="alert">
            {{ workersError }}
          </Message>
        </form>
      </PagePanel>

      <PagePanel title="Upload limits">
        <UploadLimits />
      </PagePanel>

      <PagePanel title="Canary words">
        <CanaryWords />
      </PagePanel>
    </div>
  </AppPage>
</template>
