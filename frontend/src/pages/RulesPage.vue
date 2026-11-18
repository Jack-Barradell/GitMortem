<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Dialog from "primevue/dialog";
import InputText from "primevue/inputtext";
import Message from "primevue/message";
import Textarea from "primevue/textarea";
import ToggleSwitch from "primevue/toggleswitch";
import { useConfirm } from "primevue/useconfirm";
import { confirmFirst } from "@/confirmFirst";
import { nextTick, onMounted, ref, useTemplateRef, watch } from "vue";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import FilePicker from "@/components/FilePicker.vue";
import ManualCopyDialog from "@/components/ManualCopyDialog.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import RuleTester from "@/components/RuleTester.vue";
import { formatTime, messageFor } from "@/format";
import { RULE_REFUSALS } from "@/labels";
import { useSay } from "@/notify";
import { fileRefusals, isRuleRefusal, ruleProblems } from "@/problems";

type Rule = components["schemas"]["RuleOut"];
type RulesFile = components["schemas"]["RulesFileOut"];

const MAX_NAME = 100;
const MAX_DESCRIPTION = 1_000;
const MAX_FILE_BYTES = 1_048_576;
const OVER_ONE_MIB = "That file is over 1 MiB. Import it in parts.";

const say = useSay();
const confirm = useConfirm();

const rules = ref<Rule[]>([]);
const loading = ref(false);
const loadError = ref("");
const switchEpoch = ref(0);
const switching = ref(new Set<number>());

async function load(): Promise<void> {
  loading.value = true;
  try {
    rules.value = await api<Rule[]>("/api/rules");
    loadError.value = "";
  } catch (failure) {
    loadError.value = messageFor(failure);
  } finally {
    loading.value = false;
  }
}

const byId = (list: Rule[]): Rule[] => [...list].sort((a, b) => a.id - b.id);

const formOpen = ref(false);
const editing = ref<Rule | null>(null);
const name = ref("");
const description = ref("");
const pattern = ref("");
const enabled = ref(true);
const formProblems = ref<string[]>([]);
const saving = ref(false);

function openCreate(): void {
  editing.value = null;
  name.value = "";
  description.value = "";
  pattern.value = "";
  enabled.value = true;
  formProblems.value = [];
  formOpen.value = true;
}

function openEdit(rule: Rule): void {
  editing.value = rule;
  name.value = rule.name;
  description.value = rule.description;
  pattern.value = rule.pattern;
  enabled.value = rule.enabled;
  formProblems.value = [];
  formOpen.value = true;
}

function changesTo(
  rule: Rule,
): Partial<Record<"name" | "description" | "pattern" | "enabled", unknown>> {
  const changes: Partial<Record<"name" | "description" | "pattern" | "enabled", unknown>> = {};
  if (name.value !== rule.name) changes.name = name.value;
  if (description.value !== rule.description) changes.description = description.value;
  if (pattern.value !== rule.pattern) changes.pattern = pattern.value;
  if (enabled.value !== rule.enabled) changes.enabled = enabled.value;
  return changes;
}

async function save(): Promise<void> {
  if (saving.value) return;
  const rule = editing.value;
  if (rule !== null && Object.keys(changesTo(rule)).length === 0) {
    formOpen.value = false;
    return;
  }
  saving.value = true;
  formProblems.value = [];
  try {
    if (rule === null) {
      const created = await api<Rule>("/api/rules", {
        method: "POST",
        body: {
          name: name.value,
          description: description.value,
          pattern: pattern.value,
          enabled: enabled.value,
        },
      });
      rules.value = byId([...rules.value, created]);
      say("success", "Rule created", created.name);
    } else {
      const changed = await api<Rule>(`/api/rules/${rule.id}`, {
        method: "PATCH",
        body: changesTo(rule),
      });
      rules.value = rules.value.map((r) => (r.id === changed.id ? changed : r));
      say("success", "Rule saved", changed.name);
    }
    formOpen.value = false;
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 404) {
      formOpen.value = false;
      say("error", "Rule not saved", "That rule no longer exists.");
      await load();
      return;
    }
    formProblems.value = ruleProblems(failure);
  } finally {
    saving.value = false;
  }
}

function askEnabled(rule: Rule, on: boolean): void {
  confirmFirst(confirm, {
    header: `${on ? "Enable" : "Disable"} ${rule.name}?`,
    message: on
      ? "Scans use it from the next scan on."
      : "Scans skip it until it is enabled again.",
    acceptLabel: on ? "Enable" : "Disable",
    danger: !on,
    accept: () => setEnabled(rule, on),
    reject: () => switchEpoch.value++,
  });
}

async function setEnabled(rule: Rule, on: boolean): Promise<void> {
  if (switching.value.has(rule.id)) return;
  switching.value = new Set(switching.value).add(rule.id);
  try {
    const changed = await api<Rule>(`/api/rules/${rule.id}`, {
      method: "PATCH",
      body: { enabled: on },
    });
    rules.value = rules.value.map((r) => (r.id === changed.id ? changed : r));
    say("success", on ? "Rule enabled" : "Rule disabled", changed.name);
  } catch (failure) {
    switchEpoch.value++;
    say("error", "Not changed", ruleProblems(failure).join(" "));
    if (failure instanceof ApiError && failure.status === 404) await load();
  } finally {
    const next = new Set(switching.value);
    next.delete(rule.id);
    switching.value = next;
  }
}

function remove(rule: Rule): void {
  confirm.require({
    header: `Delete ${rule.name}?`,
    message:
      `Its findings keep the id custom:${rule.id}, which no later rule is given. ` +
      "A scan no longer runs it.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Delete",
    rejectLabel: "Cancel",
    acceptProps: { severity: "danger" },
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: async () => {
      try {
        await api<void>(`/api/rules/${rule.id}`, { method: "DELETE" });
        rules.value = rules.value.filter((r) => r.id !== rule.id);
        say("success", "Rule deleted", rule.name);
      } catch (failure) {
        say("error", "Rule not deleted", messageFor(failure));
        await load();
      }
    },
  });
}

const testPattern = ref("");
const tester = useTemplateRef<InstanceType<typeof RuleTester>>("tester");

async function testRule(rule: Rule): Promise<void> {
  testPattern.value = rule.pattern;
  await nextTick();
  tester.value?.focus();
}

const exported = ref<string | null>(null);
const exportedCount = ref(0);
const exporting = ref(false);

async function exportRules(): Promise<void> {
  if (exporting.value) return;
  exporting.value = true;
  try {
    const file = await api<RulesFile>("/api/rules/export", { method: "POST" });
    exportedCount.value = file.rules.length;
    exported.value = JSON.stringify(file, null, 2);
  } catch (failure) {
    say("error", "Rules not exported", messageFor(failure));
  } finally {
    exporting.value = false;
  }
}

function forgetExport(): void {
  exported.value = null;
}

const RULES_FILE_SHAPE =
  '{"format": "gitmortem-rules", "version": 1, "rules": [{"name": …, "pattern": …}]}';

const importOpen = ref(false);
const importText = ref("");
const importProblems = ref<string[]>([]);
const importing = ref(false);
const fileKey = ref(0);

watch(importOpen, (open) => {
  if (!open) importText.value = "";
});

function openImport(): void {
  importText.value = "";
  importProblems.value = [];
  importOpen.value = true;
}

function pickFile(file: File | null): void {
  importProblems.value = [];
  if (file === null) return;
  if (file.size > MAX_FILE_BYTES) {
    importProblems.value = [OVER_ONE_MIB];
    fileKey.value += 1;
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    importText.value = typeof reader.result === "string" ? reader.result : "";
  };
  reader.onerror = () => {
    importProblems.value = ["The file could not be read."];
  };
  reader.readAsText(file);
}

function refusedLines(failure: unknown): string[] {
  const refused = fileRefusals(failure);
  if (refused === null) return [messageFor(failure)];
  return [
    "The file was refused; nothing was imported.",
    ...refused.map((found) => {
      const where = found.index === null ? "The file" : `Entry ${found.index + 1}`;
      return `${where}: ${isRuleRefusal(found.reason) ? RULE_REFUSALS[found.reason] : found.reason}`;
    }),
  ];
}

async function importRules(): Promise<void> {
  if (importing.value) return;
  importProblems.value = [];
  let document: unknown;
  try {
    document = JSON.parse(importText.value);
  } catch {
    importProblems.value = ["The text is not valid JSON."];
    return;
  }
  importing.value = true;
  try {
    const made = await api<Rule[]>("/api/rules/import", { method: "POST", body: document });
    rules.value = byId([...rules.value, ...made]);
    importOpen.value = false;
    say("success", "Rules imported", `${made.length} ${made.length === 1 ? "rule" : "rules"}`);
  } catch (failure) {
    importProblems.value =
      failure instanceof ApiError && failure.status === 413
        ? [OVER_ONE_MIB]
        : refusedLines(failure);
  } finally {
    importing.value = false;
  }
}

onMounted(load);
</script>

<template>
  <AppPage title="Rules">
    <template #actions>
      <Button
        label="Import"
        icon="pi pi-upload"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="import-open"
        @click="openImport"
      />
      <Button
        label="Export"
        icon="pi pi-file-export"
        size="small"
        severity="secondary"
        variant="outlined"
        :loading="exporting"
        :disabled="exporting"
        data-test="export-open"
        @click="exportRules"
      />
      <Button
        label="New rule"
        icon="pi pi-plus"
        size="small"
        data-test="new-rule"
        @click="openCreate"
      />
    </template>

    <Message v-if="loadError" severity="error" size="small" role="alert" data-test="rules-error">
      {{ loadError }}
    </Message>

    <PagePanel flush>
      <DataTable :value="rules" data-key="id" :loading="loading" size="small" striped-rows>
        <template #empty
          ><p class="py-6 text-center text-surface-500 dark:text-surface-400">
            No rules yet. Create one, or import a rules file.
          </p></template
        >
        <Column header="Name">
          <template #body="{ data }">
            <span class="font-semibold">{{ data.name }}</span>
          </template>
        </Column>
        <Column header="Description">
          <template #body="{ data }">
            <span class="text-sm whitespace-pre-line">{{ data.description }}</span>
          </template>
        </Column>
        <Column header="Enabled">
          <template #body="{ data }">
            <ToggleSwitch
              :key="`${data.id}-${switchEpoch}`"
              :model-value="data.enabled"
              :disabled="switching.has(data.id)"
              :aria-label="`Enable ${data.name}`"
              @update:model-value="askEnabled(data, $event)"
            />
          </template>
        </Column>
        <Column header="Last changed">
          <template #body="{ data }">
            <div>{{ formatTime(data.updated_at) }}</div>
            <div v-if="data.updated_by" class="text-xs text-surface-500 dark:text-surface-400">
              by {{ data.updated_by }}
            </div>
          </template>
        </Column>
        <Column header="Actions">
          <template #body="{ data }">
            <div class="flex gap-1">
              <Button
                label="Test"
                size="small"
                severity="secondary"
                variant="text"
                :data-test="`test-rule-${data.id}`"
                @click="testRule(data)"
              />
              <Button
                label="Edit"
                size="small"
                severity="secondary"
                variant="text"
                :data-test="`edit-rule-${data.id}`"
                @click="openEdit(data)"
              />
              <Button
                label="Delete"
                size="small"
                severity="danger"
                variant="text"
                :data-test="`delete-rule-${data.id}`"
                @click="remove(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </PagePanel>

    <PagePanel>
      <RuleTester ref="tester" v-model:pattern="testPattern" />
    </PagePanel>

    <Dialog
      v-model:visible="formOpen"
      modal
      :header="editing === null ? 'New rule' : 'Edit rule'"
      class="w-full max-w-lg"
    >
      <form data-test="rule-form" @submit.prevent="save">
        <Message
          v-if="formProblems.length > 0"
          severity="error"
          size="small"
          class="mb-4"
          role="alert"
          data-test="rule-error"
        >
          <p v-for="problem in formProblems" :key="problem">{{ problem }}</p>
        </Message>
        <div class="mb-4 flex flex-col gap-1">
          <label for="rule-name" class="text-sm font-medium">Name</label>
          <InputText
            id="rule-name"
            v-model="name"
            autocomplete="off"
            spellcheck="false"
            :maxlength="MAX_NAME"
            fluid
          />
        </div>
        <div class="mb-4 flex flex-col gap-1">
          <label for="rule-description" class="text-sm font-medium">Description</label>
          <Textarea
            id="rule-description"
            v-model="description"
            autocomplete="off"
            spellcheck="false"
            :maxlength="MAX_DESCRIPTION"
            :rows="2"
            class="w-full"
          />
        </div>
        <div class="mb-4 flex flex-col gap-1">
          <label for="rule-pattern" class="text-sm font-medium">Pattern</label>
          <Textarea
            id="rule-pattern"
            v-model="pattern"
            autocomplete="off"
            spellcheck="false"
            :rows="5"
            class="w-full font-mono"
          />
        </div>
        <div class="mb-6 flex items-center gap-2">
          <ToggleSwitch v-model="enabled" input-id="rule-enabled" />
          <label for="rule-enabled" class="text-sm font-medium">Enabled</label>
        </div>
        <div class="flex justify-end gap-2">
          <Button
            type="button"
            label="Cancel"
            severity="secondary"
            variant="outlined"
            data-test="rule-cancel"
            @click="formOpen = false"
          />
          <Button
            type="submit"
            :label="editing === null ? 'Create rule' : 'Save rule'"
            :loading="saving"
            :disabled="saving"
            data-test="rule-save"
          />
        </div>
      </form>
    </Dialog>

    <Dialog v-model:visible="importOpen" modal header="Import rules" class="w-full max-w-2xl">
      <form data-test="import-form" @submit.prevent="importRules">
        <p class="text-sm" data-test="import-format">
          A rules file is the JSON that Export writes:
          <code class="font-mono">{{ RULES_FILE_SHAPE }}</code
          >, each rule's description and enabled optional. Every rule is added or none is.
        </p>
        <FilePicker
          :key="fileKey"
          class="mt-3"
          label="Rules file"
          action="Choose a rules file"
          input-id="import-file"
          accept=".json,application/json"
          test-id="import-file"
          @pick="pickFile"
        />
        <div class="mt-3 flex flex-col gap-1">
          <label for="import-text" class="text-sm font-medium">Or paste its JSON</label>
          <Textarea
            id="import-text"
            v-model="importText"
            spellcheck="false"
            autocomplete="off"
            :rows="10"
            class="w-full font-mono"
            data-test="import-text"
          />
        </div>
        <Message
          v-if="importProblems.length > 0"
          severity="error"
          size="small"
          class="mt-3"
          role="alert"
          data-test="import-errors"
        >
          <ul class="max-h-64 overflow-auto">
            <li v-for="(problem, i) in importProblems" :key="i">{{ problem }}</li>
          </ul>
        </Message>
        <div class="mt-4 flex justify-end gap-2">
          <Button
            type="button"
            label="Cancel"
            severity="secondary"
            variant="outlined"
            data-test="import-cancel"
            @click="importOpen = false"
          />
          <Button
            type="submit"
            label="Import"
            :loading="importing"
            :disabled="importing"
            data-test="import-submit"
          />
        </div>
      </form>
    </Dialog>

    <ManualCopyDialog
      :text="exported"
      :count="exportedCount"
      header="Rules file"
      note="Every rule, patterns included, as a rules file. Select it and copy it yourself; closing this forgets it."
      label="Rules file as JSON"
      @close="forgetExport"
    />
  </AppPage>
</template>
