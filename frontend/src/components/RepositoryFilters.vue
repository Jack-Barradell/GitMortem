<script setup lang="ts">
import Button from "primevue/button";
import InputText from "primevue/inputtext";
import MultiSelect from "primevue/multiselect";
import Select from "primevue/select";
import { computed, ref } from "vue";
import ChoicePicker from "@/components/ChoicePicker.vue";
import { REPOSITORY_KINDS, REPOSITORY_STATES } from "@/labels";
import { NO_ORG_VALUE, rootOrgs } from "@/pickers";
import {
  anyFilter,
  noFilters,
  SCANNED_CHOICES,
  type RepoFilters,
  type RepoKind,
  type RepoState,
  type Scanned,
} from "@/repositoryFilters";

const props = defineProps<{ modelValue: RepoFilters; root: number }>();
const emit = defineEmits<{ "update:modelValue": [RepoFilters] }>();

function set(patch: Partial<RepoFilters>): void {
  emit("update:modelValue", { ...props.modelValue, ...patch });
}

const NO_ORG = NO_ORG_VALUE;
const orgs = computed(() => rootOrgs(props.root));
const chosenOrgs = computed(() => [
  ...(props.modelValue.noOrg ? [NO_ORG] : []),
  ...props.modelValue.orgs,
]);

function pickOrgs(picked: string[]): void {
  set({ orgs: picked.filter((org) => org !== NO_ORG), noOrg: picked.includes(NO_ORG) });
}

const ROOT_KINDS: RepoKind[] = ["work_tree", "bare"];
const kindOptions = ROOT_KINDS.map((kind) => ({ label: REPOSITORY_KINDS[kind], value: kind }));
const stateOptions = (Object.keys(REPOSITORY_STATES) as RepoState[]).map((state) => ({
  label: REPOSITORY_STATES[state],
  value: state,
}));
const scannedOptions = (Object.keys(SCANNED_CHOICES) as Scanned[]).map((value) => ({
  label: SCANNED_CHOICES[value],
  value,
}));

const open = ref(false);
const anyChosen = computed(() => anyFilter(props.modelValue));
</script>

<template>
  <div role="group" aria-label="Repository filters">
    <button
      type="button"
      class="flex items-center gap-2 rounded-md px-2 py-1 text-sm font-medium text-surface-700 hover:bg-surface-100 lg:hidden dark:text-surface-200 dark:hover:bg-surface-800"
      :aria-expanded="open"
      aria-controls="repo-filters-grid"
      data-test="toggle-repo-filters"
      @click="open = !open"
    >
      <i class="pi pi-filter text-xs" aria-hidden="true" />
      Filters<span v-if="anyChosen" class="text-primary"> in use</span>
      <i
        :class="open ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
        class="text-xs"
        aria-hidden="true"
      />
    </button>
    <div
      id="repo-filters-grid"
      :class="[
        'grid grid-cols-1 items-start gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6',
        open ? 'mt-3 lg:mt-0' : 'hidden lg:grid',
      ]"
    >
      <div class="flex min-w-0 flex-col gap-1 sm:col-span-2">
        <label
          for="repo-search"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Search</label
        >
        <InputText
          id="repo-search"
          :model-value="modelValue.text"
          maxlength="256"
          autocomplete="off"
          spellcheck="false"
          size="small"
          placeholder="Org, name or path"
          class="w-full"
          data-test="repo-search"
          @update:model-value="set({ text: $event ?? '' })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="repo-filter-org"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Org</label
        >
        <ChoicePicker
          :source="orgs"
          input-id="repo-filter-org"
          :model-value="chosenOrgs"
          placeholder="Any org"
          test="repo-filter-org"
          @update:model-value="pickOrgs($event as string[])"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="repo-filter-kind"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Kind</label
        >
        <MultiSelect
          input-id="repo-filter-kind"
          :model-value="modelValue.kinds"
          :options="kindOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="w-full"
          data-test="repo-filter-kind"
          @update:model-value="set({ kinds: $event })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="repo-filter-state"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >State</label
        >
        <MultiSelect
          input-id="repo-filter-state"
          :model-value="modelValue.states"
          :options="stateOptions"
          option-label="label"
          option-value="value"
          placeholder="Any"
          class="w-full"
          data-test="repo-filter-state"
          @update:model-value="set({ states: $event })"
        />
      </div>
      <div class="flex min-w-0 flex-col gap-1">
        <label
          for="repo-filter-scanned"
          class="text-xs font-semibold text-surface-600 dark:text-surface-300"
          >Scanned</label
        >
        <Select
          input-id="repo-filter-scanned"
          :model-value="modelValue.scanned"
          :options="scannedOptions"
          option-label="label"
          option-value="value"
          class="w-full"
          data-test="repo-filter-scanned"
          @update:model-value="set({ scanned: $event as Scanned })"
        />
      </div>
      <Button
        v-if="anyChosen"
        class="self-end justify-self-start"
        label="Clear filters"
        size="small"
        severity="secondary"
        variant="outlined"
        data-test="clear-repo-filters"
        @click="emit('update:modelValue', noFilters())"
      />
    </div>
  </div>
</template>
