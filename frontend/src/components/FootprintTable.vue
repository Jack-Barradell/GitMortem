<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import ContextLines from "@/components/ContextLines.vue";
import MarkedSegments from "@/components/MarkedSegments.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import { formatTime, messageFor, shown } from "@/format";
import {
  EXPLORER_UNAVAILABLE,
  FINDING_PLACES,
  NO_LONGER_REPORTED,
  REPORTED_LIVE,
  REPOSITORY_KINDS,
  TOOLS,
  UNAVAILABLE,
} from "@/labels";
import { subjectPath, type Subject } from "@/stores/triage";

type Schemas = components["schemas"];
type PlacePage = Schemas["FootprintPlacePageOut"];
type Place = PlacePage["items"][number];
type FindingItem = Place["findings"][number];
type FindingOut = Schemas["FindingOut"];
type ToolName = FindingItem["tool"];

const props = defineProps<{
  subject: Subject;
  standalone: FindingOut | null;
  holding: number | null;
}>();
const emit = defineEmits<{ explore: [findingId: number] }>();

const PLACES_PER_PAGE = 20;

const places = ref<Place[]>([]);
const total = ref(0);
const first = ref(0);
const loading = ref(false);
const error = ref("");
const expanded = ref<Record<number, boolean>>({});
const marksDropped = ref(false);

let generation = 0;
let asked = 0;

function placeOf(finding: FindingOut): Place {
  return {
    handle: finding.id,
    repository_id: finding.repository_id,
    repo: finding.repo,
    org: finding.org,
    repository_on_disk: finding.repository_on_disk,
    commit: finding.commit,
    display_path: finding.display_path,
    place: finding.place,
    line: finding.line,
    tools: [finding.tool],
    findings_total: 1,
    findings: [finding],
    no_longer_reported: finding.no_longer_reported,
    reported_live: finding.reported_live,
    first_authored_at: finding.authored_at,
  };
}

watch(
  [() => props.subject.kind, () => props.subject.id, () => props.standalone],
  () => {
    generation += 1;
    places.value = [];
    total.value = 0;
    first.value = 0;
    error.value = "";
    expanded.value = {};
    marksDropped.value = false;
    loading.value = false;
    if (props.standalone !== null) {
      marksDropped.value = props.standalone.marks_dropped;
      places.value = [placeOf(props.standalone)];
      total.value = 1;
      return;
    }
    void load(1, props.holding);
  },
  { immediate: true },
);

async function load(page: number, holding: number | null): Promise<void> {
  const mine = generation;
  const ask = ++asked;
  const current = () => mine === generation && ask === asked;
  const which = holding === null ? `page=${page}` : `finding=${holding}`;
  loading.value = true;
  try {
    const answer = await api<PlacePage>(
      `/api${subjectPath(props.subject)}/places?${which}&per_page=${PLACES_PER_PAGE}`,
    );
    if (!current()) return;
    places.value = answer.items;
    total.value = answer.total;
    marksDropped.value = answer.marks_dropped;
    first.value = (answer.page - 1) * answer.per_page;
    error.value = "";
  } catch (failure) {
    if (current()) error.value = messageFor(failure);
  } finally {
    if (current()) loading.value = false;
  }
}

function onPage(event: DataTablePageEvent): void {
  void load(event.page + 1, null);
}
</script>

<template>
  <div>
    <Message
      v-if="error"
      severity="error"
      size="small"
      class="mt-2"
      role="alert"
      data-test="findings-error"
    >
      {{ error }}
    </Message>
    <MarksDroppedNote v-if="marksDropped" class="mt-2" />
    <DataTable
      v-model:expanded-rows="expanded"
      :value="places"
      data-key="handle"
      lazy
      :paginator="total > PLACES_PER_PAGE"
      :rows="PLACES_PER_PAGE"
      :first="first"
      :total-records="total"
      :loading="loading"
      size="small"
      scrollable
      class="mt-2"
      data-test="footprint"
      @page="onPage"
    >
      <Column expander class="w-12" />
      <Column header="Place">
        <template #body="{ data }">
          <span class="flex flex-col gap-1">
            <span
              v-if="data.place !== 'message'"
              class="inline-block min-w-48 font-mono text-sm wrap-anywhere"
              >{{ shown(data.display_path) }}:{{ data.line }}</span
            >
            <span v-if="data.place !== 'line'" class="text-sm text-surface-500" data-test="place">{{
              FINDING_PLACES[data.place as Place["place"]]
            }}</span>
            <span v-if="data.no_longer_reported || data.reported_live" class="flex flex-wrap gap-1">
              <Tag
                v-if="data.no_longer_reported"
                :value="NO_LONGER_REPORTED"
                severity="secondary"
                data-test="place-no-longer"
              />
              <Tag
                v-if="data.reported_live"
                :value="REPORTED_LIVE"
                severity="danger"
                data-test="place-live"
              />
            </span>
          </span>
        </template>
      </Column>
      <Column header="Repository">
        <template #body="{ data }">
          <span class="flex flex-col gap-1">
            <span>{{ shown(data.repo) }}</span>
            <span
              v-if="!data.repository_on_disk"
              class="text-sm text-surface-500"
              data-test="not-on-disk"
              >{{ REPOSITORY_KINDS.not_on_disk }}</span
            >
          </span>
        </template>
      </Column>
      <Column header="Commit">
        <template #body="{ data }">
          <span class="font-mono" :title="shown(data.commit)">{{
            shown(data.commit.slice(0, 12))
          }}</span>
        </template>
      </Column>
      <Column header="Authored">
        <template #body="{ data }">
          <time
            v-if="data.first_authored_at"
            :datetime="data.first_authored_at"
            class="whitespace-nowrap"
          >
            {{ formatTime(data.first_authored_at) }}
          </time>
          <span v-else class="text-surface-500">unknown</span>
        </template>
      </Column>
      <Column header="Message">
        <template #body="{ data }">
          <span v-if="data.findings[0]?.commit_message == null" class="text-surface-500"
            >unknown</span
          >
          <span
            v-else-if="data.findings[0].commit_message.length === 0"
            class="text-surface-500"
            data-test="message-subject"
            >No message</span
          >
          <span v-else data-test="message-subject"
            ><MarkedSegments :segments="data.findings[0].commit_message[0]?.segments ?? []"
          /></span>
        </template>
      </Column>
      <Column header="Repository content">
        <template #body="{ data }">
          <span
            v-if="!data.repository_on_disk"
            class="block max-w-xs text-sm text-surface-500"
            data-test="explore-unavailable"
            >{{ EXPLORER_UNAVAILABLE.not_on_disk }}</span
          >
          <Button
            v-else
            label="Explore"
            icon="pi pi-folder-open"
            size="small"
            severity="secondary"
            variant="outlined"
            data-test="explore"
            @click="emit('explore', data.handle)"
          />
        </template>
      </Column>
      <template #expansion="{ data }">
        <div class="flex flex-col gap-3 py-1">
          <ul class="flex flex-wrap gap-x-4 gap-y-1 text-sm" data-test="place-tools">
            <li v-for="tool in data.tools" :key="tool">{{ TOOLS[tool as ToolName] }}</li>
          </ul>
          <Message
            v-if="!data.repository_on_disk"
            severity="secondary"
            size="small"
            data-test="context-unavailable"
            >{{ UNAVAILABLE.not_on_disk }}</Message
          >
          <ContextLines v-else :finding-id="data.handle" />
        </div>
      </template>
    </DataTable>
  </div>
</template>
