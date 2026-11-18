<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import CanaryHints from "@/components/CanaryHints.vue";
import FootprintTable from "@/components/FootprintTable.vue";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import MarkedSegments from "@/components/MarkedSegments.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import NotesPanel from "@/components/NotesPanel.vue";
import RepositorySummary from "@/components/RepositorySummary.vue";
import SkippedDialog from "@/components/SkippedDialog.vue";
import StatusForm from "@/components/StatusForm.vue";
import StatusHistory from "@/components/StatusHistory.vue";
import ValueBar from "@/components/ValueBar.vue";
import { formatTime, messageFor, shown } from "@/format";
import { SECRET_STATUSES, statusSeverity, SUBJECT_KINDS, TOOLS } from "@/labels";
import { placeAddress } from "@/stores/explorer";
import {
  listedPath,
  staysInTriage,
  subjectKey,
  subjectPath,
  useTriage,
  type Neighbours,
  type SecretStatus,
  type Subject,
} from "@/stores/triage";

type Schemas = components["schemas"];
type SecretOut = Schemas["SecretOut"];
type FindingOut = Schemas["FindingOut"];
type FirstSeen = Schemas["SecretOut.FirstSeenOut"];
type ToolName = Schemas["SecretOut.ToolName"];
type CanaryHint = Schemas["FindingOut.CanaryHintOut"];

interface Detail {
  kind: string;
  status: SecretStatus;
  value: string;
  marksDropped: boolean;
  tools: ToolName[];
  firstSeen: FirstSeen | null;
  findings: number;
  repos: number;
  lastChangeId: number;
  canaryHints: CanaryHint[];
  canaryHintsMore: boolean;
  canaryUnchecked: boolean;
}

const NOT_FOUND: Record<Subject["kind"], string> = {
  secret: "No such secret.",
  finding: "No such finding.",
};

const props = defineProps<{ kind: Subject["kind"] }>();
const route = useRoute();
const router = useRouter();
const triage = useTriage();

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
const toolsOf = (tools: ToolName[]): string => tools.map((tool) => TOOLS[tool]).join(", ");

function idFrom(param: unknown): number | null {
  const id = Number(param);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function ofSecret(found: SecretOut): Detail {
  return {
    kind: found.kind,
    status: found.status,
    value: found.value,
    marksDropped: found.marks_dropped,
    tools: found.tools,
    firstSeen: found.first_seen,
    findings: found.findings,
    repos: found.repos,
    lastChangeId: found.last_change_id,
    canaryHints: found.canary_hints,
    canaryHintsMore: found.canary_hints_more,
    canaryUnchecked: found.canary_unchecked,
  };
}

function ofFinding(found: FindingOut): Detail {
  return {
    kind: found.rule,
    status: found.status as SecretStatus,
    value: found.value,
    marksDropped: found.marks_dropped,
    tools: [found.tool],
    firstSeen: {
      finding_id: found.id,
      repository_id: found.repository_id,
      repo: found.repo,
      display_path: found.display_path,
      line: found.line,
      commit: found.commit,
      authored_at: found.authored_at,
      author_name: found.author_name,
      author_email: found.author_email,
      message_subject:
        found.commit_message === null ? null : (found.commit_message[0] ?? { segments: [] }),
    },
    findings: 1,
    repos: 1,
    lastChangeId: found.last_change_id as number,
    canaryHints: found.canary_hints,
    canaryHintsMore: found.canary_hints_more,
    canaryUnchecked: found.canary_unchecked,
  };
}

const subject = ref<Subject | null>(null);
const detail = ref<Detail | null>(null);
const loadError = ref("");
const nav = ref<Neighbours | null>(null);
const navError = ref("");
const standalone = ref<FindingOut | null>(null);
const holdingFinding = ref<number | null>(null);
const exploreError = ref("");
const statusError = ref("");
const skipped = ref<Schemas["StatusOut"]["skipped"]>([]);
const skippedTotal = ref(0);
const historyRefresh = ref(0);
const notesRefresh = ref(0);

let generation = 0;
let openedAt = "";
let exploreAsked = 0;

function forget(): void {
  generation += 1;
  subject.value = null;
  detail.value = null;
  loadError.value = "";
  nav.value = null;
  navError.value = "";
  standalone.value = null;
  holdingFinding.value = null;
  exploreError.value = "";
  exploreAsked += 1;
  statusError.value = "";
  skipped.value = [];
  skippedTotal.value = 0;
}

watch(
  [() => props.kind, () => route.name, () => route.params.id],
  () => {
    forget();
    if (route.name !== props.kind) return;
    openedAt = route.path;
    const id = idFrom(route.params.id);
    if (id === null) loadError.value = NOT_FOUND[props.kind];
    else void open({ kind: props.kind, id });
  },
  { immediate: true },
);

async function open(asked: Subject): Promise<void> {
  const mine = generation;
  const named = route.query.finding;
  const holding = asked.kind === "secret" && typeof named === "string" ? idFrom(named) : null;
  let found: Detail;
  let only: FindingOut | null = null;
  try {
    if (asked.kind === "secret") {
      found = ofSecret(await api<SecretOut>(`/api${subjectPath(asked)}`));
    } else {
      const finding = await api<FindingOut>(`/api${subjectPath(asked)}`);
      if (mine !== generation) return;
      if (finding.secret_id !== null) {
        void router.replace({
          path: subjectPath({ kind: "secret", id: finding.secret_id }),
          query: { finding: String(asked.id) },
        });
        return;
      }
      found = ofFinding(finding);
      only = finding;
    }
  } catch (failure) {
    if (mine === generation) loadError.value = messageFor(failure);
    return;
  }
  if (mine !== generation) return;
  subject.value = asked;
  detail.value = found;
  holdingFinding.value = holding;
  standalone.value = only;
  void walk(asked);
}

async function explore(at: Subject, findingId: number): Promise<void> {
  const mine = generation;
  const asked = ++exploreAsked;
  exploreError.value = "";
  try {
    const address = await placeAddress(findingId, subjectKey(at));
    if (mine === generation && asked === exploreAsked) await router.push(address);
  } catch (failure) {
    if (mine === generation && asked === exploreAsked) exploreError.value = messageFor(failure);
  }
}

async function walk(current: Subject): Promise<void> {
  const mine = generation;
  try {
    const found = await triage.neighbours(current);
    if (mine === generation) nav.value = found;
  } catch (failure) {
    if (mine === generation) navError.value = messageFor(failure);
  }
}

const title = computed(() => {
  const id = idFrom(route.params.id);
  return id === null ? SUBJECT_KINDS[props.kind] : `${SUBJECT_KINDS[props.kind]} ${id}`;
});

async function onChanged(result: Schemas["StatusOut"], noted: boolean): Promise<void> {
  const at = subject.value;
  if (at === null) return;
  const mine = generation;
  statusError.value = "";
  skipped.value = result.skipped;
  skippedTotal.value = result.skipped_total;
  historyRefresh.value += 1;
  if (noted) notesRefresh.value += 1;
  try {
    const found =
      at.kind === "secret"
        ? ofSecret(await api<SecretOut>(`/api${subjectPath(at)}`))
        : ofFinding(await api<FindingOut>(`/api${subjectPath(at)}`));
    if (mine === generation) detail.value = found;
  } catch (failure) {
    if (mine === generation) statusError.value = messageFor(failure);
  }
}

function closeSkipped(): void {
  skipped.value = [];
  skippedTotal.value = 0;
}

onBeforeUnmount(() => {
  forget();
  const to = router.currentRoute.value;
  if (to.path === openedAt || !staysInTriage(to)) triage.leaveTriage();
});
</script>

<template>
  <AppPage :title="title" fluid>
    <template #summary>
      <RouterLink
        :to="{ path: '/secrets', query: triage.toRoute() }"
        class="font-medium gm-link"
        data-test="back"
      >
        Secrets
      </RouterLink>
    </template>
    <template #actions>
      <nav
        v-if="nav && (nav.previous || nav.next)"
        class="flex gap-2"
        aria-label="Previous and next in the list"
      >
        <Button
          v-if="nav.previous"
          as="router-link"
          :to="listedPath(triage.query.view, nav.previous, nav.previous.finding)"
          label="Previous"
          icon="pi pi-arrow-left"
          size="small"
          severity="secondary"
          variant="outlined"
          data-test="previous"
        />
        <Button
          v-else
          label="Previous"
          icon="pi pi-arrow-left"
          size="small"
          severity="secondary"
          variant="outlined"
          disabled
          data-test="previous"
        />
        <Button
          v-if="nav.next"
          as="router-link"
          :to="listedPath(triage.query.view, nav.next, nav.next.finding)"
          label="Next"
          icon="pi pi-arrow-right"
          icon-pos="right"
          size="small"
          severity="secondary"
          variant="outlined"
          data-test="next"
        />
        <Button
          v-else
          label="Next"
          icon="pi pi-arrow-right"
          icon-pos="right"
          size="small"
          severity="secondary"
          variant="outlined"
          disabled
          data-test="next"
        />
      </nav>
    </template>
    <Message v-if="navError" severity="warn" size="small" data-test="nav-error">
      Previous and next could not be read: {{ navError }}
    </Message>
    <Message v-if="loadError" severity="error" size="small" role="alert" data-test="load-error">
      {{ loadError }}
    </Message>

    <template v-if="detail && subject">
      <CanaryHints
        :key="subjectKey(subject)"
        :subject="subject"
        :hints="detail.canaryHints"
        :more="detail.canaryHintsMore"
        :unchecked="detail.canaryUnchecked"
        :status="detail.status"
        :seen="detail.lastChangeId"
        @changed="onChanged($event, false)"
      />
      <PagePanel>
        <ValueBar :key="subjectKey(subject)" :value="detail.value" />
      </PagePanel>

      <div class="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div class="flex min-w-0 flex-col gap-6">
          <PagePanel title="Details">
            <dl
              class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm"
              data-test="details"
            >
              <dt class="text-surface-500 dark:text-surface-400">Type</dt>
              <dd>{{ shown(detail.kind) }}</dd>
              <dt class="text-surface-500 dark:text-surface-400">Found by</dt>
              <dd>{{ toolsOf(detail.tools) }}</dd>
              <dt class="text-surface-500 dark:text-surface-400">Found</dt>
              <dd>
                {{ plural(detail.findings, "finding", "findings") }} in
                {{ plural(detail.repos, "repository", "repositories") }}
              </dd>
              <template v-if="detail.firstSeen">
                <dt class="text-surface-500 dark:text-surface-400">First seen</dt>
                <dd class="flex flex-col" data-test="first-seen">
                  <span>{{ shown(detail.firstSeen.repo) }}</span>
                  <span class="font-mono break-all"
                    >{{ shown(detail.firstSeen.display_path) }}:{{ detail.firstSeen.line }}</span
                  >
                  <span
                    >Commit
                    <span class="font-mono break-all">{{
                      shown(detail.firstSeen.commit)
                    }}</span></span
                  >
                  <span>
                    Authored
                    <time
                      v-if="detail.firstSeen.authored_at"
                      :datetime="detail.firstSeen.authored_at"
                    >
                      {{ formatTime(detail.firstSeen.authored_at) }}
                    </time>
                    <template v-else>at an unknown time</template>
                    by {{ shown(detail.firstSeen.author_name) }} &lt;{{
                      shown(detail.firstSeen.author_email)
                    }}&gt;
                  </span>
                  <span
                    v-if="detail.firstSeen.message_subject !== null"
                    class="text-surface-500 dark:text-surface-400"
                    data-test="first-seen-message"
                    ><MarkedSegments :segments="detail.firstSeen.message_subject.segments"
                  /></span>
                  <MarksDroppedNote v-if="detail.marksDropped" />
                </dd>
              </template>
            </dl>
          </PagePanel>

          <PagePanel
            v-if="subject.kind === 'secret'"
            title="Repositories"
            data-test="repositories-section"
          >
            <RepositorySummary :secret-id="subject.id" />
          </PagePanel>

          <PagePanel title="Footprint" data-test="findings">
            <Message
              v-if="exploreError"
              severity="error"
              size="small"
              class="mt-2"
              role="alert"
              data-test="explore-error"
            >
              {{ exploreError }}
            </Message>
            <FootprintTable
              :subject="subject"
              :standalone="standalone"
              :holding="holdingFinding"
              @explore="explore(subject, $event)"
            />
          </PagePanel>
        </div>

        <div class="flex min-w-0 flex-col gap-6">
          <PagePanel title="Status">
            <Tag
              :value="SECRET_STATUSES[detail.status]"
              :severity="statusSeverity(detail.status)"
              data-test="status"
            />
            <StatusForm
              :key="subjectKey(subject)"
              :subject="subject"
              :seen="detail.lastChangeId"
              @changed="onChanged"
            />
            <Message
              v-if="statusError"
              severity="error"
              size="small"
              class="mt-2"
              role="alert"
              data-test="status-error"
            >
              {{ statusError }}
            </Message>
          </PagePanel>

          <PagePanel title="Status history">
            <StatusHistory :subject="subject" :refresh="historyRefresh" />
          </PagePanel>

          <PagePanel title="Notes" data-test="notes-section">
            <NotesPanel :subject="subject" :refresh="notesRefresh" />
          </PagePanel>
        </div>
      </div>
    </template>

    <SkippedDialog
      :skipped="skipped"
      :total="skippedTotal"
      :seen="triage.seen"
      @close="closeSkipped"
    />
  </AppPage>
</template>
