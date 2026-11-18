<script setup lang="ts">
import Button from "primevue/button";
import Column from "primevue/column";
import DataTable, { type DataTablePageEvent } from "primevue/datatable";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { useConfirm } from "primevue/useconfirm";
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import AppPage from "@/components/page/AppPage.vue";
import PagePanel from "@/components/page/PagePanel.vue";
import RunOutputDialog from "@/components/RunOutputDialog.vue";
import { formatDuration, formatTime, messageFor, shownName } from "@/format";
import {
  CANARY_STATES,
  COVERAGE_GAPS,
  INTEGRITY_STATES,
  integritySeverity,
  isUnfinished,
  REREAD_RUNNING,
  RUN_FAILURES,
  RUN_STATES,
  DONE_WITH_GAPS,
  runSeverity,
  SCAN_STATES,
  scanSeverity,
  SKIP_REASONS,
  TOOLS,
} from "@/labels";
import { confirmFirst } from "@/confirmFirst";
import { useSay } from "@/notify";
import { SCAN_PAGE_ROWS } from "@/paging";
import { usePolling } from "@/poll";
import { exitCodeText, gitLines } from "@/runDiagnosis";
import { useSession } from "@/stores/session";

type Scan = components["schemas"]["ScanOut"];
type RunPage = components["schemas"]["ToolRunPageOut"];
type Run = RunPage["items"][number];
type Failure = NonNullable<Run["failure"]>;
type Gaps = NonNullable<Run["coverage_gaps"]>;
type Skipped = { tool: keyof typeof TOOLS; reason: NonNullable<Scan["skipped_tools"][string]> };

const ROWS = SCAN_PAGE_ROWS;
const RUN_ORDER = Object.keys(RUN_STATES) as Run["state"][];
const INTEGRITY_ORDER = Object.keys(INTEGRITY_STATES) as Run["integrity"][];

const route = useRoute();
const router = useRouter();
const say = useSay();
const confirm = useConfirm();

const scanId = computed(() => Number(route.params.id));
const scan = ref<Scan | null>(null);
const runs = ref<Run[]>([]);
const runTotal = ref(0);
const first = ref(0);
let shown = 0;
const error = ref("");
const cancelling = ref(false);
const session = useSession();
const mayCancel = computed(
  () => session.isAdmin || (scan.value?.started_by ?? null) === session.user?.username,
);
const running = computed(() => scan.value !== null && isUnfinished(scan.value.state));
const rereadNote = ref("");
const rereading = ref(false);
const skippedOf = (shown: Scan): Skipped[] =>
  Object.entries(shown.skipped_tools).map(([tool, reason]) => ({
    tool: tool as Skipped["tool"],
    reason: reason as Skipped["reason"],
  }));

const poll = usePolling(async () => {
  const id = scanId.value;
  const at = first.value;
  const stale = () => id !== scanId.value || at !== first.value;
  try {
    const found = await api<Scan>(`/api/scans/${id}`, { background: true });
    if (stale()) return false;
    const page = await api<RunPage>(
      `/api/scans/${id}/runs?page=${at / ROWS + 1}&per_page=${ROWS}`,
      { background: true },
    );
    if (stale()) return false;
    scan.value = found;
    runs.value = page.items;
    runTotal.value = page.total;
    shown = at;
    error.value = "";
    return isUnfinished(found.state);
  } catch (failure) {
    if (stale()) return false;
    error.value = messageFor(failure);
    first.value = shown;
    return false;
  }
});

watch(
  scanId,
  (id) => {
    poll.stop();
    if (!Number.isInteger(id)) return;
    scan.value = null;
    runs.value = [];
    runTotal.value = 0;
    first.value = 0;
    shown = 0;
    error.value = "";
    cancelling.value = false;
    rereadNote.value = "";
    rereading.value = false;
    poll.start();
  },
  { immediate: true },
);

function onPage(event: DataTablePageEvent): void {
  first.value = event.first;
  poll.stop();
  poll.start();
}

function retry(): void {
  error.value = "";
  poll.start();
}

function askCancel(): void {
  confirmFirst(confirm, {
    header: "Cancel this scan?",
    message: "Queued runs will not start, and running tools are stopped.",
    acceptLabel: "Cancel scan",
    danger: true,
    accept: cancel,
  });
}

async function cancel(): Promise<void> {
  cancelling.value = true;
  try {
    await api<components["schemas"]["ScanIdOut"]>(`/api/scans/${scanId.value}/cancel`, {
      method: "POST",
    });
    say(
      "success",
      "Cancel requested",
      "Queued runs will not start, and running tools are stopped.",
    );
  } catch (failure) {
    cancelling.value = false;
    say("error", "Scan not cancelled", messageFor(failure));
  }
}

async function reread(): Promise<void> {
  const id = scanId.value;
  rereading.value = true;
  rereadNote.value = "";
  try {
    const made = await api<components["schemas"]["RereadOut"]>(`/api/scans/${id}/reread`, {
      method: "POST",
    });
    if (id !== scanId.value) return;
    if (made.scan_id === null) {
      rereadNote.value =
        "Nothing to re-read: no run of this scan has stored output that can be read again.";
      return;
    }
    say(
      "success",
      "Re-read started",
      `Re-reading ${made.runs} ${made.runs === 1 ? "run" : "runs"}.`,
    );
    await router.push(`/scans/${made.scan_id}`);
  } catch (failure) {
    if (id !== scanId.value) return;
    rereadNote.value =
      failure instanceof ApiError && failure.status === 409 ? REREAD_RUNNING : messageFor(failure);
  } finally {
    if (id === scanId.value) rereading.value = false;
  }
}

const canaryNote = (canary: Run["canary"]): string | null =>
  canary === null || canary === "seen" ? null : CANARY_STATES[canary];

function gapsOf(gaps: Gaps): { kind: keyof Gaps; label: string; count: number }[] {
  return (Object.keys(COVERAGE_GAPS) as (keyof Gaps)[])
    .filter((kind) => gaps[kind] > 0)
    .map((kind) => ({ kind, label: COVERAGE_GAPS[kind], count: gaps[kind] }));
}

function withGaps(run: Run): boolean {
  return run.state === "done" && run.coverage_gaps !== null && gapsOf(run.coverage_gaps).length > 0;
}

function stateText(run: Run): string {
  return withGaps(run) ? DONE_WITH_GAPS : RUN_STATES[run.state];
}

function failureText(failure: Failure, run: Run): string {
  const reason = RUN_FAILURES[failure];
  const error = run.diagnosis?.error ?? null;
  if (failure === "exit_code" && run.exit_code !== null)
    return `${reason} (${exitCodeText(run.exit_code)})`;
  if (failure === "unexpected_error" && error !== null) return `${reason} (${error})`;
  return reason;
}

const outputOf = ref<Run | null>(null);
const outputTitle = computed(() =>
  outputOf.value === null
    ? ""
    : `${TOOLS[outputOf.value.tool]}'s output: ${shownName(outputOf.value.display_path)}`,
);
</script>

<template>
  <AppPage :title="`Scan ${scanId}`" fluid>
    <template #summary>
      <span class="flex flex-wrap items-center gap-3">
        <RouterLink to="/scans" class="font-medium gm-link">All scans</RouterLink>
        <Tag v-if="scan" :value="SCAN_STATES[scan.state]" :severity="scanSeverity(scan.state)" />
      </span>
    </template>
    <template #actions>
      <Button
        v-if="scan && !running"
        label="Re-read stored output"
        icon="pi pi-replay"
        size="small"
        severity="secondary"
        variant="outlined"
        :loading="rereading"
        :disabled="rereading"
        title="Reads each run's stored output again with today's parsers; no tool runs"
        data-test="reread"
        @click="reread"
      />
      <Button
        v-if="scan && running && scan.kind !== 'import' && mayCancel"
        :label="cancelling || scan.cancel_requested_at ? 'Cancelling' : 'Cancel scan'"
        size="small"
        severity="secondary"
        variant="outlined"
        :disabled="cancelling || scan.cancel_requested_at !== null"
        data-test="cancel-scan"
        @click="askCancel"
      />
    </template>

    <Message v-if="error" severity="error" size="small" role="alert">
      <div class="flex items-center gap-3">
        <span>Progress not loaded: {{ error }}</span>
        <Button
          label="Try again"
          size="small"
          severity="secondary"
          variant="outlined"
          data-test="retry"
          @click="retry"
        />
      </div>
    </Message>

    <Message
      v-if="rereadNote"
      severity="secondary"
      size="small"
      role="status"
      data-test="reread-note"
    >
      {{ rereadNote }}
    </Message>

    <template v-if="scan">
      <PagePanel>
        <p
          v-if="scan.kind === 'reread'"
          class="mb-3 text-sm text-surface-500 dark:text-surface-400"
          data-test="scan-kind"
        >
          Re-read of stored output: no tool ran. Each run reads again the output of the run it
          names, and supersedes it once it has read all of it.
        </p>
        <p
          v-if="scan.kind === 'import'"
          class="mb-3 text-sm text-surface-500 dark:text-surface-400"
          data-test="import-scan"
        >
          An import's scan: confirm, discard or remove it on the
          <RouterLink to="/imports" class="font-medium gm-link">Imports</RouterLink>
          page.
        </p>
        <dl class="grid max-w-3xl grid-cols-[8rem_1fr] gap-y-2 text-sm">
          <dt class="text-surface-500 dark:text-surface-400">Started by</dt>
          <dd>{{ scan.started_by ?? "–" }}</dd>
          <dt class="text-surface-500 dark:text-surface-400">Created</dt>
          <dd>
            <time :datetime="scan.created_at">{{ formatTime(scan.created_at) }}</time>
          </dd>
          <dt class="text-surface-500 dark:text-surface-400">Took</dt>
          <dd>{{ formatDuration(scan.started_at, scan.finished_at) }}</dd>
          <dt class="text-surface-500 dark:text-surface-400">Workers</dt>
          <dd>{{ scan.workers }} when it was planned</dd>
        </dl>

        <section v-if="skippedOf(scan).length > 0" class="mt-4" data-test="skipped-tools">
          <h2 class="text-sm font-semibold">Tools not run</h2>
          <ul class="mt-1 text-sm">
            <li v-for="each in skippedOf(scan)" :key="each.tool">
              {{ TOOLS[each.tool] }}: {{ SKIP_REASONS[each.reason] }}
            </li>
          </ul>
        </section>
      </PagePanel>

      <PagePanel title="Secrets found" data-test="secrets-found">
        <p v-if="running" class="mb-3 text-sm text-surface-500 dark:text-surface-400">
          Counted as each run finishes, so these grow while the scan runs.
        </p>
        <dl class="grid grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-2">
          <div
            class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
            data-test="secrets-unique"
          >
            <dt class="text-xs text-surface-500 dark:text-surface-400">Unique secrets</dt>
            <dd class="flex items-baseline gap-2">
              <span class="text-xl font-semibold tabular-nums">{{ scan.secrets.unique }}</span>
              <RouterLink
                :to="{ path: '/secrets', query: { scan: String(scan.id) } }"
                class="text-xs gm-link"
                :aria-label="`Show the unique secrets found by scan ${scan.id}`"
                >Show</RouterLink
              >
            </dd>
          </div>
          <div
            class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
            data-test="secrets-new"
          >
            <dt class="text-xs text-surface-500 dark:text-surface-400">New in this scan</dt>
            <dd class="flex items-baseline gap-2">
              <span class="text-xl font-semibold tabular-nums">{{ scan.secrets.new_unique }}</span>
              <RouterLink
                :to="{ path: '/secrets', query: { scan: String(scan.id), scope: 'new' } }"
                class="text-xs gm-link"
                :aria-label="`Show the secrets new in scan ${scan.id}`"
                >Show</RouterLink
              >
            </dd>
          </div>
          <div
            class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
            data-test="secrets-findings"
          >
            <dt class="text-xs text-surface-500 dark:text-surface-400">Findings</dt>
            <dd class="text-xl font-semibold tabular-nums">{{ scan.secrets.findings }}</dd>
          </div>
        </dl>
      </PagePanel>

      <div class="grid gap-6 lg:grid-cols-2">
        <PagePanel title="Runs by state">
          <dl
            class="grid grid-cols-[repeat(auto-fill,minmax(7rem,1fr))] gap-2"
            data-test="run-counts"
          >
            <div
              v-for="state in RUN_ORDER"
              :key="state"
              class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
              :data-test="`run-count-${state}`"
            >
              <dt class="text-xs text-surface-500 dark:text-surface-400">
                {{ RUN_STATES[state] }}
              </dt>
              <dd class="text-xl font-semibold tabular-nums">{{ scan.counts.states[state] }}</dd>
            </div>
          </dl>
        </PagePanel>
        <PagePanel title="Integrity of each repository">
          <dl
            class="grid grid-cols-[repeat(auto-fill,minmax(7rem,1fr))] gap-2"
            data-test="integrity-counts"
          >
            <div
              v-for="state in INTEGRITY_ORDER"
              :key="state"
              class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
              :data-test="`integrity-count-${state}`"
            >
              <dt class="text-xs text-surface-500 dark:text-surface-400">
                {{ INTEGRITY_STATES[state] }}
              </dt>
              <dd class="text-xl font-semibold tabular-nums">{{ scan.counts.integrity[state] }}</dd>
            </div>
          </dl>
        </PagePanel>
      </div>

      <PagePanel flush>
        <DataTable
          v-model:first="first"
          :value="runs"
          data-key="id"
          lazy
          :paginator="runTotal > ROWS"
          :rows="ROWS"
          :total-records="runTotal"
          size="small"
          striped-rows
          @page="onPage"
        >
          <Column header="Repository">
            <template #body="{ data }">
              <span class="font-mono break-all">{{ shownName(data.display_path) }}</span>
            </template>
          </Column>
          <Column header="Tool">
            <template #body="{ data }">
              <div class="whitespace-nowrap">{{ data.tool }}</div>
              <div class="text-xs text-surface-500 dark:text-surface-400">{{ data.identity }}</div>
            </template>
          </Column>
          <Column header="State">
            <template #body="{ data }">
              <Tag
                :value="stateText(data)"
                :severity="withGaps(data) ? 'warn' : runSeverity(data.state)"
                data-test="run-state"
              />
              <p
                v-if="data.failure"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
              >
                {{ failureText(data.failure, data) }}
              </p>
              <p
                v-for="line in gitLines(data.diagnosis, TOOLS[data.tool as Run['tool']])"
                :key="line"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
                data-test="git-end"
              >
                {{ line }}
              </p>
              <Button
                v-if="data.has_output"
                label="Show the tool's output"
                link
                size="small"
                class="mt-1 p-0"
                data-test="show-output"
                @click="outputOf = data"
              />
              <p
                v-if="data.kept_end"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
                data-test="kept-end"
              >
                Kept from the run it re-read
              </p>
              <p
                v-if="canaryNote(data.canary)"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
                data-test="canary"
              >
                {{ canaryNote(data.canary) }}
              </p>
              <p
                v-if="data.reread_of_id !== null"
                class="mt-1 text-sm text-surface-500 dark:text-surface-400"
                data-test="reread-of"
              >
                Re-reads run {{ data.reread_of_id }}
              </p>
              <p
                v-if="data.superseded_by_id !== null"
                class="mt-1 text-sm text-surface-500 dark:text-surface-400"
                data-test="superseded"
              >
                Superseded by run {{ data.superseded_by_id }}
                <template v-if="data.superseded_at">
                  <time :datetime="data.superseded_at">{{ formatTime(data.superseded_at) }}</time>
                </template>
              </p>
            </template>
          </Column>
          <Column header="Integrity">
            <template #body="{ data }">
              <Tag
                :value="INTEGRITY_STATES[data.integrity as Run['integrity']]"
                :severity="integritySeverity(data.integrity)"
              />
            </template>
          </Column>
          <Column header="Findings">
            <template #body="{ data }">
              <span>{{ data.findings_count }}</span>
              <Tag
                v-if="data.parse_issues > 0"
                :value="`${data.parse_issues} ${data.parse_issues === 1 ? 'line' : 'lines'} not read`"
                severity="warn"
                class="ml-2"
                title="Lines of the tool's output that could not be read; the run's other findings are kept."
              />
              <p
                v-if="data.coverage_gaps"
                class="mt-1 max-w-xs text-sm text-surface-500 dark:text-surface-400"
                data-test="coverage-gaps"
              >
                <template v-if="gapsOf(data.coverage_gaps).length === 0"
                  >Every file and rule was read</template
                >
                <span v-for="gap in gapsOf(data.coverage_gaps)" v-else :key="gap.kind" class="block"
                  >{{ gap.label }}: {{ gap.count }}</span
                >
              </p>
            </template>
          </Column>
          <Column header="Duration">
            <template #body="{ data }">
              <span class="whitespace-nowrap">{{
                formatDuration(data.started_at, data.finished_at)
              }}</span>
            </template>
          </Column>
        </DataTable>
      </PagePanel>
      <RunOutputDialog
        :scan-id="scanId"
        :run-id="outputOf?.id ?? null"
        :title="outputTitle"
        @close="outputOf = null"
      />
    </template>
  </AppPage>
</template>
