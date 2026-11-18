<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Tag from "primevue/tag";
import { computed, onBeforeUnmount, ref } from "vue";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor } from "@/format";
import { DISCOVERY_STATES, discoverySeverity, isUnfinished } from "@/labels";
import { useSay } from "@/notify";
import { usePolling } from "@/poll";
import { useSession } from "@/stores/session";

type Root = components["schemas"]["ScanRootOut"];
type Discovery = components["schemas"]["DiscoveryOut"];
type DiscoveryId = components["schemas"]["DiscoveryIdOut"];

const props = defineProps<{ root: Root }>();
const emit = defineEmits<{
  follow: [rootId: number, discoveryId: number];
  ended: [rootId: number];
}>();
const say = useSay();

const followed = ref<number | null>(null);
const discovery = ref<Discovery | null>(null);
const polling = ref(false);
const pollError = ref("");
const refused = ref("");
const starting = ref(false);
const cancelling = ref(false);
const session = useSession();
const mayCancel = computed(
  () => session.isAdmin || (discovery.value?.started_by ?? null) === session.user?.username,
);
let sawUnfinished = false;
let polled = 0;
let alive = true;
onBeforeUnmount(() => {
  alive = false;
});

const unfinished = computed(() => discovery.value !== null && isUnfinished(discovery.value.state));
const live = computed(() => polling.value && (discovery.value === null || unfinished.value));
const heading = computed(() => {
  if (live.value) return "Discovery";
  return unfinished.value ? "Last seen" : "Last discovery";
});

const poll = usePolling(async () => {
  const id = polled;
  let found: Discovery | null = null;
  let failed = "";
  try {
    found = await api<Discovery>(`/api/discoveries/${id}`, { background: true });
  } catch (failure) {
    failed = messageFor(failure);
  }
  if (!alive || id !== followed.value) return false;
  if (found === null) {
    pollError.value = failed;
    polling.value = false;
    return false;
  }
  discovery.value = found;
  if (isUnfinished(found.state)) {
    sawUnfinished = true;
    return true;
  }
  polling.value = false;
  if (sawUnfinished) {
    sawUnfinished = false;
    emit("ended", props.root.id);
  }
  return false;
});

function follow(id: number | null, started = false): void {
  if (!alive) return;
  poll.stop();
  followed.value = id;
  discovery.value = null;
  pollError.value = "";
  cancelling.value = false;
  sawUnfinished = started;
  polling.value = id !== null;
  if (id === null) return;
  polled = id;
  if (id !== props.root.last_discovery_id) emit("follow", props.root.id, id);
  poll.start();
}

function retry(): void {
  pollError.value = "";
  polling.value = true;
  poll.start();
}

async function discover(): Promise<void> {
  starting.value = true;
  refused.value = "";
  try {
    const started = await api<DiscoveryId>(`/api/scan-roots/${props.root.id}/discover`, {
      method: "POST",
    });
    follow(started.discovery_id, true);
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409) await followRunning(failure.message);
    else refused.value = messageFor(failure);
  } finally {
    starting.value = false;
  }
}

async function followRunning(why: string): Promise<void> {
  let roots: Root[];
  try {
    roots = await api<Root[]>("/api/scan-roots");
  } catch (failure) {
    refused.value = `${why} ${messageFor(failure)}`;
    return;
  }
  const newest = roots.find((r) => r.id === props.root.id)?.last_discovery_id ?? null;
  if (newest === null) {
    refused.value = why;
    return;
  }
  follow(newest);
}

async function cancel(id: number): Promise<void> {
  cancelling.value = true;
  refused.value = "";
  try {
    await api<DiscoveryId>(`/api/discoveries/${id}/cancel`, { method: "POST" });
    say("success", "Cancel requested", "The discovery stops at its next folder.");
  } catch (failure) {
    cancelling.value = false;
    refused.value = messageFor(failure);
  }
}

follow(props.root.last_discovery_id);
</script>

<template>
  <section aria-label="Discovery">
    <div class="mt-4 flex flex-wrap items-center gap-2 text-sm">
      <Button
        label="Discover repositories"
        icon="pi pi-search"
        :loading="starting"
        :disabled="starting || live || !root.usable"
        data-test="discover"
        @click="discover"
      />
      <div v-if="followed !== null" class="flex flex-wrap items-center gap-2" data-test="discovery">
        <template v-if="discovery">
          <span class="font-medium">{{ heading }}</span>
          <Tag
            :value="DISCOVERY_STATES[discovery.state]"
            :severity="discoverySeverity(discovery.state)"
          />
          <span>
            {{ discovery.found }} found · {{ discovery.refused }} can't be scanned ·
            {{ discovery.aliases }} {{ discovery.aliases === 1 ? "alias" : "aliases" }} ·
            {{ discovery.not_followed }} not followed
          </span>
          <time
            v-if="discovery.finished_at"
            :datetime="discovery.finished_at"
            class="text-surface-500"
          >
            {{ formatTime(discovery.finished_at) }}
          </time>
          <Button
            v-if="live && mayCancel"
            :label="cancelling || discovery.cancel_requested_at ? 'Cancelling' : 'Cancel'"
            size="small"
            severity="secondary"
            variant="outlined"
            :disabled="cancelling || discovery.cancel_requested_at !== null"
            data-test="cancel-discovery"
            @click="cancel(discovery.id)"
          />
        </template>
        <span v-else-if="polling" class="text-surface-500">
          Asking for the discovery's progress.
        </span>
      </div>
    </div>
    <Message
      v-if="pollError"
      severity="error"
      size="small"
      class="mt-2"
      role="alert"
      data-test="discovery-error"
    >
      <div class="flex flex-wrap items-center gap-3">
        <span>Discovery progress not loaded: {{ pollError }}</span>
        <Button
          label="Try again"
          size="small"
          severity="secondary"
          variant="outlined"
          data-test="retry-discovery"
          @click="retry"
        />
      </div>
    </Message>
    <Message
      v-if="refused"
      severity="error"
      size="small"
      class="mt-2"
      role="alert"
      data-test="discovery-refused"
    >
      {{ refused }}
    </Message>
  </section>
</template>
