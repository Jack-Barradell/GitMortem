<script setup lang="ts">
import Dialog from "primevue/dialog";
import Message from "primevue/message";
import { computed, ref, watch } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor } from "@/format";
import { EXPLORER_UNAVAILABLE, REF_KINDS } from "@/labels";
import { useExplorer } from "@/stores/explorer";

type Schemas = components["schemas"];
type Refs = Schemas["RefsOut"];
type RefList = Schemas["RefsOut.RefListOut"];
type RefKind = Schemas["RefsOut.RefOut"]["kind"];

const props = defineProps<{ repositoryId: number; visible: boolean }>();

const emit = defineEmits<{ "update:visible": [visible: boolean]; open: [commit: string] }>();

const explorer = useExplorer();
const refs = ref<Refs | null>(null);
const error = ref("");
let asked = 0;

const listed = computed((): RefList | null =>
  refs.value !== null && "refs" in refs.value ? refs.value : null,
);
const unavailable = computed(() =>
  refs.value !== null && "unavailable" in refs.value ? refs.value.unavailable : null,
);
const groups = computed(() =>
  (Object.keys(REF_KINDS) as RefKind[])
    .map((kind) => ({ kind, refs: (listed.value?.refs ?? []).filter((r) => r.kind === kind) }))
    .filter((group) => group.refs.length > 0),
);

async function read(): Promise<void> {
  const mine = (asked += 1);
  refs.value = null;
  error.value = "";
  try {
    const answer = await api<Refs>(
      `/api/repositories/${props.repositoryId}/refs${explorer.versionQuery("?")}`,
    );
    if (mine === asked) refs.value = answer;
  } catch (failure) {
    if (mine === asked) error.value = messageFor(failure);
  }
}

watch(
  () => props.visible,
  (open) => {
    if (open && listed.value === null) void read();
  },
  { immediate: true },
);

watch(
  () => [props.repositoryId, explorer.version] as const,
  () => {
    asked += 1;
    refs.value = null;
    error.value = "";
    if (props.visible) void read();
  },
);

function choose(target: string): void {
  emit("open", target);
  emit("update:visible", false);
}
</script>

<template>
  <Dialog
    :visible="visible"
    modal
    header="Branches and tags"
    class="w-full max-w-2xl"
    data-test="refs-dialog"
    @update:visible="emit('update:visible', $event)"
  >
    <div class="max-h-[60vh] overflow-auto" data-test="refs">
      <Message v-if="error" severity="error" size="small" role="alert" data-test="refs-error">
        {{ error }}
      </Message>
      <Message
        v-else-if="unavailable"
        severity="secondary"
        size="small"
        data-test="refs-unavailable"
      >
        {{ EXPLORER_UNAVAILABLE[unavailable] }}
      </Message>
      <p v-else-if="listed === null" class="text-sm text-surface-500">Reading the refs…</p>
      <template v-else>
        <p v-if="groups.length === 0" class="text-sm text-surface-500" data-test="refs-none">
          The repository has no branches or tags.
        </p>
        <section v-for="group in groups" :key="group.kind" class="mb-3">
          <h3 class="text-sm font-semibold">{{ REF_KINDS[group.kind] }}</h3>
          <ul>
            <li v-for="(named, index) in group.refs" :key="index">
              <button
                type="button"
                class="w-full px-1 py-0.5 text-left font-mono text-sm break-all hover:bg-surface-100 disabled:text-surface-500 disabled:hover:bg-transparent dark:hover:bg-surface-800"
                :disabled="named.target === null"
                data-test="ref"
                @click="named.target !== null && choose(named.target)"
              >
                {{ named.name }}<template v-if="named.target === null"> (names no commit)</template>
              </button>
            </li>
          </ul>
        </section>
        <p v-if="listed.truncated" class="text-sm text-surface-500" data-test="refs-truncated">
          Only the first {{ listed.refs.length.toLocaleString("en-US") }} refs are listed: the
          repository has more.
        </p>
      </template>
    </div>
  </Dialog>
</template>
