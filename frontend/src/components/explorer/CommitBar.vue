<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import { computed, ref, watch } from "vue";
import type { components } from "@/api/schema";
import { copyText } from "@/clipboard";
import MarkedSegments from "@/components/MarkedSegments.vue";
import MarksDroppedNote from "@/components/MarksDroppedNote.vue";
import { formatTime, shown } from "@/format";
import { EXPLORER_UNAVAILABLE } from "@/labels";
import { useSay } from "@/notify";
import type { CommitReply, Failure } from "@/stores/explorer";

type Schemas = components["schemas"];
type CommitRead = Schemas["CommitOut.CommitReadOut"];

const NEWLINE = "\n";
const SHORT = 12;

const props = defineProps<{
  commit: CommitReply | null;
  failure: Failure | null;
}>();
const emit = defineEmits<{ open: [commit: string] }>();
const say = useSay();

const read = computed((): CommitRead | null =>
  props.commit !== null && !("unavailable" in props.commit) ? props.commit : null,
);
const unavailable = computed(() =>
  props.commit !== null && "unavailable" in props.commit ? props.commit.unavailable : null,
);

const wholeMessage = ref(false);
watch(
  () => read.value?.id,
  () => (wholeMessage.value = false),
);
const hasMore = computed(
  () => read.value !== null && (read.value.message.length > 1 || read.value.message_cut),
);

async function copyId(id: string): Promise<void> {
  if ((await copyText(id)) === "copied") say("success", "Commit id copied");
  else say("warn", "Commit id not copied", "Your browser did not allow it: select the id instead.");
}
</script>

<template>
  <section class="min-w-0" aria-label="Commit" data-test="commit-bar">
    <Message v-if="failure" severity="error" size="small" role="alert" data-test="commit-error">
      {{ failure.message }}
    </Message>
    <Message
      v-else-if="unavailable"
      severity="secondary"
      size="small"
      data-test="commit-unavailable"
    >
      {{ EXPLORER_UNAVAILABLE[unavailable] }}
    </Message>
    <p v-else-if="read === null" class="text-sm text-surface-500" data-test="commit-loading">
      Reading the commit…
    </p>
    <template v-else>
      <Message
        v-if="read.integrity_failed"
        severity="warn"
        size="small"
        class="mb-2"
        data-test="integrity"
      >
        This repo failed its integrity check; what the explorer shows may not be what was committed.
      </Message>
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span class="font-mono break-all" data-test="commit-id">{{ read.id }}</span>
        <Button
          icon="pi pi-copy"
          text
          size="small"
          severity="secondary"
          aria-label="Copy the commit id"
          title="Copy the commit id"
          data-test="copy-id"
          @click="copyId(read.id)"
        />
        <span class="text-surface-600 dark:text-surface-300" data-test="author">
          {{ shown(read.author.name) }} &lt;{{ shown(read.author.email) }}&gt;,
          <time v-if="read.author.at" :datetime="read.author.at">{{
            formatTime(read.author.at)
          }}</time>
          <template v-else>at an unknown time</template>
        </span>
      </div>
      <p class="mt-1 font-semibold break-words" data-test="subject">
        <MarkedSegments
          v-if="read.message.length > 0"
          :segments="read.message[0]?.segments ?? []"
        />
        <template v-else>No message</template>
      </p>
      <MarksDroppedNote v-if="read.marks_dropped" />
      <Button
        v-if="hasMore"
        :label="wholeMessage ? 'Hide the message' : 'Show the whole message'"
        link
        size="small"
        class="!px-0"
        :aria-expanded="wholeMessage"
        data-test="toggle-message"
        @click="wholeMessage = !wholeMessage"
      />
      <template v-if="wholeMessage">
        <p class="text-sm break-words whitespace-pre-wrap" data-test="message">
          <template v-for="(line, index) in read.message" :key="index"
            ><template v-if="index !== 0">{{ NEWLINE }}</template
            ><MarkedSegments :segments="line.segments"
          /></template>
        </p>
        <p v-if="read.message_cut" class="mt-1 text-sm text-surface-500" data-test="message-cut">
          The message is cut to its first 4 KiB.
        </p>
      </template>

      <dl class="mt-2 grid grid-cols-[max-content_1fr] items-center gap-x-4 text-sm">
        <dt class="text-surface-500">Parents</dt>
        <dd class="flex flex-wrap items-center gap-x-1" data-test="parents">
          <template v-if="read.parents.length === 0">None: the first commit</template>
          <Button
            v-for="(parent, index) in read.parents"
            :key="index"
            :label="parent.slice(0, SHORT)"
            :title="parent"
            link
            size="small"
            class="!px-1 font-mono"
            data-test="parent"
            @click="emit('open', parent)"
          />
        </dd>
        <dt class="text-surface-500">Children</dt>
        <dd class="flex flex-wrap items-center gap-x-1" data-test="children">
          <span
            v-if="read.children_unavailable !== null"
            class="text-surface-500"
            data-test="children-unavailable"
            >{{ EXPLORER_UNAVAILABLE[read.children_unavailable] }}</span
          >
          <template v-else-if="(read.children ?? []).length === 0">None</template>
          <Button
            v-for="(child, index) in read.children ?? []"
            :key="index"
            :label="child.slice(0, SHORT)"
            :title="child"
            link
            size="small"
            class="!px-1 font-mono"
            data-test="child"
            @click="emit('open', child)"
          />
        </dd>
      </dl>
    </template>
  </section>
</template>
