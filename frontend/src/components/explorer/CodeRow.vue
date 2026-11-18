<script setup lang="ts">
import { computed } from "vue";
import { TOKEN_CLASSES } from "@/explorer/highlight/encode";
import type { Piece } from "@/explorer/rows";

const props = defineProps<{
  index: number;
  text: string;
  target: boolean;
  piecesOf: (line: string, index: number) => Piece[];
}>();

const KNOWN = "A value GitMortem knows";
const pieces = computed(() => props.piecesOf(props.text, props.index));
</script>

<template>
  <div class="code-row" :data-line="index + 1" :data-target="target ? 'true' : undefined">
    <span class="code-gutter">{{ index + 1 }}</span
    ><span class="code-text"
      ><span
        v-for="(piece, at) in pieces"
        :key="at"
        :class="[TOKEN_CLASSES[piece.cls], { mark: piece.known }]"
        :title="piece.known ? KNOWN : undefined"
        :data-find="piece.find"
        :data-subject="piece.subject"
        >{{ piece.text }}</span
      ></span
    >
  </div>
</template>
