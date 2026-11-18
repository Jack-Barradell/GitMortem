import { ref } from "vue";
import type { RouteLocationNormalized } from "vue-router";
import { EXPLORE } from "@/stores/explorer";

const TRIAGE = /^\/(secrets|(secrets|findings)\/\d+)$/;

export const exploredFrom = ref<string | null>(null);

export function noteExploring(to: RouteLocationNormalized, from: RouteLocationNormalized): void {
  if (to.name !== EXPLORE || from.name === EXPLORE) return;
  exploredFrom.value = TRIAGE.test(from.path) ? from.fullPath : null;
}
