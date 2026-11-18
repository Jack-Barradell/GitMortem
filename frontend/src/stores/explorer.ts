import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { useRouter, type LocationQuery, type RouteLocationRaw } from "vue-router";
import { api, ApiError } from "@/api/client";
import type { components } from "@/api/schema";
import { messageFor, shownLine } from "@/format";
import type { Subject } from "@/stores/triage";

type Schemas = components["schemas"];
export type CommitReply = Schemas["CommitOut"];
export type FileReply = Schemas["FileOut"];
export type Unavailable = Schemas["FileOut.Unavailable"];
export type RepositoryReply = Schemas["RepositoryOut"];
type HeadReply = Schemas["HeadOut"];

export const EXPLORE = "explore";
export const MAX_VISITED = 500;
export const MAX_SEGMENT_BYTES = 4_096;
export const MAX_PATH_BYTES = 65_536;
export const MAX_SEGMENTS = 4_096;
export const MAX_QUERY_CHARS = 1_000;

export interface Place {
  commit: string;
  path: string[];
  line: number | null;
}

export interface Address extends Omit<Place, "commit"> {
  commit: string | null;
  from: string | null;
  version: number | null;
}

export interface Failure {
  status: number | null;
  message: string;
}

const FULL_HEX = /^[0-9a-f]{40}$/;
const SEGMENT = /^[A-Za-z0-9_-]+$/;
const LINE = /^[1-9]\d{0,8}$/;
const FROM = /^(secret|finding):[1-9]\d{0,15}$/;
const LINE_BREAKS = /[\n\r]/g;

function one(value: LocationQuery[string] | undefined): string | null {
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" ? first : null;
}

export function joinPath(path: readonly string[]): string {
  return path.join(".");
}

function bytesOf(segment: string): Uint8Array | null {
  if (!SEGMENT.test(segment)) return null;
  let binary: string;
  try {
    binary = atob(segment.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
  const spelled = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return spelled === segment ? Uint8Array.from(binary, (byte) => byte.charCodeAt(0)) : null;
}

function splitPath(text: string): string[] | null {
  if (text === "") return [];
  const segments = text.split(".");
  if (segments.length > MAX_SEGMENTS) return null;
  let total = 0;
  for (const segment of segments) {
    const bytes = bytesOf(segment);
    if (bytes === null || bytes.length > MAX_SEGMENT_BYTES) return null;
    total += bytes.length;
  }
  return total <= MAX_PATH_BYTES ? segments : null;
}

export function readAddress(query: LocationQuery): Address | null {
  const commit = one(query.commit) ?? "";
  if (commit !== "" && !FULL_HEX.test(commit)) return null;
  const path = splitPath(one(query.path) ?? "");
  if (path === null) return null;
  const line = one(query.line);
  const from = one(query.from);
  const version = one(query.version);
  return {
    commit: commit === "" ? null : commit,
    path,
    line: path.length > 0 && line !== null && LINE.test(line) ? Number(line) : null,
    from: from !== null && FROM.test(from) ? from : null,
    version: version !== null && /^[1-9][0-9]{0,15}$/.test(version) ? Number(version) : null,
  };
}

export function addressOf(
  repositoryId: number,
  place: Place,
  from: string | null,
  version: number | null = null,
): RouteLocationRaw {
  const query: Record<string, string> = { commit: place.commit };
  if (place.path.length > 0) {
    query.path = joinPath(place.path);
    if (place.line !== null) query.line = String(place.line);
  }
  if (from !== null) query.from = from;
  if (version !== null) query.version = String(version);
  return { name: EXPLORE, params: { id: String(repositoryId) }, query };
}

export function subjectOfFrom(from: string | null): Subject | null {
  if (from === null || !FROM.test(from)) return null;
  const [kind, id] = from.split(":");
  const number = Number(id);
  if (!Number.isSafeInteger(number)) return null;
  return { kind: kind as Subject["kind"], id: number };
}

export async function placeAddress(findingId: number, from: string): Promise<RouteLocationRaw> {
  const answer = await api<Schemas["PlaceOut"]>(`/api/findings/${findingId}/place`);
  const place = { commit: answer.commit, path: answer.path.map((s) => s.raw), line: answer.line };
  return addressOf(answer.repository_id, place, from);
}

export async function subjectAddress(subject: Subject, from: string): Promise<RouteLocationRaw> {
  if (subject.kind === "finding") return placeAddress(subject.id, from);
  const secret = await api<Schemas["SecretOut"]>(`/api/secrets/${subject.id}`);
  if (secret.first_seen === null)
    throw new ApiError(404, "This secret has no place to open.", null);
  return placeAddress(secret.first_seen.finding_id, from);
}

export function nameOf(raw: string): string {
  const bytes = bytesOf(raw);
  if (bytes === null) return "\uFFFD";
  return shownLine(new TextDecoder().decode(bytes)).replace(LINE_BREAKS, "\uFFFD");
}

export function displayPath(path: readonly string[]): string {
  return path.map(nameOf).join("/");
}

function failureOf(error: unknown): Failure {
  return { status: error instanceof ApiError ? error.status : null, message: messageFor(error) };
}

const samePlace = (a: Place | undefined, b: Place): boolean =>
  a !== undefined && a.commit === b.commit && joinPath(a.path) === joinPath(b.path);

export const useExplorer = defineStore("explorer", () => {
  const router = useRouter();
  const repositoryId = ref<number | null>(null);
  const version = ref<number | null>(null);
  const repository = ref<RepositoryReply | null>(null);
  const repositoryFailure = ref<Failure | null>(null);
  const place = ref<Place | null>(null);
  const from = ref<string | null>(null);
  const visited = ref<Place[]>([]);
  const at = ref(-1);
  const commit = ref<CommitReply | null>(null);
  const commitFailure = ref<Failure | null>(null);
  const file = ref<FileReply | null>(null);
  const fileFailure = ref<Failure | null>(null);
  const headUnavailable = ref<Unavailable | null>(null);
  const headFailure = ref<Failure | null>(null);

  const canBack = computed(() => at.value > 0);
  const canForward = computed(() => at.value < visited.value.length - 1);

  let generation = 0;
  let commitAsked = 0;
  let fileAsked = 0;
  let headAsked = 0;
  let pending: { move: number; intent: number | "new" } | null = null;
  let moves = 0;

  function leave(): void {
    generation += 1;
    pending = null;
    repositoryId.value = null;
    repository.value = null;
    repositoryFailure.value = null;
    place.value = null;
    from.value = null;
    visited.value = [];
    at.value = -1;
    commit.value = null;
    commitFailure.value = null;
    file.value = null;
    fileFailure.value = null;
    headUnavailable.value = null;
    headFailure.value = null;
  }

  async function loadRepository(id: number): Promise<void> {
    const mine = generation;
    repositoryFailure.value = null;
    try {
      const answer = await api<RepositoryReply>(`/api/repositories/${id}`);
      if (mine === generation) repository.value = answer;
    } catch (failure) {
      if (mine === generation) repositoryFailure.value = failureOf(failure);
    }
  }

  function enter(id: number): void {
    if (repositoryId.value === id) {
      if (repositoryFailure.value !== null) void loadRepository(id);
      return;
    }
    leave();
    repositoryId.value = id;
    void loadRepository(id);
  }

  function record(next: Place): void {
    const wanted = pending?.intent ?? null;
    pending = null;
    const looked = wanted === "new" ? [at.value] : [wanted, at.value, at.value - 1, at.value + 1];
    const near = looked.find((index) => index !== null && samePlace(visited.value[index], next));
    if (near !== undefined && near !== null) {
      at.value = near;
      visited.value[near] = next;
      return;
    }
    visited.value = [...visited.value.slice(0, at.value + 1), next].slice(-MAX_VISITED);
    at.value = visited.value.length - 1;
  }

  async function loadCommit(id: number, wanted: string): Promise<void> {
    const mine = generation;
    const asked = (commitAsked += 1);
    const current = () => mine === generation && asked === commitAsked;
    commit.value = null;
    commitFailure.value = null;
    try {
      const answer = await api<CommitReply>(
        `/api/repositories/${id}/commits/${wanted}${versionQuery("?")}`,
      );
      if (current()) commit.value = answer;
    } catch (failure) {
      if (current()) commitFailure.value = failureOf(failure);
    }
  }

  function versionField(): { version?: number } {
    return version.value === null ? {} : { version: version.value };
  }

  function versionQuery(lead: string): string {
    return version.value === null ? "" : `${lead}version=${version.value}`;
  }

  async function loadFile(id: number, wanted: Place): Promise<void> {
    const mine = generation;
    const asked = (fileAsked += 1);
    const current = () => mine === generation && asked === fileAsked;
    file.value = null;
    fileFailure.value = null;
    if (wanted.path.length === 0) return;
    try {
      const answer = await api<FileReply>(`/api/repositories/${id}/explore/file`, {
        method: "POST",
        body: { commit: wanted.commit, path: wanted.path, ...versionField() },
      });
      if (current()) file.value = answer;
    } catch (failure) {
      if (current()) fileFailure.value = failureOf(failure);
    }
  }

  function arrive(id: number, next: Place, origin: string | null): void {
    enter(id);
    headAsked += 1;
    headUnavailable.value = null;
    headFailure.value = null;
    const before = place.value;
    from.value = origin;
    place.value = next;
    record(next);
    if (before === null || before.commit !== next.commit || commitFailure.value !== null) {
      void loadCommit(id, next.commit);
    }
    if (before === null || !samePlace(before, next) || fileFailure.value !== null) {
      void loadFile(id, next);
    }
  }

  async function findHead(id: number, address: Address): Promise<void> {
    enter(id);
    const mine = generation;
    const asked = (headAsked += 1);
    const current = () => mine === generation && asked === headAsked;
    headUnavailable.value = null;
    headFailure.value = null;
    try {
      const answer = await api<HeadReply>(`/api/repositories/${id}/head${versionQuery("?")}`);
      if (!current()) return;
      if ("unavailable" in answer) {
        headUnavailable.value = answer.unavailable;
        return;
      }
      const head = { commit: answer.commit, path: address.path, line: address.line };
      await router.replace(addressOf(id, head, address.from, version.value));
    } catch (failure) {
      if (current()) headFailure.value = failureOf(failure);
    }
  }

  async function move(id: number, target: Place, intent: number | "new"): Promise<void> {
    const mine = (moves += 1);
    pending = { move: mine, intent };
    const failed = await router.push(addressOf(id, target, from.value, version.value));
    if (failed !== undefined && pending?.move === mine) pending = null;
  }

  async function go(to: string, path: string[] = [], line: number | null = null): Promise<void> {
    if (repositoryId.value !== null) {
      await move(repositoryId.value, { commit: to, path, line }, "new");
    }
  }

  async function step(by: -1 | 1): Promise<void> {
    const target = visited.value[at.value + by];
    if (repositoryId.value !== null && target !== undefined) {
      await move(repositoryId.value, target, at.value + by);
    }
  }

  return {
    repositoryId,
    version,
    versionField,
    versionQuery,
    repository,
    repositoryFailure,
    place,
    from,
    visited,
    at,
    commit,
    commitFailure,
    file,
    fileFailure,
    headUnavailable,
    headFailure,
    canBack,
    canForward,
    arrive,
    findHead,
    go,
    back: () => step(-1),
    forward: () => step(1),
    leave,
  };
});
