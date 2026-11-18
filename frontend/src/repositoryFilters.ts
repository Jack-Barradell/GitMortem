import type { LocationQuery, LocationQueryRaw } from "vue-router";
import type { components } from "@/api/schema";
import { PAGE_SIZES } from "@/stores/triage";

type Repo = components["schemas"]["RepositoryPageOut.RepositoryOut"];
export type RepoKind = Repo["kind"];
export type RepoState = Repo["state"];

export const SCANNED_CHOICES = {
  any: "Any",
  never: "Never scanned",
  scanned: "Scanned",
  scanning: "Scanning now",
} as const;
export type Scanned = keyof typeof SCANNED_CHOICES;

export const REPO_SORTS = [
  "path",
  "org",
  "name",
  "kind",
  "commits",
  "size",
  "state",
  "scanned",
] as const;
export type RepoSort = (typeof REPO_SORTS)[number];

const KINDS: readonly RepoKind[] = ["work_tree", "bare", "not_on_disk", "uploaded"];
const STATES: readonly RepoState[] = ["scannable", "refused", "missing"];
export const DEFAULT_ROWS = 50;
const MAX_TEXT = 256;
const MAX_PAGE = 1_000_000_000;

export interface RepoFilters {
  text: string;
  orgs: string[];
  noOrg: boolean;
  kinds: RepoKind[];
  states: RepoState[];
  scanned: Scanned;
}

export interface RepoView {
  filters: RepoFilters;
  sort: RepoSort;
  descending: boolean;
  page: number;
  rows: number;
}

export function noFilters(): RepoFilters {
  return { text: "", orgs: [], noOrg: false, kinds: [], states: [], scanned: "any" };
}

export function anyFilter(filters: RepoFilters): boolean {
  return (
    filters.text.trim() !== "" ||
    filters.orgs.length > 0 ||
    filters.noOrg ||
    filters.kinds.length > 0 ||
    filters.states.length > 0 ||
    filters.scanned !== "any"
  );
}

function scannedFits(repo: Repo, scanned: Scanned): boolean {
  switch (scanned) {
    case "never":
      return repo.last_scanned_at === null && !repo.scanning;
    case "scanned":
      return repo.last_scanned_at !== null;
    case "scanning":
      return repo.scanning;
    default:
      return true;
  }
}

function orgFits(repo: Repo, filters: RepoFilters): boolean {
  if (filters.orgs.length === 0 && !filters.noOrg) return true;
  return repo.org === null ? filters.noOrg : filters.orgs.includes(repo.org);
}

function asciiLower(text: string): string {
  return text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}

export function matches(repo: Repo, filters: RepoFilters): boolean {
  const text = asciiLower(filters.text.trim());
  const said =
    text === "" ||
    [repo.org ?? "", repo.name, repo.display_path].some((field) =>
      asciiLower(field).includes(text),
    );
  return (
    said &&
    orgFits(repo, filters) &&
    (filters.kinds.length === 0 || filters.kinds.includes(repo.kind)) &&
    (filters.states.length === 0 || filters.states.includes(repo.state)) &&
    scannedFits(repo, filters.scanned)
  );
}

export function apiRepositoryFilters(
  filters: RepoFilters,
): components["schemas"]["RepositoryListIn.RepositoryFiltersIn"] {
  return {
    text: filters.text.trim(),
    orgs: [...filters.orgs],
    no_org: filters.noOrg,
    kinds: [...filters.kinds],
    states: [...filters.states],
    scanned: filters.scanned,
  };
}

function all(value: LocationQuery[string] | undefined): string[] {
  if (value === undefined || value === null) return [];
  return (Array.isArray(value) ? value : [value]).filter((v): v is string => typeof v === "string");
}

function one(value: LocationQuery[string] | undefined): string {
  return all(value)[0] ?? "";
}

function among<T extends string>(allowed: readonly T[], value: string): value is T {
  return (allowed as readonly string[]).includes(value);
}

function count(value: string, fallback: number, most: number): number {
  if (!/^\d{1,10}$/.test(value)) return fallback;
  const n = Number(value);
  return n >= 1 && n <= most ? n : fallback;
}

export function viewOf(query: LocationQuery): RepoView {
  const scanned = one(query.scanned);
  const sort = one(query.sort);
  const rows = count(one(query.rows), DEFAULT_ROWS, Number.MAX_SAFE_INTEGER);
  return {
    filters: {
      text: one(query.q).slice(0, MAX_TEXT),
      orgs: [...new Set(all(query.org))],
      noOrg: one(query.no_org) === "1",
      kinds: [...new Set(all(query.kind).filter((k) => among(KINDS, k)))],
      states: [...new Set(all(query.state).filter((s) => among(STATES, s)))],
      scanned: scanned in SCANNED_CHOICES ? (scanned as Scanned) : "any",
    },
    sort: among(REPO_SORTS, sort) ? sort : "path",
    descending: one(query.order) === "desc",
    page: count(one(query.page), 1, MAX_PAGE),
    rows: (PAGE_SIZES as readonly number[]).includes(rows) ? rows : DEFAULT_ROWS,
  };
}

export function queryOf(view: RepoView): LocationQueryRaw {
  const { filters } = view;
  const query: LocationQueryRaw = {};
  if (filters.text.trim() !== "") query.q = filters.text.slice(0, MAX_TEXT);
  if (filters.orgs.length > 0) query.org = [...filters.orgs];
  if (filters.noOrg) query.no_org = "1";
  if (filters.kinds.length > 0) query.kind = [...filters.kinds];
  if (filters.states.length > 0) query.state = [...filters.states];
  if (filters.scanned !== "any") query.scanned = filters.scanned;
  if (view.sort !== "path") query.sort = view.sort;
  if (view.descending) query.order = "desc";
  if (view.page !== 1) query.page = String(view.page);
  if (view.rows !== DEFAULT_ROWS) query.rows = String(view.rows);
  return query;
}
