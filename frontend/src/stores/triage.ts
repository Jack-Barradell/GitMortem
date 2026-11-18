import { defineStore } from "pinia";
import type { LocationQueryRaw, RouteLocationRaw } from "vue-router";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { REPORTED_SCOPES, SCAN_SCOPES, SECRET_STATUSES, TOOLS, VIEWS } from "@/labels";

type Schemas = components["schemas"];
export type Row = Schemas["ListOut.RowOut"];
export type ExportFormat = Schemas["ExportIn"]["format"];
export type ListPage = Schemas["ListOut"];
export type Bound = Schemas["ListOut.BoundOut"];
export type SecretStatus = Schemas["ListOut.SecretStatus"];
export type View = Schemas["ListQueryIn.View"];
export type ListSort = Schemas["ListQueryIn.ListSort"];
export type ScanScope = Schemas["ListQueryIn.ScanScope"];
export type ReportedScope = Schemas["ListQueryIn.ReportedScope"];
export type ToolName = Schemas["ListQueryIn.ToolName"];
export type ValueSearch = Schemas["ListQueryIn.ValueSearchIn"];
export type StatusResult = Schemas["StatusOut"];
type Canaries = Schemas["CanariesOut"];
export type Order = "asc" | "desc";

export interface Subject {
  kind: Row["kind"];
  id: number;
}

export interface Filters {
  orgs: string[];
  repositoryIds: number[];
  paths: string[];
  kinds: string[];
  kindsNegated: boolean;
  tools: ToolName[];
  statuses: SecretStatus[];
  statusesNegated: boolean;
  scanId: number | null;
  scanScope: ScanScope;
  reported: ReportedScope;
  reportedLive: boolean | null;
  reused: boolean | null;
  noOrg: boolean;
  canary: boolean;
  from: string | null;
  to: string | null;
  text: string;
}

export interface Query {
  filters: Filters;
  view: View;
  sort: ListSort;
  order: Order;
  page: number;
  perPage: number;
}

export interface Neighbour extends Subject {
  finding: number;
}

export interface Neighbours {
  previous: Neighbour | null;
  next: Neighbour | null;
}

export const PER_PAGE = 50;
export const FILTER_QUIET_MS = 300;
export const PAGE_SIZES = [25, 50, 100, 250, 500] as const;
const PER_PAGE_KEY = "gitmortem.secrets-per-page";
const MAX_PAGE = 1_000_000_000;
export const MAX_PATHS = 50;
const MAX_PATH_CHARS = 4096;

const SORTS: Record<ListSort, true> = {
  date: true,
  repo: true,
  org: true,
  path: true,
  type: true,
  tool: true,
  status: true,
  findings: true,
  repos: true,
  value: true,
};

export function subjectKey(subject: Subject): string {
  return `${subject.kind}:${subject.id}`;
}

export function subjectPath(subject: Subject): string {
  return `/${subject.kind === "secret" ? "secrets" : "findings"}/${subject.id}`;
}

export function listedPath(view: View, subject: Subject, finding: number): RouteLocationRaw {
  if (view !== "all" || subject.kind !== "secret") return subjectPath(subject);
  return { path: subjectPath(subject), query: { finding: String(finding) } };
}

export function staysInTriage(to: { path: string }): boolean {
  return /^\/(secrets(\/\d+)?|findings\/\d+|repositories\/\d+\/explore|stats)$/.test(to.path);
}

function noFilters(): Filters {
  return {
    orgs: [],
    repositoryIds: [],
    paths: [],
    kinds: [],
    kindsNegated: false,
    tools: [],
    statuses: [],
    statusesNegated: false,
    scanId: null,
    scanScope: "seen",
    reported: "all",
    reportedLive: null,
    reused: null,
    noOrg: false,
    canary: false,
    from: null,
    to: null,
    text: "",
  };
}

function pageSize(text: string | null): number | null {
  return PAGE_SIZES.find((size) => String(size) === text) ?? null;
}

function rememberedPerPage(): number {
  try {
    return pageSize(window.localStorage.getItem(PER_PAGE_KEY)) ?? PER_PAGE;
  } catch {
    return PER_PAGE;
  }
}

function rememberPerPage(size: number): void {
  try {
    if (size === PER_PAGE) window.localStorage.removeItem(PER_PAGE_KEY);
    else window.localStorage.setItem(PER_PAGE_KEY, String(size));
  } catch {}
}

function defaultQuery(): Query {
  return {
    filters: noFilters(),
    view: "unique",
    sort: "date",
    order: "desc",
    page: 1,
    perPage: rememberedPerPage(),
  };
}

function strings(value: LocationQueryRaw[string]): string[] {
  const all = Array.isArray(value) ? value : [value];
  return [...new Set(all.filter((v): v is string => typeof v === "string" && v !== ""))];
}

function first(value: LocationQueryRaw[string]): string | null {
  return strings(value)[0] ?? null;
}

function rowId(text: string): number | null {
  if (!/^[1-9]\d{0,15}$/.test(text)) return null;
  const id = Number(text);
  return Number.isSafeInteger(id) ? id : null;
}

function oneOf<T extends string>(choices: Record<T, unknown>, text: string | null): T | null {
  return text !== null && Object.hasOwn(choices, text) ? (text as T) : null;
}

export function dateOf(text: string, days = 0): Date {
  const [y, m, d] = text.split("-").map(Number) as [number, number, number];
  return new Date(y, m - 1, d + days);
}

const pad = (n: number, width = 2): string => String(n).padStart(width, "0");

export function dayOf(date: Date): string {
  return `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function day(text: string | null): string | null {
  if (text === null || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return null;
  return dayOf(dateOf(text)) === text ? text : null;
}

function midnight(text: string, days = 0): string {
  return dateOf(text, days).toISOString();
}

export function apiFilters(filters: Filters): Schemas["ListQueryIn.FiltersIn"] {
  return {
    orgs: [...filters.orgs],
    repository_ids: [...filters.repositoryIds],
    paths: [...filters.paths],
    kinds: [...filters.kinds],
    kinds_negated: filters.kindsNegated,
    tools: [...filters.tools],
    statuses: [...filters.statuses],
    statuses_negated: filters.statusesNegated,
    scan_id: filters.scanId,
    scan_scope: filters.scanScope,
    reported: filters.reported,
    reported_live: filters.reportedLive,
    reused: filters.reused,
    no_org: filters.noOrg,
    canary: filters.canary,
    authored_from: filters.from === null ? null : midnight(filters.from),
    authored_to: filters.to === null ? null : midnight(filters.to, 1),
    text: filters.text === "" ? null : filters.text,
  };
}

function choices(query: Query): string {
  return JSON.stringify({ ...query.filters, text: undefined, view: query.view });
}

function indexOf(rows: Row[], subject: Subject): number {
  return rows.findIndex((r) => r.kind === subject.kind && r.id === subject.id);
}

function nearest(rows: Row[], from: number, step: 1 | -1, key: string): Neighbour | null {
  for (let i = from + step; i >= 0 && i < rows.length; i += step) {
    const row = rows[i] as Row;
    if (subjectKey(row) !== key)
      return { kind: row.kind, id: row.id, finding: row.anchor_finding_id };
  }
  return null;
}

export const MAX_OWN_BATCHES = 50;

let generation = 0;
let canaryAsk = 0;

interface State {
  query: Query;
  valueSearch: ValueSearch | null;
  rows: Row[];
  page: number;
  perPage: number;
  totalFindings: number;
  totalUnique: number;
  byStatus: NonNullable<ListPage["by_status"]>;
  byTool: NonNullable<ListPage["by_tool"]>;
  possibleCanaries: Set<string>;
  canaryUnchecked: boolean;
  summaryOwed: boolean;
  bound: Bound | null;
  lastChangeId: number;
  boundChangeId: number;
  loaded: boolean;
  loading: boolean;
  selection: Map<string, Subject>;
  selectionSeen: number | null;
  ownBatches: string[];
  matchingAll: boolean;
  adjacent: Map<number, ListPage>;
  seen: Map<string, Row>;
}

export const useTriage = defineStore("triage", {
  state: (): State => ({
    query: defaultQuery(),
    valueSearch: null,
    rows: [],
    page: 1,
    perPage: PER_PAGE,
    totalFindings: 0,
    totalUnique: 0,
    byStatus: [],
    byTool: [],
    possibleCanaries: new Set(),
    canaryUnchecked: false,
    summaryOwed: false,
    bound: null,
    lastChangeId: 0,
    boundChangeId: 0,
    loaded: false,
    loading: false,
    selection: new Map(),
    selectionSeen: null,
    ownBatches: [],
    matchingAll: false,
    adjacent: new Map(),
    seen: new Map(),
  }),
  getters: {
    totalRows: (state): number =>
      state.query.view === "unique" ? state.totalUnique : state.totalFindings,
    selectedCount: (state): number =>
      state.matchingAll ? state.totalUnique : state.selection.size,
    pageSelected: (state): boolean =>
      state.rows.length > 0 && state.rows.every((r) => state.selection.has(subjectKey(r))),
  },
  actions: {
    toRoute(): LocationQueryRaw {
      const { filters, view, sort, order, page, perPage } = this.query;
      const query: LocationQueryRaw = {};
      if (filters.orgs.length > 0) query.org = [...filters.orgs];
      if (filters.noOrg) query.noorg = "1";
      if (filters.repositoryIds.length > 0) query.repo = filters.repositoryIds.map(String);
      if (filters.paths.length > 0) query.file = [...filters.paths];
      if (filters.kinds.length > 0) query.kind = [...filters.kinds];
      if (filters.kindsNegated) query.notkind = "1";
      if (filters.tools.length > 0) query.tool = [...filters.tools];
      if (filters.statuses.length > 0) query.status = [...filters.statuses];
      if (filters.statusesNegated) query.not = "1";
      if (filters.scanId !== null) {
        query.scan = String(filters.scanId);
        if (filters.scanScope !== "seen") query.scope = filters.scanScope;
      }
      if (filters.reported !== "all") query.reported = filters.reported;
      if (filters.reportedLive !== null) query.live = filters.reportedLive ? "1" : "0";
      if (filters.reused !== null) query.reused = filters.reused ? "1" : "0";
      if (filters.canary) query.canary = "1";
      if (filters.from !== null) query.from = filters.from;
      if (filters.to !== null) query.to = filters.to;
      if (view !== "unique") query.view = view;
      if (sort !== "date") query.sort = sort;
      if (order !== "desc") query.order = order;
      if (page !== 1) query.page = String(page);
      if (perPage !== PER_PAGE) query.per = String(perPage);
      return query;
    },
    fromRoute(route: LocationQueryRaw): boolean {
      const before = JSON.stringify(this.query);
      const beforeChoices = choices(this.query);
      const scanId = rowId(first(route.scan) ?? "");
      const sort = oneOf(SORTS, first(route.sort));
      const page = rowId(first(route.page) ?? "");
      const live = first(route.live);
      const reused = first(route.reused);
      this.query = {
        filters: {
          orgs: strings(route.org),
          repositoryIds: strings(route.repo)
            .map(rowId)
            .filter((id): id is number => id !== null),
          paths: strings(route.file)
            .filter((path) => path.length <= MAX_PATH_CHARS)
            .slice(0, MAX_PATHS),
          kinds: strings(route.kind),
          kindsNegated: first(route.notkind) === "1",
          tools: strings(route.tool).filter((t): t is ToolName => Object.hasOwn(TOOLS, t)),
          statuses: strings(route.status).filter((s): s is SecretStatus =>
            Object.hasOwn(SECRET_STATUSES, s),
          ),
          statusesNegated: first(route.not) === "1",
          scanId,
          scanScope: oneOf(SCAN_SCOPES, first(route.scope)) ?? "seen",
          reported: oneOf(REPORTED_SCOPES, first(route.reported)) ?? "all",
          reportedLive: live === "1" ? true : live === "0" ? false : null,
          reused: reused === "1" ? true : reused === "0" ? false : null,
          noOrg: first(route.noorg) === "1",
          canary: first(route.canary) === "1",
          from: day(first(route.from)),
          to: day(first(route.to)),
          text: this.query.filters.text,
        },
        view: oneOf(VIEWS, first(route.view)) ?? "unique",
        sort: sort ?? "date",
        order: first(route.order) === "asc" ? "asc" : "desc",
        page: page !== null && page <= MAX_PAGE ? page : 1,
        perPage: pageSize(first(route.per)) ?? rememberedPerPage(),
      };
      const subjectSort = this.query.sort === "value" || this.query.sort === "findings";
      if (subjectSort && this.query.view !== "unique") this.query.sort = "date";
      if (choices(this.query) !== beforeChoices) this.clearSelection();
      return JSON.stringify(this.query) !== before;
    },
    body(page: number, summary = true): Schemas["ListQueryIn"] {
      const { filters, view, sort, order } = this.query;
      return {
        filters: apiFilters(filters),
        view,
        sort,
        order,
        page,
        per_page: this.query.perPage,
        value_search: this.valueSearch,
        summary,
      };
    },
    async load(summary = true): Promise<boolean> {
      const mine = ++generation;
      const asking = summary || !this.loaded || this.summaryOwed;
      this.summaryOwed = asking;
      this.loading = true;
      try {
        const page = await api<ListPage>("/api/triage/query", {
          method: "POST",
          body: this.body(this.query.page, asking),
        });
        if (mine !== generation) return false;
        this.apply(page);
        void this.checkCanaries();
        return true;
      } catch (failure) {
        if (mine === generation) throw failure;
        return false;
      } finally {
        if (mine === generation) this.loading = false;
      }
    },
    apply(page: ListPage): void {
      this.rows = page.items;
      this.page = page.page;
      this.query.page = page.page;
      this.perPage = page.per_page;
      if (page.total_findings !== null && page.total_unique !== null) {
        this.totalFindings = page.total_findings;
        this.totalUnique = page.total_unique;
        this.bound = page.bound;
        this.boundChangeId = page.last_change_id;
        this.summaryOwed = false;
      }
      if (page.by_status !== null) this.byStatus = page.by_status;
      if (page.by_tool !== null) this.byTool = page.by_tool;
      this.possibleCanaries = new Set();
      this.canaryUnchecked = false;
      this.lastChangeId = page.last_change_id;
      this.loaded = true;
      this.adjacent = new Map();
      for (const row of page.items) {
        const key = subjectKey(row);
        if (!this.seen.has(key)) this.seen.set(key, row);
      }
    },
    async checkCanaries(): Promise<void> {
      const mine = ++canaryAsk;
      const asked = [...new Map(this.rows.map((row) => [subjectKey(row), row])).values()];
      if (asked.length === 0) return;
      if (this.query.filters.canary) {
        this.possibleCanaries = new Set(asked.map(subjectKey));
        return;
      }
      try {
        const found = await api<Canaries>("/api/triage/canaries", {
          method: "POST",
          body: { subjects: asked.map((row) => ({ kind: row.kind, id: row.id })) },
        });
        if (mine !== canaryAsk) return;
        this.possibleCanaries = new Set(found.possible.map(subjectKey));
        this.canaryUnchecked = found.unchecked;
      } catch {
        if (mine === canaryAsk) this.canaryUnchecked = true;
      }
    },
    possibleCanary(subject: Subject): boolean {
      return this.possibleCanaries.has(subjectKey(subject));
    },
    setFilters(patch: Partial<Filters>): void {
      this.query.filters = { ...this.query.filters, ...patch };
      this.query.page = 1;
      this.clearSelection();
    },
    setView(view: View): void {
      this.query.view = view;
      if (view === "all" && (this.query.sort === "value" || this.query.sort === "findings")) {
        this.query.sort = "date";
      }
      this.query.page = 1;
      this.clearSelection();
    },
    setSort(sort: ListSort, order: Order): void {
      this.query.sort = sort;
      this.query.order = order;
      this.query.page = 1;
    },
    setPage(page: number): void {
      this.query.page = page;
    },
    setPerPage(size: number): void {
      const chosen = pageSize(String(size));
      if (chosen === null || chosen === this.query.perPage) return;
      const firstRow = (this.query.page - 1) * this.query.perPage;
      this.query.perPage = chosen;
      this.query.page = Math.floor(firstRow / chosen) + 1;
      rememberPerPage(chosen);
    },
    setValueSearch(search: ValueSearch | null): void {
      this.valueSearch = search;
      this.query.page = 1;
      this.clearSelection();
    },
    toggle(subject: Subject, on: boolean): void {
      const key = subjectKey(subject);
      this.matchingAll = false;
      if (on) {
        this.selection.set(key, { kind: subject.kind, id: subject.id });
        this.selectionSeen = Math.min(this.selectionSeen ?? this.lastChangeId, this.lastChangeId);
      } else {
        this.selection.delete(key);
        if (this.selection.size === 0) this.selectionSeen = null;
      }
    },
    selectPage(on: boolean): void {
      for (const row of this.rows) this.toggle(row, on);
    },
    selectAllMatching(): void {
      if (this.bound !== null) this.matchingAll = true;
    },
    listGeneration(): number {
      return generation;
    },
    endMatchingAll(asked: number): boolean {
      if (asked !== generation) return false;
      this.matchingAll = false;
      return true;
    },
    clearSelection(): void {
      this.selection = new Map();
      this.selectionSeen = null;
      this.ownBatches = [];
      this.matchingAll = false;
    },
    exportBody(format: ExportFormat, includeValues: boolean): Schemas["ExportIn"] {
      return {
        filters: apiFilters(this.query.filters),
        view: this.query.view,
        sort: this.query.sort,
        order: this.query.order,
        value_search: this.valueSearch,
        format,
        include_values: includeValues,
      };
    },
    statsBody(): Schemas["StatsIn"] {
      return {
        filters: apiFilters(this.query.filters),
        view: this.query.view,
        value_search: this.valueSearch,
      };
    },
    valuesTarget():
      | { subjects: NonNullable<Schemas["ValuesIn"]["subjects"]> }
      | { matching: NonNullable<Schemas["ValuesIn"]["matching"]> } {
      if (this.matchingAll && this.bound !== null) {
        return {
          matching: {
            filters: apiFilters(this.query.filters),
            view: this.query.view,
            value_search: this.valueSearch,
            bound: { ...this.bound },
          },
        };
      }
      return { subjects: [...this.selection.values()] };
    },
    async setStatus(
      status: SecretStatus,
      note: string | null = null,
      across: number | null = null,
    ): Promise<StatusResult> {
      const text = note?.trim() ?? "";
      const target =
        this.matchingAll && this.bound !== null
          ? {
              filters: apiFilters(this.query.filters),
              view: this.query.view,
              value_search: this.valueSearch,
              bound: { ...this.bound },
            }
          : { subjects: [...this.selection.values()] };
      const seen = this.matchingAll
        ? this.boundChangeId
        : (this.selectionSeen ?? this.lastChangeId);
      const result = await api<StatusResult>("/api/triage/status", {
        method: "POST",
        body: {
          target,
          status,
          seen_change_id: seen,
          own_batches: this.matchingAll ? [] : [...this.ownBatches],
          note: text === "" ? null : text,
          across_repositories: across,
        },
      });
      this.clearSelection();
      return result;
    },
    async setSubjectStatus(
      subject: Subject,
      status: SecretStatus,
      from?: { seen: number; ownBatches: string[] },
      across: number | null = null,
    ): Promise<StatusResult> {
      const result = await api<StatusResult>("/api/triage/status", {
        method: "POST",
        body: {
          target: { subjects: [{ kind: subject.kind, id: subject.id }] },
          status,
          seen_change_id: from?.seen ?? this.lastChangeId,
          own_batches: from?.ownBatches ?? [],
          note: null,
          across_repositories: across,
        },
      });
      if (result.changed > 0 && this.selection.size > 0) {
        this.ownBatches = [...this.ownBatches, result.batch_id].slice(-MAX_OWN_BATCHES);
      }
      if (result.changed > 0 && !this.matchingAll && !this.statusFits(status)) {
        this.selection.delete(subjectKey(subject));
        if (this.selection.size === 0) this.selectionSeen = null;
      }
      return result;
    },
    statusFits(status: SecretStatus): boolean {
      const { statuses, statusesNegated } = this.query.filters;
      if (statuses.length === 0) return true;
      return statuses.includes(status) !== statusesNegated;
    },
    async adjacentPage(page: number): Promise<ListPage | null> {
      const known = this.adjacent.get(page);
      if (known !== undefined) return known;
      const mine = generation;
      const read = await api<ListPage>("/api/triage/query", {
        method: "POST",
        body: this.body(page, false),
      });
      if (mine !== generation) return null;
      this.adjacent.set(page, read);
      return read;
    },
    async neighbours(current: Subject): Promise<Neighbours> {
      let at = indexOf(this.rows, current);
      if (at === -1) {
        const found = [...this.adjacent.values()].find((p) => indexOf(p.items, current) !== -1);
        if (found === undefined) return { previous: null, next: null };
        const left: ListPage = {
          items: this.rows,
          page: this.page,
          per_page: this.perPage,
          total_findings: this.totalFindings,
          total_unique: this.totalUnique,
          by_status: this.byStatus,
          by_tool: this.byTool,
          bound: this.bound as Bound,
          last_change_id: this.lastChangeId,
        };
        this.apply(found);
        void this.checkCanaries();
        this.adjacent.set(left.page, left);
        at = indexOf(this.rows, current);
      }
      const none = { previous: null, next: null };
      const key = subjectKey(current);
      let previous = nearest(this.rows, at, -1, key);
      if (previous === null && this.page > 1) {
        const before = await this.adjacentPage(this.page - 1);
        if (before === null) return none;
        previous = nearest(before.items, before.items.length, -1, key);
      }
      let next = nearest(this.rows, at, 1, key);
      if (next === null && this.page * this.perPage < this.totalRows) {
        const after = await this.adjacentPage(this.page + 1);
        if (after === null) return none;
        next = nearest(after.items, -1, 1, key);
      }
      return { previous, next };
    },
    leaveTriage(): void {
      generation += 1;
      canaryAsk += 1;
      this.$reset();
    },
  },
});
