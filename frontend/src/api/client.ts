import { announceActivity } from "@/sessionChannel";
import type { components } from "./schema";

export type Me = components["schemas"]["MeOut"];
export type Role = Me["role"];

const CSRF_PATH = "/api/auth/csrf";
const CSRF_REJECTED = "CSRF token missing or invalid.";
export const SESSION_KEY_STORE = "gitmortem.session-key";
export const SESSION_KEY_HEADER = "X-GitMortem-Session";
export const BACKGROUND_HEADER = "X-GitMortem-Background";

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly retryAfter: number | null;

  constructor(status: number, message: string, body: unknown, retryAfter: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfter = retryAfter;
  }
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";
interface Options {
  method?: Method;
  body?: unknown;
  background?: boolean;
}

let unauthorized: () => void = () => {};
let passwordPrompter: () => Promise<boolean> = () => Promise.resolve(false);
let passwordChangeNeeded: () => void = () => {};
let pendingPrompt: Promise<boolean> | null = null;
let csrfToken: Promise<string> | null = null;
let lastRequest = 0;

export function setUnauthorizedHandler(fn: () => void): void {
  unauthorized = fn;
}

export function setPasswordPrompter(fn: () => Promise<boolean>): void {
  passwordPrompter = fn;
}

export function setPasswordChangeHandler(fn: () => void): void {
  passwordChangeNeeded = fn;
}

export function reasonIn(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("detail" in body)) return null;
  const { detail } = body;
  if (typeof detail !== "object" || detail === null || !("reason" in detail)) return null;
  const { reason } = detail;
  return typeof reason === "string" ? reason : null;
}

function promptForPassword(): Promise<boolean> {
  pendingPrompt ??= passwordPrompter().finally(() => {
    pendingPrompt = null;
  });
  return pendingPrompt;
}

export function lastRequestAt(): number {
  return lastRequest;
}

export function noteActivityElsewhere(at: number): void {
  lastRequest = Math.max(lastRequest, at);
}

export function resetCsrfToken(): void {
  csrfToken = null;
}

export function rememberSessionKey(key: string): void {
  try {
    localStorage.setItem(SESSION_KEY_STORE, key);
  } catch {}
}

export function forgetSessionKey(): void {
  try {
    localStorage.removeItem(SESSION_KEY_STORE);
  } catch {}
}

function sessionKey(): string | null {
  try {
    return localStorage.getItem(SESSION_KEY_STORE);
  } catch {
    return null;
  }
}

function fetchCsrfToken(): Promise<string> {
  csrfToken ??= request(CSRF_PATH, "GET")
    .then(async (response) => {
      const body = await readBody(response);
      if (!response.ok) throw errorFrom(response, body);
      return (body as { csrf_token: string }).csrf_token;
    })
    .catch((error: unknown) => {
      csrfToken = null;
      throw error;
    });
  return csrfToken;
}

function request(
  path: string,
  method: Method,
  body?: unknown,
  token?: string,
  background = false,
): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token !== undefined) headers["X-CSRFToken"] = token;
  const key = sessionKey();
  if (key !== null) headers[SESSION_KEY_HEADER] = key;
  if (background) headers[BACKGROUND_HEADER] = "1";
  return fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text === "") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function messageOf(body: unknown, status: number): string {
  if (typeof body === "object" && body !== null && "message" in body) {
    const { message } = body;
    if (typeof message === "string" && message !== "") return message;
  }
  return `Request failed (${status}).`;
}

function retryAfterOf(response: Response): number | null {
  const seconds = Number(response.headers.get("Retry-After"));
  return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
}

function errorFrom(response: Response, body: unknown): ApiError {
  return new ApiError(
    response.status,
    messageOf(body, response.status),
    body,
    retryAfterOf(response),
  );
}

export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const background = opts.background ?? false;
  if (!background) {
    lastRequest = Date.now();
    announceActivity(lastRequest);
  }
  const attempt = async (): Promise<Response> =>
    request(
      path,
      method,
      opts.body,
      method === "GET" ? undefined : await fetchCsrfToken(),
      background,
    );

  let response = await attempt();
  let body = await readBody(response);
  if (response.status === 400 && method !== "GET" && messageOf(body, 400) === CSRF_REJECTED) {
    resetCsrfToken();
    response = await attempt();
    body = await readBody(response);
  }
  if (response.status === 403 && !background && reasonIn(body) === "password_needed") {
    if (await promptForPassword()) {
      response = await attempt();
      body = await readBody(response);
    }
  }

  if (response.status === 204) return undefined as T;
  if (response.ok) return body as T;
  if (response.status === 401) unauthorized();
  if (response.status === 403 && reasonIn(body) === "password_change_needed") {
    passwordChangeNeeded();
  }
  throw errorFrom(response, body);
}

export interface Download {
  blob: Blob;
  filename: string;
}

function filenameOf(response: Response): string {
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const named = /filename="([^"]+)"/.exec(disposition);
  return named?.[1] ?? "gitmortem-export";
}

export async function download(path: string, body: unknown): Promise<Download> {
  lastRequest = Date.now();
  announceActivity(lastRequest);
  const attempt = async (): Promise<Response> =>
    request(path, "POST", body, await fetchCsrfToken());

  let response = await attempt();
  if (!response.ok) {
    let error = await readBody(response);
    if (response.status === 400 && messageOf(error, 400) === CSRF_REJECTED) {
      resetCsrfToken();
      response = await attempt();
      if (response.ok) return { blob: await response.blob(), filename: filenameOf(response) };
      error = await readBody(response);
    }
    if (response.status === 401) unauthorized();
    throw errorFrom(response, error);
  }
  return { blob: await response.blob(), filename: filenameOf(response) };
}
