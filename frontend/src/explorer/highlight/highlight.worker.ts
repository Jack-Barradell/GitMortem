import {
  createCssVariablesTheme,
  createHighlighterCore,
  type GrammarState,
  type HighlighterCore,
  type LanguageRegistration,
} from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import {
  MAX_HIGHLIGHT_LINE_CHARS,
  encodeChunk,
  lineBody,
  type HighlightReply,
  type HighlightRequest,
} from "./encode";
import type { LangId } from "./languages";

const CHUNK_LINES = 500;
const SHIKI_MAX_LINE_LENGTH = MAX_HIGHLIGHT_LINE_CHARS + 1;
const LINE_TIME_LIMIT_MS = 500;
const BUDGET_MS = 10_000;
const THEME = "gm";

type Grammar = { default: LanguageRegistration[] };

const GRAMMARS: Record<LangId, () => Promise<Grammar>> = {
  javascript: () => import("@shikijs/langs/javascript"),
  jsx: () => import("@shikijs/langs/jsx"),
  typescript: () => import("@shikijs/langs/typescript"),
  tsx: () => import("@shikijs/langs/tsx"),
  python: () => import("@shikijs/langs/python"),
  go: () => import("@shikijs/langs/go"),
  java: () => import("@shikijs/langs/java"),
  json: () => import("@shikijs/langs/json"),
  yaml: () => import("@shikijs/langs/yaml"),
  toml: () => import("@shikijs/langs/toml"),
  ini: () => import("@shikijs/langs/ini"),
  properties: () => import("@shikijs/langs/properties"),
  dotenv: () => import("@shikijs/langs/dotenv"),
  shellscript: () => import("@shikijs/langs/shellscript"),
  docker: () => import("@shikijs/langs/docker"),
  xml: () => import("@shikijs/langs/xml"),
  html: () => import("@shikijs/langs/html"),
  markdown: () => import("@shikijs/langs/markdown"),
  sql: () => import("@shikijs/langs/sql"),
  ruby: () => import("@shikijs/langs/ruby"),
  php: () => import("@shikijs/langs/php"),
  c: () => import("@shikijs/langs/c"),
  cpp: () => import("@shikijs/langs/cpp"),
  csharp: () => import("@shikijs/langs/csharp"),
  terraform: () => import("@shikijs/langs/terraform"),
};

interface WorkerScope {
  onmessage: ((event: MessageEvent<HighlightRequest>) => void) | null;
  postMessage(reply: HighlightReply, transfer: Transferable[]): void;
}
const scope = self as unknown as WorkerScope;

let highlighter: Promise<HighlighterCore> | undefined;
let current = 0;

async function loaded(lang: LangId): Promise<HighlighterCore> {
  highlighter ??= createHighlighterCore({
    themes: [createCssVariablesTheme({ name: THEME, variablePrefix: "--gm-" })],
    langs: [],
    engine: createJavaScriptRegexEngine(),
  });
  const core = await highlighter;
  if (!core.getLoadedLanguages().includes(lang)) {
    await core.loadLanguage((await GRAMMARS[lang]()).default);
  }
  return core;
}

const messagesRead = () => new Promise<void>((resolve) => setTimeout(resolve));

async function highlight(id: number, text: string, lang: LangId): Promise<void> {
  const core = await loaded(lang);
  const lines = text.split("\n");
  let grammarState: GrammarState | undefined;
  let spent = 0;
  for (let from = 0; from < lines.length && spent < BUDGET_MS; from += CHUNK_LINES) {
    if (current !== id) return;
    const chunk = lines.slice(from, from + CHUNK_LINES);
    const started = performance.now();
    const result = core.codeToTokens(chunk.map(lineBody).join("\n"), {
      lang,
      theme: THEME,
      grammarState,
      tokenizeMaxLineLength: SHIKI_MAX_LINE_LENGTH,
      tokenizeTimeLimit: LINE_TIME_LIMIT_MS,
    });
    spent += performance.now() - started;
    grammarState = result.grammarState;
    const data = encodeChunk(chunk, result.tokens);
    scope.postMessage({ kind: "chunk", id, data }, [data.buffer]);
    await messagesRead();
  }
  if (current === id) scope.postMessage({ kind: "end", id }, []);
}

scope.onmessage = (event) => {
  const request = event.data;
  if (request.kind === "stop") {
    if (current === request.id) current = 0;
    return;
  }
  current = request.id;
  highlight(request.id, request.text, request.lang).catch(() => {
    scope.postMessage({ kind: "failed", id: request.id }, []);
  });
};
