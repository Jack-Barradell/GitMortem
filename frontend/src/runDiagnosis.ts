import type { components } from "@/api/schema";
import { TRACE_PROBLEMS, TRACE_UNREAD } from "@/labels";

type Diagnosis = components["schemas"]["ToolRunPageOut.RunDiagnosis"];
type GitEnd = components["schemas"]["ToolRunPageOut.GitEnd"];
type Unread = components["schemas"]["ToolRunPageOut.TraceUnread"];

const SIGNALS: Readonly<Record<number, string>> = {
  1: "SIGHUP",
  2: "SIGINT",
  3: "SIGQUIT",
  6: "SIGABRT",
  9: "SIGKILL",
  11: "SIGSEGV",
  13: "SIGPIPE",
  14: "SIGALRM",
  15: "SIGTERM",
};
const SHELL_SIGNALLED = 128;
const HIGHEST_SIGNAL = 64;
const KILLED_OUTRIGHT = "killed outright, as by SIGKILL or the out-of-memory killer";

export function signalText(signal: number): string {
  const name = SIGNALS[signal];
  return name === undefined ? `signal ${signal}` : `signal ${signal} (${name})`;
}

export function exitCodeText(code: number): string {
  if (code < 0) return `killed by ${signalText(-code)}`;
  if (code > SHELL_SIGNALLED && code <= SHELL_SIGNALLED + HIGHEST_SIGNAL) {
    const signal = signalText(code - SHELL_SIGNALLED);
    return `exit code ${code}: 128 + ${signal}, as a shell reports a command killed by it`;
  }
  return `exit code ${code}`;
}

function times(count: number): string {
  return count === 1 ? "" : `, ${count.toLocaleString("en-US")} times`;
}

function endText(end: GitEnd): string {
  const git = `git ${end.command}`;
  if (end.signal !== null && end.signal > 0)
    return `${git} was killed by ${signalText(end.signal)}${times(end.count)}`;
  if (end.signal !== null) return `${git} was stopped by a signal${times(end.count)}`;
  if (end.code !== null) return `${git} exited with code ${end.code}${times(end.count)}`;
  return `${git} never recorded its end${times(end.count)}: ${KILLED_OUTRIGHT}`;
}

function problemText(problem: string, unread: Unread | null): string {
  if (unread === null) return problem;
  const error = unread.error === null ? "" : ` (error ${unread.error})`;
  return `${problem}: ${TRACE_UNREAD[unread.reason]}${error}`;
}

export function gitLines(diagnosis: Diagnosis | null, tool: string): string[] {
  const git = diagnosis?.git ?? null;
  if (git === null) return [];
  const lines = git.ends.map(endText);
  if (git.more > 0) {
    const kinds = git.more === 1 ? "process" : "processes";
    lines.push(`${git.more.toLocaleString("en-US")} more git ${kinds} ended in other ways`);
  }
  if (git.problem !== null) lines.push(problemText(TRACE_PROBLEMS[git.problem], git.unread));
  if (git.needed !== null) lines.push(`${tool}'s own git ${git.needed} did not finish`);
  return lines;
}
