import { onBeforeUnmount } from "vue";

export const POLL_MS = 2000;

export function usePolling(step: () => Promise<boolean>, intervalMs = POLL_MS) {
  let wanted = false;
  let busy = false;
  let run = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function call(current: number): Promise<void> {
    timer = undefined;
    busy = true;
    let again = false;
    try {
      again = await step();
    } finally {
      busy = false;
      if (current !== run) {
        if (wanted) void call(run);
      } else if (again && wanted) {
        timer = setTimeout(() => void call(current), intervalMs);
      } else {
        wanted = false;
      }
    }
  }

  function start(): void {
    if (wanted) return;
    wanted = true;
    run += 1;
    if (!busy) void call(run);
  }

  function stop(): void {
    wanted = false;
    run += 1;
    clearTimeout(timer);
    timer = undefined;
  }

  onBeforeUnmount(stop);
  return { start, stop };
}
