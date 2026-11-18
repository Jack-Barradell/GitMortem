const NAME = "gitmortem-session";
const SIGNED_OUT = "signed-out";

interface Activity {
  activity: number;
}

let channel: BroadcastChannel | null = null;

function open(): BroadcastChannel | null {
  if (channel === null && typeof BroadcastChannel === "function") {
    channel = new BroadcastChannel(NAME);
  }
  return channel;
}

function subscribe(listener: (data: unknown) => void): () => void {
  const ch = open();
  if (ch === null) return () => {};
  const handler = (event: MessageEvent): void => listener(event.data);
  ch.addEventListener("message", handler);
  return () => ch.removeEventListener("message", handler);
}

function isActivity(data: unknown): data is Activity {
  return (
    typeof data === "object" &&
    data !== null &&
    "activity" in data &&
    typeof data.activity === "number"
  );
}

export function announceSignedOut(): void {
  open()?.postMessage(SIGNED_OUT);
}

export function announceActivity(at: number): void {
  const message: Activity = { activity: at };
  open()?.postMessage(message);
}

export function onSignedOutElsewhere(fn: () => void): () => void {
  return subscribe((data) => {
    if (data === SIGNED_OUT) fn();
  });
}

export function onActivityElsewhere(fn: (at: number) => void): () => void {
  return subscribe((data) => {
    if (isActivity(data)) fn(data.activity);
  });
}
