import type { Router } from "vue-router";
import { lastRequestAt, noteActivityElsewhere } from "@/api/client";
import { leaveForSignIn } from "@/router";
import { onActivityElsewhere, onSignedOutElsewhere } from "@/sessionChannel";
import { useSession } from "@/stores/session";

export const CHECK_EVERY_MS = 15_000;

export function installSessionWatch(router: Router, now: () => number = Date.now): () => void {
  const timer = setInterval(() => {
    const user = useSession().user;
    if (user !== null && now() - lastRequestAt() >= user.idle_timeout_seconds * 1000) {
      leaveForSignIn(router);
    }
  }, CHECK_EVERY_MS);
  const stopListening = onSignedOutElsewhere(() => {
    if (useSession().user !== null) leaveForSignIn(router);
  });
  const stopHearing = onActivityElsewhere(noteActivityElsewhere);
  const onVisible = (): void => {
    const session = useSession();
    if (document.visibilityState === "visible" && session.user !== null) {
      session.load().catch(() => {});
    }
  };
  document.addEventListener("visibilitychange", onVisible);
  return () => {
    clearInterval(timer);
    stopListening();
    stopHearing();
    document.removeEventListener("visibilitychange", onVisible);
  };
}
