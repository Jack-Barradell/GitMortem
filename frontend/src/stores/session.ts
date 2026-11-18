import { defineStore } from "pinia";
import {
  api,
  ApiError,
  forgetSessionKey,
  rememberSessionKey,
  resetCsrfToken,
  type Me,
} from "@/api/client";
import { announceSignedOut } from "@/sessionChannel";
import { useTriage } from "@/stores/triage";

interface State {
  user: Me | null;
  loaded: boolean;
}

export const useSession = defineStore("session", {
  state: (): State => ({ user: null, loaded: false }),
  getters: {
    isAdmin: (state): boolean => state.user?.role === "admin",
  },
  actions: {
    async load(): Promise<void> {
      try {
        this.user = await api<Me>("/api/auth/me");
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) throw error;
        this.user = null;
      }
      this.loaded = true;
    },
    async login(username: string, password: string): Promise<void> {
      const signedIn = await api<Me & { session_key: string }>("/api/auth/login", {
        method: "POST",
        body: { username, password },
      });
      if (typeof signedIn.session_key === "string") rememberSessionKey(signedIn.session_key);
      this.user = {
        id: signedIn.id,
        username: signedIn.username,
        role: signedIn.role,
        idle_timeout_seconds: signedIn.idle_timeout_seconds,
        must_change_password: signedIn.must_change_password,
      };
      this.loaded = true;
      resetCsrfToken();
    },
    async logout(): Promise<void> {
      try {
        await api<void>("/api/auth/logout", { method: "POST" });
      } finally {
        this.user = null;
        useTriage().leaveTriage();
        resetCsrfToken();
        forgetSessionKey();
        announceSignedOut();
      }
    },
    passwordChanged(): void {
      if (this.user) this.user = { ...this.user, must_change_password: false };
    },
    clear(): void {
      this.user = null;
      useTriage().leaveTriage();
      this.loaded = true;
    },
  },
});
