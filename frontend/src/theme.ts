import { ref, type Ref } from "vue";

export type ThemeChoice = "system" | "light" | "dark";

export const THEME_KEY = "gitmortem.theme";
const CHOICES: readonly ThemeChoice[] = ["system", "light", "dark"];

export interface ThemeEnvironment {
  root: HTMLElement;
  storage: Storage | null;
  media: MediaQueryList | null;
}

export interface Theme {
  choice: Ref<ThemeChoice>;
  dark: Ref<boolean>;
  set(choice: ThemeChoice): void;
}

function read(storage: Storage | null): ThemeChoice {
  try {
    const held = storage?.getItem(THEME_KEY);
    return CHOICES.includes(held as ThemeChoice) ? (held as ThemeChoice) : "system";
  } catch {
    return "system";
  }
}

function write(storage: Storage | null, choice: ThemeChoice): void {
  try {
    if (choice === "system") storage?.removeItem(THEME_KEY);
    else storage?.setItem(THEME_KEY, choice);
  } catch {}
}

function browserEnvironment(): ThemeEnvironment {
  let storage: Storage | null;
  try {
    storage = window.localStorage;
  } catch {
    storage = null;
  }
  const media =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-color-scheme: dark)")
      : null;
  return { root: document.documentElement, storage, media };
}

export function installTheme(environment: ThemeEnvironment = browserEnvironment()): Theme {
  const { root, storage, media } = environment;
  const choice = ref<ThemeChoice>(read(storage));
  const dark = ref(false);

  function apply(): void {
    dark.value = choice.value === "dark" || (choice.value === "system" && media?.matches === true);
    root.classList.toggle("dark", dark.value);
    root.classList.toggle("light", choice.value === "light");
  }

  media?.addEventListener("change", () => {
    if (choice.value === "system") apply();
  });
  apply();

  installed = {
    choice,
    dark,
    set(next: ThemeChoice): void {
      choice.value = next;
      write(storage, next);
      apply();
    },
  };
  return installed;
}

let installed: Theme | null = null;

export function useTheme(): Theme {
  return installed ?? installTheme();
}
