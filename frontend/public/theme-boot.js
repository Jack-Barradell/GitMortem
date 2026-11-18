(() => {
  const stored = () => {
    try {
      return window.localStorage.getItem("gitmortem.theme");
    } catch {
      return null;
    }
  };
  const choice = stored();
  const system =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches;
  const root = document.documentElement;
  root.classList.toggle("dark", choice === "dark" || (choice !== "light" && system));
  root.classList.toggle("light", choice === "light");
})();
