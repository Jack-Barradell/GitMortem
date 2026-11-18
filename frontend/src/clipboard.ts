export async function copyText(text: string): Promise<"copied" | "manual"> {
  if (window.isSecureContext && navigator.clipboard !== undefined) {
    try {
      await navigator.clipboard.writeText(text);
      return "copied";
    } catch {}
  }
  const before = document.activeElement;
  const area = document.createElement("textarea");
  area.value = text;
  area.readOnly = true;
  area.className = "pointer-events-none fixed top-0 left-0 opacity-0";
  area.setAttribute("aria-hidden", "true");
  document.body.append(area);
  area.focus();
  area.select();
  let copied: boolean;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  } finally {
    area.value = "";
    area.remove();
    if (before instanceof HTMLElement) before.focus();
  }
  return copied ? "copied" : "manual";
}
