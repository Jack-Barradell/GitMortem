export const SIDEBAR_KEY = "gitmortem.sidebar";

export interface NavLink {
  to: string;
  label: string;
  icon: string;
}

export interface NavGroup {
  label: string;
  adminOnly: boolean;
  links: NavLink[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Triage",
    adminOnly: false,
    links: [
      { to: "/secrets", label: "Secrets", icon: "pi pi-key" },
      { to: "/stats", label: "Stats", icon: "pi pi-chart-bar" },
    ],
  },
  {
    label: "Sources",
    adminOnly: false,
    links: [
      { to: "/repositories", label: "Repositories", icon: "pi pi-folder" },
      { to: "/scans", label: "Scans", icon: "pi pi-sync" },
      { to: "/imports", label: "Imports", icon: "pi pi-file-import" },
      { to: "/uploads", label: "Uploads", icon: "pi pi-upload" },
    ],
  },
  {
    label: "Administration",
    adminOnly: true,
    links: [
      { to: "/scan-roots", label: "Scan roots", icon: "pi pi-sitemap" },
      { to: "/tools", label: "Tools", icon: "pi pi-wrench" },
      { to: "/rules", label: "Rules", icon: "pi pi-filter" },
      { to: "/users", label: "Users", icon: "pi pi-users" },
      { to: "/audit", label: "Audit log", icon: "pi pi-history" },
    ],
  },
];

export function groupOf(path: string): string | undefined {
  return NAV_GROUPS.find((group) => group.links.some((link) => isUnder(path, link.to)))?.label;
}

export function isUnder(path: string, to: string): boolean {
  return (
    path === to || path.startsWith(`${to}/`) || (to === "/secrets" && path.startsWith("/findings/"))
  );
}

export function currentOf(path: string, to: string): "page" | "true" | undefined {
  if (path === to) return "page";
  return isUnder(path, to) ? "true" : undefined;
}

export function readCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
  } catch {
    return false;
  }
}

export function writeCollapsed(collapsed: boolean): void {
  try {
    if (collapsed) localStorage.setItem(SIDEBAR_KEY, "collapsed");
    else localStorage.removeItem(SIDEBAR_KEY);
  } catch {}
}
