import {
  createRouter,
  createWebHistory,
  START_LOCATION,
  type Router,
  type RouterHistory,
} from "vue-router";
import { setPasswordChangeHandler, setUnauthorizedHandler } from "@/api/client";
import AccountPage from "@/pages/AccountPage.vue";
import AuditPage from "@/pages/AuditPage.vue";
import LoginPage from "@/pages/LoginPage.vue";
import RepositoriesPage from "@/pages/RepositoriesPage.vue";
import RulesPage from "@/pages/RulesPage.vue";
import ScanPage from "@/pages/ScanPage.vue";
import ScanRootsPage from "@/pages/ScanRootsPage.vue";
import ScansPage from "@/pages/ScansPage.vue";
import ToolsPage from "@/pages/ToolsPage.vue";
import UsersPage from "@/pages/UsersPage.vue";
import { noteExploring } from "@/exploredFrom";
import { announceSignedOut } from "@/sessionChannel";
import { EXPLORE } from "@/stores/explorer";
import { useSession } from "@/stores/session";

const ACCOUNT = "/account";
const SecretsPage = () => import("@/pages/SecretsPage.vue");
const SubjectPage = () => import("@/pages/SubjectPage.vue");
const ExplorerPage = () => import("@/pages/ExplorerPage.vue");

declare module "vue-router" {
  interface RouteMeta {
    public?: boolean;
    role?: "admin";
  }
}

export function createAppRouter(history: RouterHistory = createWebHistory()): Router {
  const router = createRouter({
    history,
    routes: [
      { path: "/", redirect: "/secrets" },
      { path: "/login", component: LoginPage, meta: { public: true } },
      { path: "/secrets", component: SecretsPage },
      {
        path: "/secrets/:id(\\d+)",
        name: "secret",
        component: SubjectPage,
        props: { kind: "secret" },
      },
      {
        path: "/findings/:id(\\d+)",
        name: "finding",
        component: SubjectPage,
        props: { kind: "finding" },
      },
      { path: "/account", component: AccountPage },
      { path: "/repositories", component: RepositoriesPage },
      { path: "/repositories/:id(\\d+)/explore", name: EXPLORE, component: ExplorerPage },
      { path: "/scans", component: ScansPage },
      { path: "/scans/:id(\\d+)", component: ScanPage },
      { path: "/scan-roots", component: ScanRootsPage, meta: { role: "admin" } },
      { path: "/tools", component: ToolsPage, meta: { role: "admin" } },
      { path: "/rules", component: RulesPage, meta: { role: "admin" } },
      { path: "/users", component: UsersPage, meta: { role: "admin" } },
      { path: "/audit", component: AuditPage, meta: { role: "admin" } },
      { path: "/imports", component: () => import("@/pages/ImportsPage.vue") },
      { path: "/stats", component: () => import("@/pages/StatsPage.vue") },
      { path: "/uploads", component: () => import("@/pages/UploadsPage.vue") },
      { path: "/:rest(.*)*", redirect: "/secrets" },
    ],
  });

  router.beforeEach(async (to) => {
    const session = useSession();
    if (!session.loaded) {
      try {
        await session.load();
      } catch {
        session.clear();
      }
    }
    if (to.meta.public) return session.user === null ? true : "/secrets";
    if (session.user === null) return { path: "/login", query: { next: to.fullPath } };
    if (session.user.must_change_password && to.path !== ACCOUNT) return ACCOUNT;
    if (to.meta.role === "admin" && !session.isAdmin) return "/secrets";
    return true;
  });
  router.afterEach((to, from, failure) => {
    if (failure === undefined) noteExploring(to, from);
  });
  return router;
}

export function installUnauthorizedRedirect(router: Router): void {
  setUnauthorizedHandler(() => {
    if (router.currentRoute.value === START_LOCATION) return;
    if (useSession().user !== null) announceSignedOut();
    leaveForSignIn(router);
  });
  setPasswordChangeHandler(() => {
    const session = useSession();
    if (session.user) session.user = { ...session.user, must_change_password: true };
    if (router.currentRoute.value.path !== ACCOUNT) void router.push(ACCOUNT);
  });
}

export function leaveForSignIn(router: Router): void {
  useSession().clear();
  const current = router.currentRoute.value;
  if (!current.meta.public) {
    void router.push({ path: "/login", query: { next: current.fullPath } });
  }
}
