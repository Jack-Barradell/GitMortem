<script setup lang="ts">
import { ref } from "vue";
import type { components } from "@/api/schema";
import AddRootForm from "@/components/AddRootForm.vue";
import ScanRootBases from "@/components/ScanRootBases.vue";
import { useSession } from "@/stores/session";

type Root = components["schemas"]["ScanRootOut"];

const session = useSession();

const added = ref<Root | null>(null);
</script>

<template>
  <section
    class="rounded-lg border-l-4 border-primary bg-surface-0 p-4 shadow-sm sm:p-6 dark:bg-surface-900"
    aria-labelledby="first-root-heading"
    data-test="first-root"
  >
    <template v-if="session.isAdmin">
      <h2 id="first-root-heading" class="font-semibold">Add the first scan root</h2>
      <template v-if="added">
        <p class="mt-1 text-sm">
          Scan root added: <span class="font-mono break-all">{{ added.path }}</span
          >. Next, discover its repositories on the
          <RouterLink
            :to="{ path: '/repositories', query: { root: String(added.id) } }"
            class="gm-link"
            data-test="discover"
            >Repositories</RouterLink
          >
          page, then scan them.
        </p>
      </template>
      <template v-else>
        <p class="mt-1 text-sm text-surface-500">
          No scan roots yet. Add the folder that holds the repositories to scan. It must be inside a
          base the operator named at start-up with
          <code class="font-mono">--scan-root-base</code>.
        </p>
        <ScanRootBases />
        <AddRootForm class="mt-4" @added="added = $event" />
      </template>
    </template>
    <p v-else id="first-root-heading" class="text-sm">No scan roots yet. An admin adds one.</p>
  </section>
</template>
