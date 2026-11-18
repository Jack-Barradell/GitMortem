<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import RadioButton from "primevue/radiobutton";
import { reactive, ref } from "vue";
import { api } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor, shownName } from "@/format";
import { UPLOAD_REPO_OUTCOMES, UPLOAD_REPO_REFUSALS } from "@/labels";

type Schemas = components["schemas"];
type Detail = Schemas["UploadDetailOut"];
type Repo = Schemas["UploadDetailOut.UploadRepoOut"];

const props = defineProps<{ upload: Detail }>();
const emit = defineEmits<{ changed: [] }>();

const choice = reactive<Record<number, string>>({});
const busy = ref(false);
const error = ref<string | null>(null);

function repoName(repo: Repo): string {
  return shownName(repo.org === null ? repo.name : `${repo.org}/${repo.name}`);
}

async function answer(repo: Repo): Promise<void> {
  const picked = choice[repo.id];
  if (picked === undefined || busy.value) return;
  busy.value = true;
  error.value = null;
  try {
    await api(`/api/uploads/${props.upload.id}/repos/${repo.id}/answer`, {
      method: "POST",
      body: { repository_id: picked === "new" ? null : Number(picked) },
    });
    emit("changed");
  } catch (failure) {
    error.value = messageFor(failure);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="flex flex-col gap-2">
    <table class="w-full text-sm" data-test="upload-repos">
      <thead>
        <tr class="text-left text-xs font-semibold text-surface-600 dark:text-surface-300">
          <th class="py-1 pr-3">Folder in the zip</th>
          <th class="py-1 pr-3">Repository</th>
          <th class="py-1">What happened</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="repo in upload.repos" :key="repo.id" class="align-top" data-test="upload-repo">
          <td class="py-1 pr-3 font-mono break-all">{{ shownName(repo.zip_path) }}</td>
          <td class="py-1 pr-3">{{ repoName(repo) }}</td>
          <td class="py-1">
            <span data-test="upload-repo-outcome">{{ UPLOAD_REPO_OUTCOMES[repo.outcome] }}</span>
            <span v-if="repo.refusal" class="text-muted-color" data-test="upload-repo-refusal">
              : {{ UPLOAD_REPO_REFUSALS[repo.refusal] }}
            </span>
            <span
              v-if="repo.dropped_objects > 0"
              class="block text-sm text-muted-color"
              data-test="upload-repo-dropped"
            >
              {{ repo.dropped_objects }}
              {{ repo.dropped_objects === 1 ? "object" : "objects" }} could not be read and
              {{ repo.dropped_objects === 1 ? "was" : "were" }} left out, so no version it would
              replace is removed.
            </span>
            <fieldset
              v-if="repo.outcome === 'waiting'"
              class="mt-2 flex flex-col gap-1"
              data-test="upload-question"
            >
              <legend class="text-sm">Which repository does this update?</legend>
              <label
                v-for="candidate in repo.candidates"
                :key="candidate.repository_id"
                class="flex items-center gap-2"
              >
                <RadioButton
                  v-model="choice[repo.id]"
                  :value="String(candidate.repository_id)"
                  :name="`answer-${repo.id}`"
                />
                <span data-test="upload-candidate">
                  {{ shownName(candidate.display_path) }}
                  <span class="text-sm text-muted-color">
                    #{{ candidate.repository_id
                    }}<template v-if="candidate.commit_count !== null"
                      >, {{ candidate.commit_count }}
                      {{ candidate.commit_count === 1 ? "commit" : "commits" }}</template
                    ><template v-if="candidate.current_version_at !== null"
                      >, uploaded {{ formatTime(candidate.current_version_at) }}</template
                    ><template v-if="candidate.current_version_by !== null">
                      by {{ shownName(candidate.current_version_by) }}</template
                    >
                  </span>
                </span>
              </label>
              <label class="flex items-center gap-2">
                <RadioButton v-model="choice[repo.id]" value="new" :name="`answer-${repo.id}`" />
                <span>A new repository</span>
              </label>
              <Button
                label="Answer"
                size="small"
                class="self-start"
                data-test="upload-answer"
                :disabled="busy || choice[repo.id] === undefined"
                @click="answer(repo)"
              />
            </fieldset>
          </td>
        </tr>
      </tbody>
    </table>
    <Message v-if="error" severity="error">{{ error }}</Message>
  </div>
</template>
