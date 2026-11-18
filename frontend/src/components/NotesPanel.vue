<script setup lang="ts">
import Button from "primevue/button";
import Message from "primevue/message";
import Textarea from "primevue/textarea";
import { useConfirm } from "primevue/useconfirm";
import { ref, watch } from "vue";
import { api, ApiError, reasonIn } from "@/api/client";
import type { components } from "@/api/schema";
import { formatTime, messageFor, shown } from "@/format";
import { MAX_NOTE_CHARS } from "@/notes";
import { subjectKey, subjectPath, type Subject } from "@/stores/triage";

type Note = components["schemas"]["NoteOut"];

const props = defineProps<{ subject: Subject; refresh: number }>();
const confirm = useConfirm();

const notes = ref<Note[]>([]);
const loaded = ref(false);
const notesError = ref("");
let generation = 0;

async function reload(): Promise<void> {
  const mine = ++generation;
  try {
    const answer = await api<components["schemas"]["NoteListOut"]>(
      `/api${subjectPath(props.subject)}/notes`,
    );
    if (mine !== generation) return;
    notes.value = answer.items;
    loaded.value = true;
    notesError.value = "";
  } catch (failure) {
    if (mine === generation) notesError.value = messageFor(failure);
  }
}

watch(() => [subjectKey(props.subject), props.refresh], reload, { immediate: true });

const draft = ref("");
const adding = ref(false);
const addError = ref("");

async function add(): Promise<void> {
  if (draft.value.trim() === "") return;
  adding.value = true;
  addError.value = "";
  try {
    const added = await api<Note>(`/api${subjectPath(props.subject)}/notes`, {
      method: "POST",
      body: { text: draft.value },
    });
    if (!notes.value.some((n) => n.id === added.id)) notes.value = [...notes.value, added];
    draft.value = "";
  } catch (failure) {
    addError.value = messageFor(failure);
  } finally {
    adding.value = false;
  }
}

const editing = ref<number | null>(null);
const editDraft = ref("");
const editError = ref("");
const saving = ref(false);

function startEdit(note: Note): void {
  editing.value = note.id;
  editDraft.value = note.text;
  editError.value = "";
}

function cancelEdit(): void {
  editing.value = null;
  editDraft.value = "";
  editError.value = "";
}

async function saveEdit(note: Note): Promise<void> {
  if (saving.value || editDraft.value.trim() === "") return;
  saving.value = true;
  editError.value = "";
  try {
    const saved = await api<Note>(`/api/notes/${note.id}`, {
      method: "PATCH",
      body: { text: editDraft.value, version: note.version },
    });
    notes.value = notes.value.map((n) => (n.id === saved.id ? saved : n));
    cancelEdit();
  } catch (failure) {
    editError.value = messageFor(failure);
    if (changedSince(failure)) await reload();
  } finally {
    saving.value = false;
  }
}

function askDelete(note: Note): void {
  confirm.require({
    header: "Delete this note?",
    message: "It cannot be brought back. The audit log records who deleted it, never its text.",
    icon: "pi pi-exclamation-triangle",
    acceptLabel: "Delete note",
    rejectLabel: "Cancel",
    acceptProps: { severity: "danger" },
    rejectProps: { severity: "secondary", variant: "outlined" },
    accept: () => void remove(note),
  });
}

async function remove(note: Note): Promise<void> {
  notesError.value = "";
  try {
    await api<void>(`/api/notes/${note.id}/delete`, {
      method: "POST",
      body: { version: note.version },
    });
    notes.value = notes.value.filter((n) => n.id !== note.id);
  } catch (failure) {
    if (changedSince(failure)) await reload();
    notesError.value = messageFor(failure);
  }
}

const nameOf = (name: string | null): string => (name === null ? "–" : shown(name));

function changedSince(failure: unknown): boolean {
  return failure instanceof ApiError && reasonIn(failure.body) === "note_changed";
}
</script>

<template>
  <div>
    <Message
      v-if="notesError"
      severity="error"
      size="small"
      role="alert"
      class="mb-2"
      data-test="notes-error"
    >
      {{ notesError }}
    </Message>
    <p v-if="loaded && notes.length === 0" class="text-sm text-surface-500">No notes yet.</p>
    <ol v-if="notes.length > 0" class="flex flex-col gap-2">
      <li
        v-for="note in notes"
        :key="note.id"
        class="rounded-md bg-surface-50 px-3 py-2 dark:bg-surface-800"
        data-test="note"
      >
        <div
          class="flex flex-wrap items-center gap-x-2 text-sm text-surface-500"
          data-test="note-meta"
        >
          <span>{{ nameOf(note.author) }}</span>
          <time :datetime="note.created_at">{{ formatTime(note.created_at) }}</time>
          <span v-if="note.edited_at !== null" data-test="edited">
            edited by {{ nameOf(note.edited_by) }} at
            <time :datetime="note.edited_at">{{ formatTime(note.edited_at) }}</time>
          </span>
          <span v-if="editing !== note.id" class="ml-auto flex gap-1">
            <Button
              label="Edit"
              size="small"
              severity="secondary"
              variant="text"
              data-test="edit-note"
              @click="startEdit(note)"
            />
            <Button
              label="Delete"
              size="small"
              severity="danger"
              variant="text"
              data-test="delete-note"
              @click="askDelete(note)"
            />
          </span>
        </div>
        <form
          v-if="editing === note.id"
          class="mt-1 flex flex-col gap-1"
          @submit.prevent="saveEdit(note)"
        >
          <label :for="`note-edit-${note.id}`" class="sr-only">Edit the note</label>
          <Textarea
            :id="`note-edit-${note.id}`"
            v-model="editDraft"
            rows="4"
            :maxlength="MAX_NOTE_CHARS"
            spellcheck="false"
            autocomplete="off"
          />
          <Message v-if="editError" severity="error" size="small" role="alert">
            {{ editError }}
          </Message>
          <div class="flex gap-2">
            <Button
              type="submit"
              label="Save"
              size="small"
              :disabled="saving || editDraft.trim() === ''"
            />
            <Button
              label="Cancel"
              size="small"
              severity="secondary"
              variant="outlined"
              data-test="cancel-edit"
              @click="cancelEdit"
            />
          </div>
        </form>
        <p v-else class="mt-1 break-words whitespace-pre-wrap" data-test="note-text">
          {{ shown(note.text) }}
        </p>
      </li>
    </ol>
    <form class="mt-4 flex flex-col gap-1" data-test="add-note" @submit.prevent="add">
      <label for="note-new" class="text-sm font-medium">Add a note</label>
      <Textarea
        id="note-new"
        v-model="draft"
        rows="3"
        :maxlength="MAX_NOTE_CHARS"
        spellcheck="false"
        autocomplete="off"
      />
      <Message v-if="addError" severity="error" size="small" role="alert" data-test="add-error">
        {{ addError }}
      </Message>
      <div>
        <Button
          type="submit"
          label="Add note"
          size="small"
          :disabled="adding || draft.trim() === ''"
        />
      </div>
    </form>
  </div>
</template>
