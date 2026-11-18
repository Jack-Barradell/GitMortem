import type { components } from "@/api/schema";

const AUDIT_ACTION_LABELS: Record<string, string> = {
  login_succeeded: "Sign-in succeeded",
  login_failed: "Sign-in failed",
  login_locked: "Sign-in locked after failed attempts",
  logout: "Sign-out",
  password_changed: "Password changed",
  password_reset: "Password reset",
  user_created: "User created",
  user_role_changed: "Role changed",
  user_activated: "User activated",
  user_deactivated: "User deactivated",
  admin_bootstrapped: "First admin created",
  scan_root_added: "Scan root added",
  scan_root_removed: "Scan root removed",
  tool_settings_changed: "Tool settings changed",
  scan_settings_changed: "Scan settings changed",
  upload_limits_changed: "Upload limits changed",
  canary_words_changed: "Canary words changed",
  scan_started: "Scan started",
  scan_cancelled: "Scan cancelled",
  scan_reread: "Stored output re-read",
  discovery_started: "Discovery started",
  discovery_cancelled: "Discovery cancelled",
  secret_revealed: "Value revealed",
  secret_copied: "Value copied",
  values_shown: "Values shown in the list",
  value_searched: "Values searched",
  note_edited: "Note edited",
  note_deleted: "Note deleted",
  file_viewed: "File viewed, values shown",
  files_searched: "Files searched, values shown",
  rule_created: "Custom rule created",
  rule_changed: "Custom rule changed",
  rule_deleted: "Custom rule deleted",
  rules_imported: "Custom rules imported",
  rules_exported: "Custom rules exported",
  secrets_exported: "Secrets exported",
  import_started: "Import started",
  import_confirmed: "Import confirmed for recording",
  import_recorded: "Import recorded",
  import_discarded: "Import discarded",
  import_removed: "Import removed",
  upload_started: "Upload started",
  upload_finished: "Upload processed",
  upload_discarded: "Upload discarded",
  upload_match_answered: "Upload match answered",
  repositories_deletion_started: "Repository deletion started",
  repositories_deleted: "Repositories deleted",
  audit_cleared: "Audit log cleared",
  access_refused: "Access refused",
  tools_detected: "Tools detected",
  instance_started: "GitMortem started",
};

type AuditDetail = components["schemas"]["AuditPageOut.AuditEventOut"]["detail"];

export function auditActionLabel(action: string, detail: AuditDetail = {}): string {
  if (action === "login_failed" && detail.context === "password_change") {
    return "Password change failed";
  }
  return AUDIT_ACTION_LABELS[action] ?? action;
}

type Schemas = components["schemas"];
type ScanState = Schemas["ScanOut.ScanState"];
type DiscoveryState = Schemas["DiscoveryOut.DiscoveryState"];
type RunState = Schemas["ToolRunPageOut.ToolRunState"];
type IntegrityState = Schemas["ToolRunPageOut.IntegrityState"];

export type Severity = "success" | "info" | "warn" | "danger" | "secondary";

export const SCAN_STATES: Record<ScanState, string> = {
  queued: "Queued",
  running: "Running",
  finished: "Finished",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
};

export const RUN_STATES: Record<RunState, string> = {
  queued: "Queued",
  running: "Running",
  done: "Done",
  failed: "Failed",
  timed_out: "Timed out",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
};

export const DISCOVERY_STATES: Record<DiscoveryState, string> = {
  queued: "Queued",
  running: "Running",
  done: "Done",
  failed: "Failed",
  cancelled: "Cancelled",
  interrupted: "Interrupted",
};

export const INTEGRITY_STATES: Record<IntegrityState, string> = {
  not_checked: "Not checked",
  verified: "Verified",
  failed: "Integrity failed",
  timed_out: "Check timed out",
};

export const RUN_FAILURES: Record<Schemas["ToolRunPageOut.ToolRunFailure"], string> = {
  outside_root: "The repository is no longer inside its scan root",
  shadow_refused: "GitMortem could not open the repository's history safely",
  unreadable: "The repository could not be read",
  unsafe_work_tree: "GitMortem's temporary folder was unsafe to use",
  unexpected_output: "The tool's output was missing or not what it should be",
  exit_code: "The tool failed",
  tool_unavailable: "The tool could not be run",
  unexpected_error: "Unexpected error",
  incomplete:
    "The tool did not report the check commit GitMortem planted, so it may have missed findings",
  git_interrupted:
    "A git process the tool ran was killed or failed, so it may have missed findings",
  no_space: "The disk ran low while the tool ran, so it may have missed findings",
  tool_reported_error: "The tool reported an error while it scanned; its findings are kept",
  no_rules_enabled: "None of the custom rules it was planned with could run",
  repository_unavailable:
    "The repository could not be read again, so its stored output was not re-read",
  tool_changed: "The tool's file changed after it was detected, so it was not run: detect again",
};

export const REPOSITORY_STATES: Record<Schemas["RepositoryPageOut.RepositoryState"], string> = {
  scannable: "Scannable",
  refused: "Can't be scanned",
  missing: "Missing",
};

export const REPOSITORY_REFUSALS: Record<Schemas["RepositoryPageOut.RepositoryRefusal"], string> = {
  own_alternates: "It borrows objects from another repository (alternates)",
  sha256: "It uses SHA-256 object names, which GitMortem cannot scan",
  shallow: "Shallow clone: its history is incomplete",
  outside_root: "Its git folder or history lies outside the scan root",
  config_fetches: "Its config would make git fetch from a remote or run a hook",
  unreadable: "It could not be read",
};

export const REPOSITORY_KINDS: Record<Schemas["RepositoryPageOut.RepositoryKind"], string> = {
  work_tree: "Work tree",
  bare: "Bare",
  not_on_disk: "Not on disk",
  uploaded: "Uploaded",
};

export const TOOL_STATUSES: Record<Schemas["ToolListOut.DetectionStatus"], string> = {
  found: "Found",
  unrecognised: "Unrecognised build",
  missing: "Missing",
  not_executable: "Not runnable",
  shadowed: "Shadowed",
  untested: "Untested version",
  unsupported: "Unsupported version",
  unsafe_folder: "In a folder others can change",
};

export function toolStatusLabel(status: Schemas["ToolListOut.DetectionStatus"] | null): string {
  return status === null ? "Not detected" : TOOL_STATUSES[status];
}

const RUN_SEVERITY: Record<RunState, Severity> = {
  queued: "secondary",
  running: "secondary",
  done: "success",
  failed: "danger",
  timed_out: "danger",
  cancelled: "warn",
  interrupted: "warn",
};

const INTEGRITY_SEVERITY: Record<IntegrityState, Severity> = {
  not_checked: "secondary",
  verified: "success",
  failed: "danger",
  timed_out: "warn",
};

export function runSeverity(state: RunState): Severity {
  return RUN_SEVERITY[state];
}

export function integritySeverity(state: IntegrityState): Severity {
  return INTEGRITY_SEVERITY[state];
}

const SCAN_SEVERITY: Record<ScanState, Severity> = {
  queued: "secondary",
  running: "secondary",
  finished: "success",
  cancelled: "warn",
  interrupted: "warn",
};

const DISCOVERY_SEVERITY: Record<DiscoveryState, Severity> = {
  queued: "secondary",
  running: "secondary",
  done: "success",
  failed: "danger",
  cancelled: "warn",
  interrupted: "warn",
};

export function scanSeverity(state: ScanState): Severity {
  return SCAN_SEVERITY[state];
}

export function discoverySeverity(state: DiscoveryState): Severity {
  return DISCOVERY_SEVERITY[state];
}

export function isUnfinished(state: ScanState | DiscoveryState): boolean {
  return state === "queued" || state === "running";
}

export const SUBJECT_KINDS: Record<Schemas["AuditSubjectPageOut.SubjectKind"], string> = {
  secret: "Secret",
  finding: "Finding",
};

export const ROLE_LABELS: Record<Schemas["MeOut.Role"], string> = {
  admin: "Admin",
  analyst: "Analyst",
};

type SecretStatus = Schemas["ListOut.SecretStatus"];

export const SECRET_STATUSES: Record<SecretStatus, string> = {
  unclassified: "Unclassified",
  to_review: "To review",
  unsure: "Unsure",
  valid: "Valid",
  invalid: "Invalid",
  false_positive: "False positive",
  test_data: "Test data",
  revoked: "Revoked",
  canary: "Canary",
};

const STATUS_SEVERITY: Record<SecretStatus, Severity> = {
  unclassified: "warn",
  to_review: "warn",
  unsure: "warn",
  valid: "danger",
  invalid: "secondary",
  false_positive: "secondary",
  test_data: "secondary",
  revoked: "success",
  canary: "info",
};

export const STATUS_DOT: Record<SecretStatus, string> = {
  unclassified: "bg-amber-400",
  to_review: "bg-orange-500",
  unsure: "bg-yellow-300",
  valid: "bg-red-500",
  invalid: "bg-surface-500",
  false_positive: "bg-surface-300",
  test_data: "bg-sky-400",
  revoked: "bg-emerald-500",
  canary: "bg-violet-500",
};

export function statusSeverity(status: SecretStatus): Severity {
  return STATUS_SEVERITY[status];
}

export const STATUS_OPTIONS = Object.entries(SECRET_STATUSES).map(([value, label]) => ({
  value: value as SecretStatus,
  label,
}));

export const VIEWS: Record<Schemas["ListQueryIn.View"], string> = {
  unique: "Unique",
  all: "All",
};

export const SCAN_SCOPES: Record<Schemas["ListQueryIn.ScanScope"], string> = {
  seen: "Seen in",
  new: "New in",
};

export const VALUE_MODES: Record<Schemas["ListQueryIn.ValueSearchIn"]["mode"], string> = {
  exact: "Exact",
  partial: "Partial",
};

export const TOOLS: Record<Schemas["ListOut.ToolName"], string> = {
  "git-secrets": "git-secrets",
  gitleaks: "gitleaks",
  trufflehog: "trufflehog",
  "custom-rules": "Custom rules",
};

export const ENTRY_KINDS: Record<Schemas["FolderOut.EntryOut"]["kind"], string> = {
  blob: "File",
  tree: "Folder",
  link: "Symbolic link",
  submodule: "Submodule",
};

export const REF_KINDS: Record<Schemas["RefsOut.RefOut"]["kind"], string> = {
  branch: "Branches",
  tag: "Tags",
  remote: "Remote branches",
  other: "Other refs",
};

export const ROOT_REFUSALS: Record<Schemas["RootFoldersOut.RootRefusal"], string> = {
  not_absolute: "A scan root must be an absolute path.",
  missing: "No such folder, or it cannot be read.",
  not_a_directory: "That path is not a folder.",
  outside_bases: "That folder is not inside a base the operator allowed.",
  inside_data_dir: "A scan root cannot be inside GitMortem's own data folder.",
  holds_key_file: "A scan root cannot contain the instance key file.",
  overlaps_root: "That folder is inside, or contains, a scan root already added.",
  no_bases: "The operator has named no scan root bases. Restart with --scan-root-base.",
  not_utf8: "A scan root must be valid text (UTF-8).",
};

export const ROOT_STATES: Record<Schemas["RootFoldersOut.RootState"], string | null> = {
  none: null,
  root: "Already a scan root",
  inside_root: "Inside a scan root",
  holds_root: "Holds a scan root",
};

export const EXPLORER_UNAVAILABLE: Record<Schemas["FileOut.Unavailable"], string> = {
  repository_gone: "The repository is gone, or its scan root was removed",
  refused: "The repository could not be read safely: it has changed since the scan",
  not_in_history: "Not in the repository's history: no such commit, or nothing there at this path",
  binary: "A binary file: there is no text to show",
  too_large: "Too large to read within the explorer's bounds",
  timed_out: "Reading the repository took too long",
  unreadable: "Git could not read the repository's refs or a tree, so nothing partial is shown",
  not_on_disk: "Not on disk: an import named this repository, which is not on this machine",
};

export const UNAVAILABLE: Record<Schemas["ContextOut.Unavailable"], string> = {
  repository_gone: "The repository is gone, or its scan root was removed",
  refused: "The repository could not be read safely: it has changed since the scan",
  not_in_history: "That commit or file is no longer in the repository's history",
  binary: "A binary file: there are no lines to show",
  too_large: "The file is over 1 MiB, too large to show",
  timed_out: "Reading the repository took too long",
  unreadable: "Git could not read the file at this commit: the repository is damaged there",
  not_on_disk: "Not on disk: an import named this repository, so there are no lines to read",
};

export const IMPORT_STATES: Record<Schemas["ImportOut.ImportState"], string> = {
  uploading: "Uploading",
  checking: "Checking",
  checked: "Checked: confirm or discard",
  recording: "Recording",
  recorded: "Recorded",
  discarded: "Discarded",
  removed: "Removed",
  failed: "Failed",
};

export const IMPORT_SOURCES: Record<Schemas["ImportOut.ImportSource"], string> = {
  upload: "Uploaded",
  server_file: "File on the server",
};

export const IMPORT_FAILURES: Record<Schemas["ImportOut.ImportFailure"], string> = {
  wrong_format: "Not the chosen tool's own output",
  no_commits: "It names no commit: output of a scan of files, not of a repository's history",
  hosted_source:
    "Output of a scan of a hosted service, not of a repository's history: not imported yet",
  too_large: "The file grew past 256 MiB while it was read",
  unreadable: "Part of it could not be read",
  repository_unavailable: "The repository could not be read",
  unexpected_error: "Unexpected error",
};

export type HidesWhen = "on" | "off" | "added" | "higher" | "lower";
export type OptionLabel = { label: string; help: string; hidesWhen: HidesWhen; noLimit?: number };

export const OPTION_LABELS: Record<Schemas["OptionDescriptorListOut.OptionName"], OptionLabel> = {
  allow_aws_examples: {
    label: "Allow AWS's example keys",
    help: "Registers AWS's two documented example values as allowed, so they are not reported.",
    hidesWhen: "on",
  },
  skip_paths: {
    label: "Skip the stock config's allowlisted paths",
    help: "Results in the paths its global allowlist names are not reported.",
    hidesWhen: "on",
  },
  skip_placeholders: {
    label: "Skip the stock config's placeholder patterns",
    help: "Values its global allowlist patterns match are not reported.",
    hidesWhen: "on",
  },
  skip_stopwords: {
    label: "Skip values holding a stop word",
    help: "Values holding a word from the stock config's stop list are not reported.",
    hidesWhen: "on",
  },
  skip_rule_allowlists: {
    label: "Apply each stock rule's own allowlist",
    help: "The paths and patterns each rule's allowlist names are not reported.",
    hidesWhen: "on",
  },
  rules_off: {
    label: "Rules turned off",
    help: "Stock rules gitleaks does not run.",
    hidesWhen: "added",
  },
  scan_merges: {
    label: "Scan merge commits",
    help: "Diff each merge against its first parent, so a value only a merge adds is found.",
    hidesWhen: "off",
  },
  max_decode_depth: {
    label: "Decode depth",
    help: "How many layers of encoding gitleaks unwraps; 0 unwraps none.",
    hidesWhen: "lower",
  },
  max_archive_depth: {
    label: "Archive depth",
    help: "How many layers of archive gitleaks opens; 0 opens none.",
    hidesWhen: "lower",
  },
  max_target_megabytes: {
    label: "Largest file scanned (MB)",
    help: "Files over this size are not scanned; 0 is no limit.",
    hidesWhen: "lower",
    noLimit: 0,
  },
  hide_word_filtered: {
    label: "Drop results TruffleHog's word filter drops",
    help: "Off, they are reported too (filtered_unverified).",
    hidesWhen: "on",
  },
  filter_entropy: {
    label: "Entropy filter",
    help: "Results under this entropy are dropped; 0 is off.",
    hidesWhen: "higher",
  },
  filter_unverified: {
    label: "Hide unverified results",
    help: "Results TruffleHog could not verify are dropped.",
    hidesWhen: "on",
  },
  detectors_off: {
    label: "Detectors turned off",
    help: "TruffleHog detectors that do not run.",
    hidesWhen: "added",
  },
  skip_binaries: {
    label: "Skip binary files",
    help: "Binary files are not scanned.",
    hidesWhen: "on",
  },
  skip_archives: {
    label: "Skip archives",
    help: "Archives are not opened.",
    hidesWhen: "on",
  },
  detector_timeout_seconds: {
    label: "Detector timeout (s)",
    help: "How long one detector may take on a chunk.",
    hidesWhen: "lower",
  },
};

export function optionLabel(name: string): OptionLabel | undefined {
  return (OPTION_LABELS as Record<string, OptionLabel | undefined>)[name];
}

export const RULE_REFUSALS: Record<Schemas["RuleRefusal"], string> = {
  too_long: "The pattern is longer than 4,096 characters",
  does_not_compile: "The pattern is not a regular expression RE2 accepts",
  too_complex: "The pattern is too complex: it compiles to more than 8,192 RE2 instructions",
  bad_value_group: "A pattern's only named group may be one called value",
  name_taken: "Another rule has this name",
  too_many: "GitMortem keeps at most 1,000 rules",
  invalid:
    "Not a rule: each needs a name and a pattern, may have a description and enabled, and nothing else",
};

export const SCAN_KINDS: Record<Schemas["ScanPageOut.ScanKind"], string> = {
  scan: "Scan",
  import: "Import",
  reread: "Re-read",
};

export const SKIP_REASONS: Record<Schemas["ScanOut.SkipReason"], string> = {
  unavailable:
    "not available: not detected, missing, not runnable, shadowed or in a folder others can change",
  unsupported: "a version GitMortem does not support",
  no_rules: "its options turn every rule off, so it would read nothing",
};

export const CANARY_FIELDS: Record<Schemas["FindingOut.CanaryField"], string> = {
  message: "Its commit message",
  path: "Its file path",
  line: "Its line",
  author: "Its author",
};

export const CANARY_STATES: Record<Schemas["ToolRunPageOut.CanaryState"], string> = {
  seen: "Check commit reported: the tool read the commit GitMortem planted",
  missing: "Check commit not reported: the tool may have missed findings",
  not_checked: "Completeness not checked: its options would hide the check commit",
};

type CoverageGap = keyof Schemas["ToolRunPageOut.CoverageGaps"];

export const COVERAGE_GAPS: Record<CoverageGap, string> = {
  binary: "Binary files not read",
  too_large: "Files too large for the tool to read",
  long_lines: "Lines too long for the tool to read",
  unreadable: "Files that could not be read",
  rules_left_out: "Rules left out, no longer compiling",
  merges_over_reported: "Merges reported in full",
  paths_over_reported: "Paths reported in full",
  duplicate_paths: "Paths a diff named twice, each read",
  archives: "Archives: a tool reads inside only the formats and depth it knows",
  encoded_text: "UTF-16 or UTF-32 text files, which most tools cannot read",
  lfs_pointers: "Git LFS pointers: the content they name is not in the repository",
  merges_not_read: "Merges with text of their own, which this tool does not read",
  type_changes: "Commits turning a file into a link or back, whose content it does not read",
  not_carried: "Messages, names or objects too many to hand to the tools",
  records_dropped: "Findings the tool reported that could not be read",
  archives_unopened: "Archives it could not open",
};

export type GapClass = "missed" | "not_read" | "read_in_full";

export const GAP_CLASSES: Record<CoverageGap, GapClass> = {
  binary: "not_read",
  too_large: "missed",
  long_lines: "missed",
  unreadable: "missed",
  rules_left_out: "missed",
  merges_over_reported: "read_in_full",
  paths_over_reported: "read_in_full",
  duplicate_paths: "read_in_full",
  archives: "not_read",
  encoded_text: "not_read",
  lfs_pointers: "not_read",
  merges_not_read: "missed",
  type_changes: "not_read",
  not_carried: "missed",
  records_dropped: "missed",
  archives_unopened: "missed",
};

export const NOT_READ_BY_TOOL = "Not read by this tool:";

export const TOOL_GAP_LABELS: Partial<
  Record<Schemas["ListOut.ToolName"], Partial<Record<CoverageGap, string>>>
> = {
  trufflehog: { binary: "Binary files, which it reads unless it skips their name or kind" },
};

export const REREAD_RUNNING =
  "A run of the scan is still queued or running: re-read it once every run has ended.";

export const FINDING_PLACES: Record<Schemas["FindingPageOut.FindingPlace"], string> = {
  line: "A line of the file",
  binary: "A binary file: its line is not read",
  message: "The commit message",
  unresolved: "Not found in the commit's changes as the tool named it",
  tag: "An annotated tag's message",
  object: "An object no commit holds: reached only from a tag, or from nothing",
  name: "A file's name, or a link's target, in the commit",
};

export const DONE_WITH_GAPS = "Done, with gaps";

export const TRACE_PROBLEMS: Record<Schemas["ToolRunPageOut.TraceProblem"], string> = {
  none_ran: "No git process that reads history ran, so nothing shows the tool read the repository",
  unreadable: "The record of the git processes the tool ran could not be read",
  too_many: "The tool ran more git processes than GitMortem reads the record of",
};

export const TRACE_UNREAD: Record<Schemas["ToolRunPageOut.TraceUnreadReason"], string> = {
  not_a_file: "a git's record was not a file",
  too_large: "a git's record was too large to read",
  refused: "a git's record could not be opened",
  listing: "the folder holding them could not be listed",
};

export const REPORTED_SCOPES: Record<Schemas["ListQueryIn.ReportedScope"], string> = {
  all: "Any",
  current: "Still reported",
  no_longer: "No longer reported",
};
export const NO_LONGER_REPORTED = "No longer reported";
export const REPORTED_LIVE = "Reported live";

export const IMPORT_TOOLS: Record<Schemas["UploadIn"]["tool"], string> = {
  "git-secrets": TOOLS["git-secrets"],
  gitleaks: TOOLS.gitleaks,
  trufflehog: TOOLS.trufflehog,
};

export const IMPORT_CHECK_COUNTS: Record<
  keyof Schemas["ImportPageOut.ImportCheckOut"],
  [string, string]
> = {
  records: ["record", "records"],
  values: ["value", "values"],
  standalone: ["standalone", "standalone"],
  redacted: ["redacted", "redacted"],
  unknown_commits: ["commit the repository lacks", "commits the repository lacks"],
  parse_issues: ["line not read", "lines not read"],
  reported_live: ["reported live", "reported live"],
};

export const IMPORT_REFUSALS: Record<Schemas["ImportRefusal"], string> = {
  empty: "The file is empty: an import holds at least one byte",
  too_large: "An import is at most 256 MiB, or the lower limit an admin set",
  not_importable: "GitMortem imports git-secrets, gitleaks and TruffleHog output",
  no_such_repository: "That repository is no longer known",
  ambiguous_repository:
    "More than one uploaded repository has that org and name: choose the repository instead",
  not_yours: "Only the user who started this import, or an admin, may do that",
  repository_being_deleted:
    "That repository is being deleted, or its deletion failed: import against it once that is settled",
  removal_changed:
    "What removing this import deletes changed since its counts were read: check them again",
  needs_repository_on_disk:
    "git-secrets output can only be imported against a repository on disk: its paths are settled against the repository's own history",
  bad_name: "An org or a name is 1 to 100 characters, none of them a control or format character",
  no_such_import: "That import is no longer there",
  not_an_upload: "That import reads a file on the server: it takes no pieces",
  not_uploading: "That upload has already been finished",
  out_of_order: "Pieces arrive in order, each once, and no more than planned",
  bad_piece: "A piece was not the size the upload planned",
  incomplete: "Not every piece has arrived yet",
  not_checked: "Only an import whose check has ended can be confirmed",
  confirmed: "That import has already been confirmed",
  recorded: "A recorded import is removed, not discarded",
  not_recorded:
    "That import recorded nothing, so there is nothing to remove: an upload or a checked import is discarded instead",
  busy: "The import's check or record, or a re-read of it, is still under way: try again once it has ended",
  ended: "That import has ended",
  no_bases: "The operator has named no scan root bases, so no file on the server can be imported",
  not_absolute: "A file on the server is named by its absolute path",
  outside_bases: "That file is not inside a base the operator allowed",
  not_utf8: "A path must be valid text (UTF-8)",
  own_file: "GitMortem never reads its own data folder or key file",
  path_too_long: "A path is at most 4,096 characters",
  missing: "No such file, or it cannot be read",
  not_a_file: "That is not a regular file",
  unreadable_file: "That file could not be read",
  changed: "That file, or a folder on its way, changed while it was checked: name it again",
};

export const UPLOAD_STATES: Record<Schemas["UploadOut.UploadState"], string> = {
  uploading: "Uploading",
  queued: "Queued",
  processing: "Processing",
  waiting: "Waiting for an answer",
  done: "Done",
  failed: "Failed",
  discarded: "Discarded",
};

export const UPLOAD_FAILURES: Record<Schemas["UploadOut.UploadFailure"], string> = {
  not_a_zip: "Not a zip file",
  multi_disk: "A zip split over several files",
  truncated: "The zip is cut short",
  too_many_entries: "More entries than the upload limit allows",
  too_large_unpacked: "Larger unpacked than the upload limit allows",
  overlapping: "Entries overlap: the zip is malformed",
  backslash_names: "Its folders are named with backslashes: re-zip it with a tool that uses /",
  encrypted: "Encrypted entries: upload a zip without a password",
  bad_central_directory: "The zip's listing disagrees with its entries",
  long_names: "A name in the zip is longer, or deeper, than any repository's can be",
  too_many_repositories: "More repositories than one upload may hold (10,000)",
  disk_full: "Not enough free disk to unpack it",
  no_repos: "No repository found in the zip",
  pieces_unreadable: "A stored piece of the upload could not be read",
  interrupted: "GitMortem stopped while processing it",
  unexpected_error: "An unexpected error",
};

export const UPLOAD_REPO_OUTCOMES: Record<Schemas["UploadDetailOut.UploadRepoOutcome"], string> = {
  pending: "Pending",
  new: "New repository",
  replaced: "Replaced the copy held",
  new_version: "Kept as a new version",
  waiting: "Waiting for an answer",
  answered: "Answered",
  refused: "Refused",
  discarded: "Discarded",
};

export const UPLOAD_REPO_REFUSALS: Record<Schemas["UploadDetailOut.UploadRepoRefusal"], string> = {
  ambiguous_case: "A .git folder named in another case",
  git_file_outside: "Its .git file points outside the zip",
  not_a_repo: "Not a repository",
  bad_entry_name: "An entry or its name cannot be taken",
  link_or_device: "A link or device in its git folder",
  name_collision: "Another repository in the zip has the same org and name",
  unreadable: "Part of it could not be read",
  too_compressed: "Compressed past the ratio limit",
  shallow: "A shallow clone: its history is incomplete",
  sha256: "Uses sha256 objects, which GitMortem does not read",
  partial_clone: "A partial clone: objects are missing",
};

export const LEFT_REASONS: Record<Schemas["DeletionPreviewOut.LeftReason"], string> = {
  root_removed: "its scan root was removed",
  root_unusable: "its scan root is gone or outside the operator's bases",
  not_contained: "it no longer sits inside its scan root",
  holds_data_or_key: "it holds GitMortem's data or key",
  worktree_unconfirmed: "a linked worktree that does not point back to its repository",
  separate_git_dir: "its git folder sits outside it, and not under a parent's .git/modules",
};

export const DELETION_STATES: Record<Schemas["RepositoryOut.DeletionState"], string> = {
  deleting: "Being deleted",
  failed: "Deletion failed",
  deleted: "Deleted",
};

export const DELETION_FAILURES: Record<Schemas["RepositoryOut.DeletionFailure"], string> = {
  files_not_deleted: "some of its files could not be deleted",
  scans_still_running: "a scan of it did not stop",
  plan_changed: "what it deletes changed after it was confirmed; review it again",
  unexpected_error: "an unexpected error",
};
