/**
 * The typed boundary between the UI and the Rust backend.
 *
 * Every `invoke` in the app goes through this file. Two conventions matter:
 *
 * - **Command argument names are camelCase.** Tauri 2 converts them to the Rust
 *   parameter's snake_case for you (`masterPassword` -> `master_password`).
 * - **Payload struct fields are snake_case**, because they are plain serde
 *   structs with no rename attribute. So `entry.updated_at`, not `updatedAt`.
 *
 * Security note: the backend deliberately never returns a stored password from
 * the list or detail commands. To show one, call `revealField`; to copy one,
 * call `copyField`, which moves the value vault -> clipboard entirely inside
 * Rust so it never enters this webview at all.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Stable machine-readable error discriminants from the backend. */
export type ErrorCode =
  | "locked"
  | "invalid_master_password"
  | "corrupt"
  | "unsupported_format"
  | "unsupported_schema"
  | "vault_exists"
  | "no_vault"
  | "entry_not_found"
  | "weak_master_password"
  | "crypto"
  | "random"
  | "invalid_options"
  | "io"
  | "sync_not_configured"
  | "sync"
  | "sync_conflict"
  | "sync_vault_mismatch"
  | "bridge_not_running"
  | "import"
  | "other";

export interface BackendError {
  code: ErrorCode;
  message: string;
}

export class ApiError extends Error {
  readonly code: ErrorCode;

  constructor(error: BackendError) {
    super(error.message);
    this.name = "ApiError";
    this.code = error.code;
  }
}

function isBackendError(value: unknown): value is BackendError {
  return (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    "message" in value
  );
}

/** Normalize whatever `invoke` rejected with into an `ApiError`. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (isBackendError(error)) return new ApiError(error);
  return new ApiError({
    code: "other",
    message: error instanceof Error ? error.message : String(error),
  });
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toApiError(error);
  }
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type VaultStatus = "uninitialized" | "locked" | "unlocked";
export type Theme = "system" | "light" | "dark";
export type EntryKind = "login" | "note";
export type Strength = "very_weak" | "weak" | "fair" | "strong" | "very_strong";

export interface Settings {
  lock_timeout_secs: number;
  clipboard_clear_secs: number;
  theme: Theme;
  lock_on_blur: boolean;
  sync_on_unlock: boolean;
  sync_on_save: boolean;
  bridge_enabled: boolean;
}

export interface GeneratorCapabilities {
  all_symbols: string;
  default_symbols: string;
  ambiguous: string;
  min_length: number;
  max_length: number;
  min_words: number;
  max_words: number;
  wordlist_size: number;
  bits_per_word: number;
  min_master_password_length: number;
}

export interface Bootstrap {
  status: VaultStatus;
  settings: Settings;
  capabilities: GeneratorCapabilities;
  version: string;
  sync_configured: boolean;
  bridge_running: boolean;
  bridge_paired: boolean;
}

export interface LockState {
  status: VaultStatus;
  idle_secs: number;
  lock_timeout_secs: number;
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

export interface EntrySummary {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  urls: string[];
  tags: string[];
  favorite: boolean;
  updated_at: number;
  has_password: boolean;
  has_notes: boolean;
  custom_field_count: number;
}

export interface CustomFieldView {
  id: string;
  label: string;
  secret: boolean;
  /** `null` for secret fields — fetch with `revealField`. */
  value: string | null;
}

export interface EntryDetail {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  urls: string[];
  tags: string[];
  favorite: boolean;
  created_at: number;
  updated_at: number;
  password_updated_at: number;
  has_password: boolean;
  has_notes: boolean;
  notes: string;
  custom_fields: CustomFieldView[];
}

/** Identifies one secret field for reveal/copy. */
export type FieldSelector =
  | { field: "password" }
  | { field: "username" }
  | { field: "notes" }
  | { field: "custom"; id: string };

export interface CustomFieldInput {
  /** Omit for a newly added field. */
  id?: string | null;
  label: string;
  /** `null`/omitted keeps the stored value for this field id. */
  value?: string | null;
  secret: boolean;
}

export interface EntryInput {
  kind: EntryKind;
  title: string;
  username: string;
  /** `null` leaves the stored password unchanged. */
  password?: string | null;
  urls: string[];
  notes: string;
  custom_fields: CustomFieldInput[];
  tags: string[];
  favorite: boolean;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

export interface CharacterOptions {
  mode: "characters";
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  symbol_set: string;
  exclude_ambiguous: boolean;
  require_each_class: boolean;
}

export type Capitalization = "lowercase" | "titlecase" | "uppercase";

export interface PassphraseOptions {
  mode: "passphrase";
  word_count: number;
  separator: string;
  capitalization: Capitalization;
  include_number: boolean;
  include_symbol: boolean;
  symbol_set: string;
}

export type GeneratorOptions = CharacterOptions | PassphraseOptions;

export interface GeneratedSecret {
  value: string;
  entropy_bits: number;
  strength: Strength;
  pool_size: number;
}

export interface GeneratorPreset {
  id: string;
  name: string;
  options: GeneratorOptions;
  created_at: number;
}

export interface PasswordAssessment {
  /** zxcvbn score, 0 (worst) to 4 (best). */
  score: number;
  entropy_bits: number;
  strength: Strength;
  acceptable: boolean;
  problems: string[];
  warning: string | null;
  suggestions: string[];
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

export interface SyncConfigInput {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  access_key_id: string;
  secret_access_key: string;
  force_path_style: boolean;
}

export interface SyncConfigView {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  access_key_id: string;
  has_secret_access_key: boolean;
  force_path_style: boolean;
  object_key: string;
}

export type SyncAction = "up_to_date" | "created_remote" | "pushed" | "merged";

export interface MergeOutcome {
  added_from_remote: number;
  updated_from_remote: number;
  kept_local: number;
  deleted_by_remote: number;
}

export interface SyncReport {
  action: SyncAction;
  outcome: MergeOutcome;
  revision: number;
  synced_at: number;
  warning: string | null;
}

export interface SyncStatusEvent {
  state: "idle" | "syncing" | "error";
  message: string | null;
}

// ---------------------------------------------------------------------------
// Bridge / transfer
// ---------------------------------------------------------------------------

export interface BridgeInfo {
  running: boolean;
  port: number | null;
  paired: boolean;
  extension_id: string | null;
}

export interface ImportReport {
  imported: number;
  duplicates: number;
  empty_rows: number;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

export const api = {
  bootstrap: () => call<Bootstrap>("app_bootstrap"),
  lockState: () => call<LockState>("vault_lock_state"),
  /** Tell the backend the user is active, deferring auto-lock. */
  touch: () => call<void>("vault_touch"),

  assessPassword: (password: string) =>
    call<PasswordAssessment>("vault_assess_password", { password }),
  setup: (masterPassword: string) => call<void>("vault_setup", { masterPassword }),
  unlock: (masterPassword: string) => call<void>("vault_unlock", { masterPassword }),
  lock: () => call<void>("vault_lock"),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    call<void>("vault_change_master_password", { currentPassword, newPassword }),

  listEntries: () => call<EntrySummary[]>("vault_list_entries"),
  getEntry: (id: string) => call<EntryDetail>("vault_get_entry", { id }),
  revealField: (id: string, selector: FieldSelector) =>
    call<string>("vault_reveal_field", { id, selector }),
  /** Copies vault -> clipboard inside Rust. Resolves with the auto-clear delay in seconds (0 = never). */
  copyField: (id: string, selector: FieldSelector) =>
    call<number>("vault_copy_field", { id, selector }),
  createEntry: (input: EntryInput) => call<string>("vault_create_entry", { input }),
  updateEntry: (id: string, input: EntryInput) =>
    call<void>("vault_update_entry", { id, input }),
  deleteEntry: (id: string) => call<void>("vault_delete_entry", { id }),
  setFavorite: (id: string, favorite: boolean) =>
    call<void>("vault_set_favorite", { id, favorite }),

  generatorCapabilities: () => call<GeneratorCapabilities>("generator_capabilities"),
  generate: (options: GeneratorOptions) =>
    call<GeneratedSecret>("generator_generate", { options }),
  listPresets: () => call<GeneratorPreset[]>("generator_list_presets"),
  savePreset: (preset: GeneratorPreset) => call<string>("generator_save_preset", { preset }),
  deletePreset: (id: string) => call<void>("generator_delete_preset", { id }),

  /** For values not yet in the vault, e.g. a freshly generated password. */
  copyText: (text: string) => call<number>("clipboard_copy", { text }),
  clearClipboard: () => call<void>("clipboard_clear"),

  getSettings: () => call<Settings>("settings_get"),
  updateSettings: (settings: Settings) => call<Settings>("settings_update", { settings }),

  getSyncConfig: () => call<SyncConfigView | null>("sync_get_config"),
  setSyncConfig: (config: SyncConfigInput) =>
    call<SyncConfigView>("sync_set_config", { config }),
  clearSyncConfig: () => call<void>("sync_clear_config"),
  testSyncConfig: (config: SyncConfigInput) => call<void>("sync_test_config", { config }),
  syncNow: () => call<SyncReport>("sync_now"),
  /**
   * Adopt an existing remote vault on this device. Resolves with the adopted
   * vault's **revision number** (not an entry count).
   */
  connectExisting: (config: SyncConfigInput, masterPassword: string) =>
    call<number>("sync_connect_existing", { config, masterPassword }),

  bridgeInfo: () => call<BridgeInfo>("bridge_info"),
  bridgeBeginPairing: () => call<string>("bridge_begin_pairing"),
  bridgeCancelPairing: () => call<void>("bridge_cancel_pairing"),
  bridgeUnpair: () => call<void>("bridge_unpair"),

  importCsv: () => call<ImportReport>("transfer_import_csv"),
  importBackup: (backupPassword: string) =>
    call<ImportReport>("transfer_import_backup", { backupPassword }),
  /** Resolves with the written path, or `null` if the user cancelled the dialog. */
  exportBackup: (backupPassword: string) =>
    call<string | null>("transfer_export_backup", { backupPassword }),
};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type LockReason = "timeout" | "manual" | "blur";

export const events = {
  onLocked: (handler: (reason: LockReason) => void): Promise<UnlistenFn> =>
    listen<{ reason: LockReason }>("vault://locked", (e) => handler(e.payload.reason)),
  onChanged: (handler: () => void): Promise<UnlistenFn> =>
    listen("vault://changed", () => handler()),
  onClipboardCleared: (handler: () => void): Promise<UnlistenFn> =>
    listen("clipboard://cleared", () => handler()),
  onSyncStatus: (handler: (status: SyncStatusEvent) => void): Promise<UnlistenFn> =>
    listen<SyncStatusEvent>("sync://status", (e) => handler(e.payload)),
  /** Emitted when the browser extension pulls a credential. */
  onBridgeFill: (handler: (entryId: string) => void): Promise<UnlistenFn> =>
    listen<string>("bridge://fill", (e) => handler(e.payload)),
  onBridgePaired: (handler: () => void): Promise<UnlistenFn> =>
    listen("bridge://paired", () => handler()),
};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export function defaultCharacterOptions(caps: GeneratorCapabilities): CharacterOptions {
  return {
    mode: "characters",
    length: 20,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    symbol_set: caps.default_symbols,
    exclude_ambiguous: false,
    require_each_class: true,
  };
}

export function defaultPassphraseOptions(caps: GeneratorCapabilities): PassphraseOptions {
  return {
    mode: "passphrase",
    word_count: 6,
    separator: "-",
    capitalization: "lowercase",
    include_number: false,
    include_symbol: false,
    symbol_set: caps.default_symbols,
  };
}

export function emptyEntryInput(kind: EntryKind = "login"): EntryInput {
  return {
    kind,
    title: "",
    username: "",
    password: "",
    urls: [],
    notes: "",
    custom_fields: [],
    tags: [],
    favorite: false,
  };
}
