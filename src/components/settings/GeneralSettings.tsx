/**
 * General preferences: auto-lock, clipboard hygiene and appearance.
 *
 * Every change is persisted immediately through the shared `onPatch` helper,
 * which sends the whole `Settings` object to the backend and adopts the clamped
 * value it returns.
 */

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Caution, SettingRow, SettingsSection } from "@/components/settings/parts";
import type { Settings, Theme } from "@/lib/api";
import { formatDuration } from "@/lib/format";

/** Offered auto-lock delays, in seconds. `0` means never. */
const LOCK_TIMEOUTS = [60, 300, 900, 1800, 3600, 0];
/** Offered clipboard-clear delays, in seconds. `0` means never. */
const CLIPBOARD_TIMEOUTS = [10, 30, 60, 120, 300, 0];

const THEMES: { value: Theme; label: string }[] = [
  { value: "system", label: "Match the system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

/**
 * Keep the stored value selectable even if the backend clamped it to something
 * outside the offered list — otherwise the trigger would render empty.
 */
function withCurrent(options: number[], current: number): number[] {
  return options.includes(current) ? options : [current, ...options];
}

interface GeneralSettingsProps {
  settings: Settings;
  onPatch: (patch: Partial<Settings>) => void;
}

export function GeneralSettings({ settings, onPatch }: GeneralSettingsProps) {
  return (
    <div className="space-y-6">
      <SettingsSection
        title="Locking"
        description="When the vault locks, its contents are dropped from memory and the master password is required again."
      >
        <SettingRow
          id="lock-timeout"
          label="Auto-lock after inactivity"
          hint="How long the app waits with no keyboard or mouse activity before it locks itself. Shorter is safer, especially on a shared or portable machine."
          extra={
            settings.lock_timeout_secs === 0 ? (
              <Caution>
                The vault will stay unlocked until you lock it manually or quit
                the app. Anyone with access to this computer can read your
                passwords.
              </Caution>
            ) : undefined
          }
          control={
            <Select
              value={String(settings.lock_timeout_secs)}
              onValueChange={(value) =>
                onPatch({ lock_timeout_secs: Number(value) })
              }
            >
              <SelectTrigger id="lock-timeout" className="w-44">
                <SelectValue placeholder="Choose a delay" />
              </SelectTrigger>
              <SelectContent>
                {withCurrent(LOCK_TIMEOUTS, settings.lock_timeout_secs).map(
                  (seconds) => (
                    <SelectItem key={seconds} value={String(seconds)}>
                      {formatDuration(seconds)}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          }
        />

        <SettingRow
          id="lock-on-blur"
          label="Lock when the window loses focus"
          hint="Locks the moment you switch to another app. The safest option, but it means re-entering your master password every time you come back."
          control={
            <Switch
              id="lock-on-blur"
              checked={settings.lock_on_blur}
              onCheckedChange={(checked) => onPatch({ lock_on_blur: checked })}
            />
          }
        />
      </SettingsSection>

      <SettingsSection
        title="Clipboard"
        description="Copied secrets are wiped from the system clipboard automatically so they do not linger in clipboard history or get pasted somewhere by accident."
      >
        <SettingRow
          id="clipboard-clear"
          label="Clear the clipboard after"
          hint="Starts counting from the moment you copy a password. If you copy something else in the meantime, that newer value is left alone."
          extra={
            settings.clipboard_clear_secs === 0 ? (
              <Caution>
                Copied passwords will stay on the clipboard indefinitely, where
                other apps and clipboard managers can read them.
              </Caution>
            ) : undefined
          }
          control={
            <Select
              value={String(settings.clipboard_clear_secs)}
              onValueChange={(value) =>
                onPatch({ clipboard_clear_secs: Number(value) })
              }
            >
              <SelectTrigger id="clipboard-clear" className="w-44">
                <SelectValue placeholder="Choose a delay" />
              </SelectTrigger>
              <SelectContent>
                {withCurrent(
                  CLIPBOARD_TIMEOUTS,
                  settings.clipboard_clear_secs,
                ).map((seconds) => (
                  <SelectItem key={seconds} value={String(seconds)}>
                    {formatDuration(seconds)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          }
        />
      </SettingsSection>

      <SettingsSection title="Appearance">
        <SettingRow
          id="theme"
          label="Theme"
          hint="Stored alongside the other preferences rather than in the vault, so the unlock screen already uses the right theme before you sign in."
          control={
            <Select
              value={settings.theme}
              onValueChange={(value) => onPatch({ theme: value as Theme })}
            >
              <SelectTrigger id="theme" className="w-44">
                <SelectValue placeholder="Choose a theme" />
              </SelectTrigger>
              <SelectContent>
                {THEMES.map(({ value, label }) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          }
        />
      </SettingsSection>
    </div>
  );
}
