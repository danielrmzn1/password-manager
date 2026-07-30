/**
 * Settings, split into tabbed sections.
 *
 * This component owns the one shared write path: `patch` builds a complete
 * `Settings` object, sends it to the backend, and lifts the *returned* value up
 * via `onSettingsChange` — the backend clamps timeouts, so its response is the
 * authority, not the object we sent. Successful changes are silent; only
 * failures raise a toast.
 */

import { useCallback, useState } from "react";
import { toast } from "sonner";

import { DataSettings } from "@/components/settings/DataSettings";
import { ExtensionSettings } from "@/components/settings/ExtensionSettings";
import { GeneralSettings } from "@/components/settings/GeneralSettings";
import { SecuritySettings } from "@/components/settings/SecuritySettings";
import { SyncSettings } from "@/components/settings/SyncSettings";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  api,
  toApiError,
  type GeneratorCapabilities,
  type Settings,
  type SyncStatusEvent,
} from "@/lib/api";

const SECTIONS = [
  { value: "general", label: "General" },
  { value: "sync", label: "Sync" },
  { value: "extension", label: "Browser extension" },
  { value: "data", label: "Data" },
  { value: "security", label: "Security" },
] as const;

interface SettingsScreenProps {
  settings: Settings;
  onSettingsChange: (settings: Settings) => void;
  capabilities: GeneratorCapabilities;
  version: string;
  syncStatus: SyncStatusEvent;
  onSync: () => void;
  onVaultChanged: () => void;
}

export function SettingsScreen({
  settings,
  onSettingsChange,
  capabilities,
  version,
  syncStatus,
  onSync,
  onVaultChanged,
}: SettingsScreenProps) {
  const [section, setSection] = useState<string>("general");

  /** Persist a partial change and adopt whatever the backend settled on. */
  const patch = useCallback(
    async (changes: Partial<Settings>): Promise<Settings | null> => {
      try {
        const saved = await api.updateSettings({ ...settings, ...changes });
        onSettingsChange(saved);
        return saved;
      } catch (error) {
        toast.error("Could not save that setting", {
          description: toApiError(error).message,
        });
        return null;
      }
    },
    [settings, onSettingsChange],
  );

  /** Fire-and-forget variant for controls that do not need the result. */
  const patchNow = useCallback(
    (changes: Partial<Settings>) => {
      void patch(changes);
    },
    [patch],
  );

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <header className="shrink-0 border-b px-8 pt-7 pb-5">
        <h1 className="font-heading text-xl font-medium">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          How this vault locks, syncs and shares itself.
        </p>
      </header>

      <Tabs
        value={section}
        onValueChange={setSection}
        className="flex min-h-0 flex-1 flex-col gap-0"
      >
        <div className="shrink-0 overflow-x-auto border-b px-8 py-3">
          <TabsList>
            {SECTIONS.map(({ value, label }) => (
              <TabsTrigger key={value} value={value} className="px-3">
                {label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <ScrollArea className="min-h-0 flex-1">
          <div className="mx-auto w-full max-w-3xl px-8 py-7">
            <TabsContent value="general">
              <GeneralSettings settings={settings} onPatch={patchNow} />
            </TabsContent>

            <TabsContent value="sync">
              <SyncSettings
                settings={settings}
                onPatch={patchNow}
                syncStatus={syncStatus}
                onSync={onSync}
                onVaultChanged={onVaultChanged}
              />
            </TabsContent>

            <TabsContent value="extension">
              <ExtensionSettings settings={settings} onPatch={patch} />
            </TabsContent>

            <TabsContent value="data">
              <DataSettings onVaultChanged={onVaultChanged} />
            </TabsContent>

            <TabsContent value="security">
              <SecuritySettings version={version} capabilities={capabilities} />
            </TabsContent>
          </div>
        </ScrollArea>
      </Tabs>
    </div>
  );
}
