/**
 * Standalone generator page: the generator itself plus presets.
 *
 * Presets live inside the encrypted vault, so they travel with it to every
 * device. Options state is lifted here so applying a preset can drive the panel.
 */

import { useCallback, useEffect, useState } from "react";
import { Bookmark, Loader2, Trash2, Wand2 } from "lucide-react";
import { toast } from "sonner";

import { GeneratorPanel } from "@/components/GeneratorPanel";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  api,
  defaultCharacterOptions,
  toApiError,
  type GeneratorCapabilities,
  type GeneratorOptions,
  type GeneratorPreset,
} from "@/lib/api";
import { formatRelative, pluralize } from "@/lib/format";

export function GeneratorScreen({
  capabilities,
}: {
  capabilities: GeneratorCapabilities;
}) {
  const [options, setOptions] = useState<GeneratorOptions>(() =>
    defaultCharacterOptions(capabilities),
  );

  const [presets, setPresets] = useState<GeneratorPreset[]>([]);
  const [loadingPresets, setLoadingPresets] = useState(true);
  const [saveOpen, setSaveOpen] = useState(false);
  const [presetName, setPresetName] = useState("");
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<GeneratorPreset | null>(
    null,
  );

  const loadPresets = useCallback(async () => {
    try {
      setPresets(await api.listPresets());
    } catch (error) {
      toast.error("Could not load presets", {
        description: toApiError(error).message,
      });
    } finally {
      setLoadingPresets(false);
    }
  }, []);

  useEffect(() => {
    void loadPresets();
  }, [loadPresets]);

  const savePreset = async () => {
    const name = presetName.trim();
    if (!name) return;
    setSaving(true);
    try {
      await api.savePreset({
        id: crypto.randomUUID(),
        name,
        options,
        // The backend stamps the real creation time.
        created_at: 0,
      });
      setSaveOpen(false);
      setPresetName("");
      toast.success("Preset saved", {
        description: "It is stored in your vault and syncs to your devices.",
      });
      await loadPresets();
    } catch (error) {
      toast.error("Could not save the preset", {
        description: toApiError(error).message,
      });
    } finally {
      setSaving(false);
    }
  };

  const deletePreset = async (preset: GeneratorPreset) => {
    try {
      await api.deletePreset(preset.id);
      setPresets((current) => current.filter((item) => item.id !== preset.id));
      toast.success(`Deleted “${preset.name}”`);
    } catch (error) {
      toast.error("Could not delete the preset", {
        description: toApiError(error).message,
      });
    } finally {
      setPendingDelete(null);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="shrink-0 border-b px-8 py-6">
        <h1 className="text-xl font-semibold tracking-tight">Generator</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Build a strong password or passphrase. Every value is generated in the
          app&apos;s Rust core with a cryptographic random source.
        </p>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto grid max-w-5xl gap-8 px-8 py-8 lg:grid-cols-[minmax(0,1fr)_19rem]">
          <GeneratorPanel
            capabilities={capabilities}
            options={options}
            onOptionsChange={setOptions}
          />

          <aside className="space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold">Saved presets</h2>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  setPresetName("");
                  setSaveOpen(true);
                }}
              >
                <Bookmark className="size-3.5" aria-hidden />
                Save current
              </Button>
            </div>

            <Separator />

            {loadingPresets ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" aria-hidden />
                Loading…
              </div>
            ) : presets.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No presets yet. Tune the options you like and save them for next
                time.
              </p>
            ) : (
              <ul className="space-y-2">
                {presets.map((preset) => (
                  <li
                    key={preset.id}
                    className="group rounded-lg border bg-card p-3"
                  >
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium">
                            {preset.name}
                          </span>
                          <Badge variant="secondary">
                            {preset.options.mode === "characters"
                              ? "Password"
                              : "Passphrase"}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">
                          {summarize(preset.options)}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Saved {formatRelative(preset.created_at)}
                        </p>
                      </div>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-sm"
                        onClick={() => setPendingDelete(preset)}
                        aria-label={`Delete preset ${preset.name}`}
                        title="Delete preset"
                      >
                        <Trash2 className="size-3.5" aria-hidden />
                      </Button>
                    </div>

                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      className="mt-2 w-full"
                      onClick={() => {
                        setOptions(preset.options);
                        toast.success(`Applied “${preset.name}”`);
                      }}
                    >
                      <Wand2 className="size-3.5" aria-hidden />
                      Apply
                    </Button>
                  </li>
                ))}
              </ul>
            )}

            <p className="text-xs text-muted-foreground">
              Presets are stored inside the encrypted vault, so they sync across
              your devices.
            </p>
          </aside>
        </div>
      </div>

      {/* Save the current options under a name. */}
      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save preset</DialogTitle>
            <DialogDescription>
              Stores the current generator options in your vault.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <Label htmlFor="preset-name">Name</Label>
            <Input
              id="preset-name"
              value={presetName}
              autoFocus
              maxLength={60}
              placeholder="Work logins"
              onChange={(event) => setPresetName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void savePreset();
                }
              }}
            />
            <p className="text-xs text-muted-foreground">
              {summarize(options)}
            </p>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setSaveOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={() => void savePreset()}
              disabled={saving || presetName.trim().length === 0}
            >
              {saving && <Loader2 className="size-4 animate-spin" aria-hidden />}
              Save preset
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this preset?</AlertDialogTitle>
            <AlertDialogDescription>
              “{pendingDelete?.name}” will be removed from your vault on every
              device. Passwords you already generated are not affected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingDelete) void deletePreset(pendingDelete);
              }}
            >
              Delete preset
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** One-line summary of a preset's key settings. */
function summarize(options: GeneratorOptions): string {
  if (options.mode === "characters") {
    const classes = [
      options.uppercase && "A–Z",
      options.lowercase && "a–z",
      options.digits && "0–9",
      options.symbols && pluralize(options.symbol_set.length, "symbol"),
    ].filter((part): part is string => typeof part === "string");

    const parts = [`${options.length} characters`, classes.join(" · ") || "—"];
    if (options.exclude_ambiguous) parts.push("no ambiguous");
    return parts.join(" · ");
  }

  const parts = [
    pluralize(options.word_count, "word"),
    options.separator ? `“${options.separator}”` : "no separator",
    options.capitalization,
  ];
  if (options.include_number) parts.push("number");
  if (options.include_symbol) parts.push("symbol");
  return parts.join(" · ");
}
