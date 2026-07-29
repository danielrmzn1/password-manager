/**
 * S3-compatible sync configuration (Cloudflare R2 is the primary target).
 *
 * The backend never hands the secret access key back — `SyncConfigView` only
 * reports whether one is stored — so the secret input always starts empty and a
 * save has to carry the full key again. There is no partial update.
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2, PlugZap, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { SyncNowButton } from "@/components/AppShell";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  FormField,
  Hint,
  ReadOnlyRow,
  SettingRow,
  SettingsSection,
} from "@/components/settings/parts";
import {
  api,
  toApiError,
  type Settings,
  type SyncConfigInput,
  type SyncConfigView,
  type SyncStatusEvent,
} from "@/lib/api";

/** Local form shape: identical to `SyncConfigInput`, kept as plain strings. */
type Form = SyncConfigInput;

const BLANK: Form = {
  endpoint: "",
  region: "auto",
  bucket: "",
  prefix: "",
  access_key_id: "",
  secret_access_key: "",
  force_path_style: false,
};

function fromView(view: SyncConfigView): Form {
  return {
    endpoint: view.endpoint,
    region: view.region,
    bucket: view.bucket,
    prefix: view.prefix,
    access_key_id: view.access_key_id,
    // Never prefilled: the backend does not expose the stored secret.
    secret_access_key: "",
    force_path_style: view.force_path_style,
  };
}

function trimmed(form: Form): SyncConfigInput {
  return {
    endpoint: form.endpoint.trim(),
    region: form.region.trim(),
    bucket: form.bucket.trim(),
    prefix: form.prefix.trim(),
    access_key_id: form.access_key_id.trim(),
    // Deliberately not trimmed — a secret is used verbatim.
    secret_access_key: form.secret_access_key,
    force_path_style: form.force_path_style,
  };
}

/** Returns a human-readable reason the form cannot be submitted yet, or `null`. */
function validate(input: SyncConfigInput, hasStoredSecret: boolean): string | null {
  if (!input.endpoint) return "Enter the S3 endpoint URL.";
  if (!input.region) return "Enter a region (use “auto” for Cloudflare R2).";
  if (!input.bucket) return "Enter the bucket name.";
  if (!input.access_key_id) return "Enter the access key ID.";
  if (!input.secret_access_key) {
    return hasStoredSecret
      ? "Re-enter the secret access key. It is stored encrypted and cannot be read back, so every save needs the full value again."
      : "Enter the secret access key.";
  }
  return null;
}

interface SyncSettingsProps {
  settings: Settings;
  onPatch: (patch: Partial<Settings>) => void;
  syncStatus: SyncStatusEvent;
  onSync: () => void;
  onVaultChanged: () => void;
}

export function SyncSettings({
  settings,
  onPatch,
  syncStatus,
  onSync,
  onVaultChanged,
}: SyncSettingsProps) {
  const [view, setView] = useState<SyncConfigView | null>(null);
  const [form, setForm] = useState<Form>(BLANK);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<"test" | "save" | "clear" | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getSyncConfig()
      .then((current) => {
        if (cancelled) return;
        setView(current);
        setForm(current ? fromView(current) : BLANK);
      })
      .catch((error) => {
        if (cancelled) return;
        toast.error("Could not read the sync settings", {
          description: toApiError(error).message,
        });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const set = useCallback(
    <K extends keyof Form>(key: K, value: Form[K]) =>
      setForm((current) => ({ ...current, [key]: value })),
    [],
  );

  const submit = useCallback(
    async (mode: "test" | "save") => {
      const input = trimmed(form);
      const problem = validate(input, view?.has_secret_access_key ?? false);
      if (problem) {
        toast.error(
          mode === "test" ? "Cannot test yet" : "Cannot save yet",
          { description: problem },
        );
        return;
      }

      setBusy(mode);
      try {
        if (mode === "test") {
          await api.testSyncConfig(input);
          toast.success("Connection works", {
            // The backend test is a HEAD of the vault object, which proves the
            // endpoint, signature and bucket are right. It deliberately does not
            // write anything, so it cannot confirm write access — saying it did
            // would be a false reassurance.
            description: `Reached bucket “${input.bucket}” and authenticated successfully. Write access is verified on the first sync.`,
          });
        } else {
          const saved = await api.setSyncConfig(input);
          setView(saved);
          // Drop the secret from React state now that it lives in the vault.
          setForm(fromView(saved));
          toast.success("Sync configured", {
            description: "Your vault will be synced as encrypted ciphertext only.",
          });
          onVaultChanged();
        }
      } catch (error) {
        const failure = toApiError(error);
        toast.error(mode === "test" ? "Connection failed" : "Could not save", {
          description: failure.message,
        });
      } finally {
        setBusy(null);
      }
    },
    [form, view, onVaultChanged],
  );

  const disconnect = useCallback(async () => {
    setBusy("clear");
    try {
      await api.clearSyncConfig();
      setView(null);
      setForm(BLANK);
      toast.success("Sync disconnected", {
        description: "Your local vault is untouched. Nothing was deleted from the bucket.",
      });
      onVaultChanged();
    } catch (error) {
      toast.error("Could not disconnect", {
        description: toApiError(error).message,
      });
    } finally {
      setBusy(null);
    }
  }, [onVaultChanged]);

  if (loading) {
    return (
      <div className="grid place-items-center py-16">
        <Loader2
          className="size-5 animate-spin text-muted-foreground"
          aria-label="Loading sync settings"
        />
      </div>
    );
  }

  const configured = view !== null;

  return (
    <div className="space-y-6">
      <SettingsSection
        title="Encrypted sync"
        description="Your vault is copied to a bucket you own, so several devices can share it. The file is encrypted on this machine before it is uploaded — the storage provider only ever receives ciphertext and cannot read a single entry."
        action={
          <Badge variant={configured ? "secondary" : "outline"}>
            {configured ? "Connected" : "Not set up"}
          </Badge>
        }
      >
        <Hint>
          Works with Cloudflare R2, Backblaze B2, MinIO, Amazon S3 and anything
          else speaking the S3 API. The access keys you enter here are stored
          encrypted with your vault key, never in plaintext on disk.
        </Hint>

        <div className="grid gap-5 sm:grid-cols-2">
          <FormField
            id="sync-endpoint"
            label="Endpoint"
            className="sm:col-span-2"
            hint="For Cloudflare R2 this is https://<account-id>.r2.cloudflarestorage.com. Plain http:// is rejected unless the host is localhost."
          >
            <Input
              id="sync-endpoint"
              value={form.endpoint}
              onChange={(event) => set("endpoint", event.target.value)}
              placeholder="https://<account-id>.r2.cloudflarestorage.com"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>

          <FormField
            id="sync-bucket"
            label="Bucket"
            hint="The bucket must already exist; the app will not create it."
          >
            <Input
              id="sync-bucket"
              value={form.bucket}
              onChange={(event) => set("bucket", event.target.value)}
              placeholder="my-vault"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>

          <FormField
            id="sync-region"
            label="Region"
            hint="Cloudflare R2 requires the literal value auto. Other providers want their real region, e.g. eu-central-1."
          >
            <Input
              id="sync-region"
              value={form.region}
              onChange={(event) => set("region", event.target.value)}
              placeholder="auto"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>

          <FormField
            id="sync-prefix"
            label="Prefix (optional)"
            className="sm:col-span-2"
            hint="A folder-like path inside the bucket, if you want to keep the vault alongside other objects."
          >
            <Input
              id="sync-prefix"
              value={form.prefix}
              onChange={(event) => set("prefix", event.target.value)}
              placeholder="password-manager/"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>

          <FormField
            id="sync-access-key"
            label="Access key ID"
            hint="Use a key scoped to this one bucket, with read and write access only."
          >
            <Input
              id="sync-access-key"
              value={form.access_key_id}
              onChange={(event) => set("access_key_id", event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>

          <FormField
            id="sync-secret-key"
            label="Secret access key"
            hint={
              view?.has_secret_access_key
                ? "A key is already stored. It is encrypted and can never be read back, so saving any change here means re-entering the whole key."
                : "Stored encrypted with your vault key. It is never written to disk in plaintext and never shown again."
            }
          >
            <Input
              id="sync-secret-key"
              type="password"
              value={form.secret_access_key}
              onChange={(event) => set("secret_access_key", event.target.value)}
              placeholder={view?.has_secret_access_key ? "Unchanged" : ""}
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>
        </div>

        <SettingRow
          id="sync-path-style"
          label="Use path-style URLs"
          hint="Puts the bucket name in the URL path instead of the hostname. Needed for MinIO and most self-hosted S3 servers; leave it off for Cloudflare R2 and Amazon S3."
          control={
            <Switch
              id="sync-path-style"
              checked={form.force_path_style}
              onCheckedChange={(checked) => set("force_path_style", checked)}
            />
          }
        />

        {view && (
          <ReadOnlyRow label="Object key in use" value={view.object_key} />
        )}

        <Separator />

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            onClick={() => void submit("test")}
            disabled={busy !== null}
          >
            {busy === "test" ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <PlugZap className="size-4" aria-hidden />
            )}
            Test connection
          </Button>

          <Button onClick={() => void submit("save")} disabled={busy !== null}>
            {busy === "save" && (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            )}
            Save
          </Button>

          {configured && <SyncNowButton onSync={onSync} status={syncStatus} />}

          <div className="flex-1" />

          {configured && (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" disabled={busy !== null}>
                  <Trash2 className="size-4" aria-hidden />
                  Disconnect
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Disconnect sync?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This removes the endpoint, bucket and stored credentials from
                    this device and stops syncing. Your local vault and every
                    entry in it are kept exactly as they are, and the encrypted
                    copy already in the bucket is left alone — you can reconnect
                    later with the same keys.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Keep syncing</AlertDialogCancel>
                  <AlertDialogAction
                    variant="destructive"
                    onClick={() => void disconnect()}
                  >
                    Disconnect
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        </div>

        {syncStatus.state === "error" && syncStatus.message && (
          <Hint className="text-destructive/85">
            Last sync attempt failed: {syncStatus.message}
          </Hint>
        )}
      </SettingsSection>

      <SettingsSection
        title="When to sync"
        description="Sync is manual by default. These options add automatic sync points; you can always trigger one yourself with “Sync now”."
      >
        <SettingRow
          id="sync-on-unlock"
          label="Sync when the vault is unlocked"
          hint="Pulls changes made on your other devices as soon as you sign in, so you start from the newest copy."
          control={
            <Switch
              id="sync-on-unlock"
              checked={settings.sync_on_unlock}
              onCheckedChange={(checked) => onPatch({ sync_on_unlock: checked })}
              disabled={!configured}
            />
          }
        />

        <SettingRow
          id="sync-on-save"
          label="Sync after every change"
          hint="Uploads a new encrypted copy each time you add or edit an entry. Keeps devices closely in step at the cost of more requests to your bucket."
          control={
            <Switch
              id="sync-on-save"
              checked={settings.sync_on_save}
              onCheckedChange={(checked) => onPatch({ sync_on_save: checked })}
              disabled={!configured}
            />
          }
        />

        {!configured && (
          <Hint>
            These take effect once sync is connected.
          </Hint>
        )}
      </SettingsSection>
    </div>
  );
}
