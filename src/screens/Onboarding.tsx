/**
 * First-launch flow. Two mutually exclusive paths:
 *
 * 1. Create a brand new vault on this device (master password only).
 * 2. Connect this device to a vault that already exists in the user's own
 *    S3-compatible bucket (storage config + that vault's master password).
 *
 * Both paths end with `onComplete()`, which re-bootstraps the app. The master
 * password lives in component state only while the form is on screen and is
 * dropped the moment the backend has accepted it — it is never logged, and key
 * derivation happens entirely in Rust.
 */

import { useState, type FormEvent } from "react";
import {
  AlertTriangle,
  Cloud,
  Loader2,
  Lock,
  PlugZap,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";

import { MasterPasswordStrength } from "@/components/PasswordStrength";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  api,
  toApiError,
  type GeneratorCapabilities,
  type PasswordAssessment,
  type SyncConfigInput,
} from "@/lib/api";

interface OnboardingProps {
  capabilities: GeneratorCapabilities;
  onComplete: () => void | Promise<void>;
}

export function Onboarding({ capabilities, onComplete }: OnboardingProps) {
  const [path, setPath] = useState("create");

  return (
    <div className="h-screen overflow-y-auto bg-background">
      <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col justify-center gap-8 px-6 py-14">
        <header className="space-y-3 text-center">
          <div className="mx-auto grid size-12 place-items-center rounded-2xl bg-primary text-primary-foreground">
            <Lock className="size-5" aria-hidden />
          </div>
          <h1 className="font-heading text-2xl font-semibold tracking-tight">
            Welcome to Password Manager
          </h1>
          <p className="mx-auto max-w-md text-sm text-muted-foreground">
            Your vault is encrypted on this device before it goes anywhere. Start
            a new vault, or bring in one you already have.
          </p>
        </header>

        <Tabs value={path} onValueChange={setPath} className="gap-6">
          <TabsList className="w-full">
            <TabsTrigger value="create">Create a new vault</TabsTrigger>
            <TabsTrigger value="connect">Connect to an existing vault</TabsTrigger>
          </TabsList>

          <TabsContent value="create">
            <CreateVault
              minLength={capabilities.min_master_password_length}
              onComplete={onComplete}
            />
          </TabsContent>

          <TabsContent value="connect">
            <ConnectExisting onComplete={onComplete} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Path A — create a new vault
// ---------------------------------------------------------------------------

function CreateVault({
  minLength,
  onComplete,
}: {
  minLength: number;
  onComplete: () => void | Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && password !== confirm;
  const canSubmit =
    !busy &&
    acknowledged &&
    assessment !== null &&
    assessment.acceptable &&
    confirm.length > 0 &&
    password === confirm;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;

    setBusy(true);
    try {
      await api.setup(password);
      // Out of the webview's hands as soon as the backend has the vault.
      setPassword("");
      setConfirm("");
      setAssessment(null);
      await onComplete();
    } catch (error) {
      const apiError = toApiError(error);
      toast.error(
        apiError.code === "weak_master_password"
          ? "That master password is too weak"
          : "Could not create the vault",
        { description: apiError.message },
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      <div className="space-y-2 rounded-xl border border-destructive/40 bg-destructive/5 p-4">
        <p className="flex items-center gap-2 text-sm font-medium text-destructive">
          <AlertTriangle className="size-4" aria-hidden />
          Your master password cannot be recovered
        </p>
        <p className="text-sm text-muted-foreground">
          It is the only key to your vault. It is never sent anywhere and never
          stored — not on this device, not in your bucket, not with us. If you
          forget it, nobody can decrypt your vault: not the developers, not
          support, not you. There is no reset link and no backdoor.
        </p>
        <p className="text-sm text-muted-foreground">
          Pick a long passphrase you will remember, and consider writing it down
          somewhere physically safe before you continue.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="new-master-password">Master password</Label>
        <Input
          id="new-master-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="new-password"
          spellCheck={false}
          autoFocus
          disabled={busy}
          className="h-10"
          aria-describedby="new-master-password-hint"
        />
        <MasterPasswordStrength password={password} onAssessment={setAssessment} />
        <p id="new-master-password-hint" className="text-xs text-muted-foreground">
          At least {minLength} characters. Length beats complexity — four or five
          uncommon words are stronger than one mangled word.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="confirm-master-password">Confirm master password</Label>
        <Input
          id="confirm-master-password"
          type="password"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          autoComplete="new-password"
          spellCheck={false}
          disabled={busy}
          className="h-10"
          aria-invalid={mismatch}
          aria-describedby={mismatch ? "confirm-mismatch" : undefined}
        />
        {mismatch && (
          <p id="confirm-mismatch" role="alert" className="text-xs text-destructive">
            The two passwords do not match.
          </p>
        )}
      </div>

      <div className="flex items-start gap-3 rounded-xl border p-4">
        <Checkbox
          id="acknowledge-no-recovery"
          checked={acknowledged}
          onCheckedChange={(checked) => setAcknowledged(checked === true)}
          disabled={busy}
          className="mt-0.5"
        />
        <Label
          htmlFor="acknowledge-no-recovery"
          className="items-start text-sm leading-snug font-normal"
        >
          I understand that if I lose my master password, my vault is permanently
          unrecoverable.
        </Label>
      </div>

      <Button type="submit" size="lg" className="w-full" disabled={!canSubmit}>
        {busy ? (
          <>
            <Loader2 className="animate-spin" aria-hidden />
            Deriving your key…
          </>
        ) : (
          "Create vault"
        )}
      </Button>

      <p className="text-center text-xs text-muted-foreground">
        {busy
          ? "This takes a few seconds on purpose — a deliberately slow key derivation is what makes guessing your master password expensive."
          : "You can set up sync to your own storage bucket later, in Settings."}
      </p>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Path B — connect to an existing, already-synced vault
// ---------------------------------------------------------------------------

function ConnectExisting({
  onComplete,
}: {
  onComplete: () => void | Promise<void>;
}) {
  const [endpoint, setEndpoint] = useState("");
  const [region, setRegion] = useState("auto");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [forcePathStyle, setForcePathStyle] = useState(false);
  const [masterPassword, setMasterPassword] = useState("");
  const [testing, setTesting] = useState(false);
  const [busy, setBusy] = useState(false);

  function buildConfig(): SyncConfigInput {
    return {
      endpoint: endpoint.trim(),
      region: region.trim(),
      bucket: bucket.trim(),
      prefix: prefix.trim(),
      access_key_id: accessKeyId.trim(),
      secret_access_key: secretAccessKey,
      force_path_style: forcePathStyle,
    };
  }

  const storageReady = Boolean(
    endpoint.trim() &&
      region.trim() &&
      bucket.trim() &&
      accessKeyId.trim() &&
      secretAccessKey,
  );
  const canSubmit = storageReady && masterPassword.length > 0 && !busy && !testing;

  async function testConnection() {
    setTesting(true);
    try {
      await api.testSyncConfig(buildConfig());
      toast.success("Connection works", {
        description: `Reached the bucket “${bucket.trim()}” with those credentials.`,
      });
    } catch (error) {
      toast.error("Could not reach that bucket", {
        description: toApiError(error).message,
      });
    } finally {
      setTesting(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;

    setBusy(true);
    try {
      await api.connectExisting(buildConfig(), masterPassword);
      setMasterPassword("");
      setSecretAccessKey("");
      toast.success("Vault connected", {
        description: "Your encrypted vault was downloaded to this device.",
      });
      await onComplete();
    } catch (error) {
      const apiError = toApiError(error);
      toast.error(
        apiError.code === "invalid_master_password"
          ? "Incorrect master password"
          : apiError.code === "sync_vault_mismatch"
            ? "That bucket holds a different vault"
            : "Could not connect to that vault",
        { description: apiError.message },
      );
    } finally {
      setBusy(false);
    }
  }

  const disabled = busy || testing;

  return (
    <form onSubmit={submit} className="space-y-6">
      <div className="space-y-2 rounded-xl border bg-muted/40 p-4">
        <p className="flex items-center gap-2 text-sm font-medium">
          <Cloud className="size-4" aria-hidden />
          Joining a vault you already have
        </p>
        <p className="text-sm text-muted-foreground">
          This downloads the existing encrypted vault from your own
          S3-compatible bucket (Cloudflare R2, AWS S3, MinIO, Backblaze B2) and
          unlocks it here. Nothing is created remotely and nothing is
          overwritten. If you do not have a vault yet, use “Create a new vault”
          instead.
        </p>
      </div>

      <section className="space-y-4">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-medium">Storage</h2>
          <Separator className="flex-1" />
        </div>

        <div className="space-y-2">
          <Label htmlFor="sync-endpoint">Endpoint</Label>
          <Input
            id="sync-endpoint"
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder="https://<account-id>.r2.cloudflarestorage.com"
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="sync-region">Region</Label>
            <Input
              id="sync-region"
              value={region}
              onChange={(event) => setRegion(event.target.value)}
              placeholder="auto"
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
              aria-describedby="sync-region-hint"
            />
            <p id="sync-region-hint" className="text-xs text-muted-foreground">
              For Cloudflare R2 this must be the literal value{" "}
              <code className="font-mono">auto</code>.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="sync-bucket">Bucket</Label>
            <Input
              id="sync-bucket"
              value={bucket}
              onChange={(event) => setBucket(event.target.value)}
              placeholder="my-vault"
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="sync-prefix">Prefix (optional)</Label>
          <Input
            id="sync-prefix"
            value={prefix}
            onChange={(event) => setPrefix(event.target.value)}
            placeholder="password-manager/"
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
            aria-describedby="sync-prefix-hint"
          />
          <p id="sync-prefix-hint" className="text-xs text-muted-foreground">
            Must match the prefix used by your other device, or this one will not
            find the vault.
          </p>
        </div>

        <div className="flex items-start justify-between gap-4 rounded-xl border p-4">
          <div className="space-y-1">
            <Label htmlFor="sync-path-style">Path-style URLs</Label>
            <p className="text-xs text-muted-foreground">
              Needed for MinIO and some self-hosted gateways. Leave off for R2 and
              AWS S3.
            </p>
          </div>
          <Switch
            id="sync-path-style"
            checked={forcePathStyle}
            onCheckedChange={setForcePathStyle}
            disabled={disabled}
            className="mt-1"
          />
        </div>
      </section>

      <section className="space-y-4">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-medium">Credentials</h2>
          <Separator className="flex-1" />
        </div>

        <div className="space-y-2">
          <Label htmlFor="sync-access-key-id">Access key ID</Label>
          <Input
            id="sync-access-key-id"
            value={accessKeyId}
            onChange={(event) => setAccessKeyId(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="sync-secret-access-key">Secret access key</Label>
          <Input
            id="sync-secret-access-key"
            type="password"
            value={secretAccessKey}
            onChange={(event) => setSecretAccessKey(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
          />
        </div>

        <p className="flex items-start gap-2 text-xs text-muted-foreground">
          <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            These credentials are encrypted with your vault key before they touch
            the disk — they are never written in plaintext, and the bucket only
            ever receives ciphertext.
          </span>
        </p>
      </section>

      <section className="space-y-4">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-medium">Master password</h2>
          <Separator className="flex-1" />
        </div>

        <div className="space-y-2">
          <Label htmlFor="existing-master-password">
            Master password of that vault
          </Label>
          <Input
            id="existing-master-password"
            type="password"
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
            className="h-10"
            aria-describedby="existing-master-password-hint"
          />
          <p
            id="existing-master-password-hint"
            className="text-xs text-muted-foreground"
          >
            The same one you set when you created the vault. It is the only thing
            that can decrypt what is in the bucket.
          </p>
        </div>
      </section>

      <div className="flex flex-col gap-3 sm:flex-row-reverse">
        <Button
          type="submit"
          size="lg"
          className="flex-1"
          disabled={!canSubmit}
        >
          {busy ? (
            <>
              <Loader2 className="animate-spin" aria-hidden />
              Deriving your key…
            </>
          ) : (
            <>
              <PlugZap aria-hidden />
              Connect vault
            </>
          )}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="lg"
          className="sm:flex-1"
          onClick={testConnection}
          disabled={!storageReady || disabled}
        >
          {testing ? (
            <>
              <Loader2 className="animate-spin" aria-hidden />
              Testing…
            </>
          ) : (
            "Test connection"
          )}
        </Button>
      </div>

      <p className="text-center text-xs text-muted-foreground">
        Test the connection first — a typo in the endpoint or a key is much
        cheaper to find that way.
      </p>
    </form>
  );
}
