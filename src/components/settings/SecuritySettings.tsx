/**
 * Master password change, plus a plain-language summary of the protections.
 *
 * The three password fields live in state only while the form is open and are
 * cleared as soon as the change succeeds. Nothing is logged.
 */

import { useCallback, useState } from "react";
import { KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { MasterPasswordStrength } from "@/components/PasswordStrength";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Hint, SettingsSection } from "@/components/settings/parts";
import {
  api,
  toApiError,
  type GeneratorCapabilities,
  type PasswordAssessment,
} from "@/lib/api";

interface SecuritySettingsProps {
  version: string;
  capabilities: GeneratorCapabilities;
}

export function SecuritySettings({ version, capabilities }: SecuritySettingsProps) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null);
  const [busy, setBusy] = useState(false);

  const matches = confirm.length > 0 && next === confirm;
  const canSubmit =
    !busy && current.length > 0 && (assessment?.acceptable ?? false) && matches;

  const submit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!canSubmit) return;

      setBusy(true);
      try {
        await api.changeMasterPassword(current, next);
        setCurrent("");
        setNext("");
        setConfirm("");
        setAssessment(null);
        toast.success("Master password changed", {
          description:
            "Use the new password the next time you unlock. Other devices pick the change up on their next sync.",
        });
      } catch (error) {
        const failure = toApiError(error);
        toast.error(
          failure.code === "invalid_master_password"
            ? "That current password is not right"
            : failure.code === "weak_master_password"
              ? "That new password was rejected"
              : "Could not change the master password",
          { description: failure.message },
        );
      } finally {
        setBusy(false);
      }
    },
    [canSubmit, current, next],
  );

  return (
    <div className="space-y-6">
      <SettingsSection
        title="Master password"
        description="The one password you have to remember. It unlocks the vault and nothing else can — it is never stored, transmitted or recoverable."
      >
        <form className="space-y-5" onSubmit={submit}>
          <div className="space-y-1.5">
            <Label htmlFor="current-master-password">Current password</Label>
            <Input
              id="current-master-password"
              type="password"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              className="max-w-sm"
            />
          </div>

          <Separator />

          <div className="space-y-1.5">
            <Label htmlFor="new-master-password">New password</Label>
            <Input
              id="new-master-password"
              type="password"
              value={next}
              onChange={(event) => setNext(event.target.value)}
              autoComplete="new-password"
              spellCheck={false}
              className="max-w-sm"
            />
            <MasterPasswordStrength
              password={next}
              onAssessment={setAssessment}
              className="max-w-sm"
            />
            <Hint>
              At least {capabilities.min_master_password_length} characters, and
              strong enough to pass the check above. A long passphrase of
              unrelated words beats a short complicated one.
            </Hint>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="confirm-master-password">Confirm new password</Label>
            <Input
              id="confirm-master-password"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              spellCheck={false}
              aria-invalid={confirm.length > 0 && !matches}
              className="max-w-sm"
            />
            {confirm.length > 0 && !matches && (
              <p className="text-xs text-destructive">
                The two passwords do not match.
              </p>
            )}
          </div>

          <Hint>
            Changing this re-wraps the key that encrypts your vault, so your
            entries themselves are not re-encrypted and nothing needs to be
            re-uploaded in bulk. Any other device you have keeps working and
            picks the change up on its next sync, where it will ask for the new
            password.
          </Hint>

          <Button type="submit" disabled={!canSubmit}>
            {busy ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <KeyRound className="size-4" aria-hidden />
            )}
            Change master password
          </Button>
        </form>
      </SettingsSection>

      <SettingsSection
        title="How your data is protected"
        action={
          <span className="text-xs text-muted-foreground tabular-nums">
            v{version}
          </span>
        }
      >
        <ul className="space-y-3">
          <Protection title="Argon2id key derivation">
            Your master password is stretched into a key with a memory-hard
            function, which makes guessing it expensive even for an attacker with
            your vault file and fast hardware.
          </Protection>
          <Protection title="XChaCha20-Poly1305 encryption">
            Every secret is encrypted with authenticated encryption, so tampering
            with the stored file is detected rather than silently accepted.
          </Protection>
          <Protection title="All crypto stays in the Rust backend">
            Keys are derived, held and zeroized outside this window. The
            interface only ever receives the one value it is about to show you,
            and copying a password moves it to the clipboard without it passing
            through the UI at all.
          </Protection>
          <Protection title="The bucket only ever receives ciphertext">
            Sync uploads the already-encrypted vault. Your storage provider,
            anyone on the network, and anyone who obtains the object sees
            nothing but random bytes.
          </Protection>
        </ul>
      </SettingsSection>
    </div>
  );
}

function Protection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <li className="flex items-start gap-3">
      <ShieldCheck
        className="mt-0.5 size-4 shrink-0 text-muted-foreground"
        aria-hidden
      />
      <div className="space-y-0.5">
        <p className="text-sm font-medium">{title}</p>
        <Hint>{children}</Hint>
      </div>
    </li>
  );
}
