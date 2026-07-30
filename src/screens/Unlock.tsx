/**
 * Lock screen. One field, one action.
 *
 * The wrong-password case is the expected failure, so it is reported inline
 * rather than as a toast: quieter, and it keeps the correction next to the
 * field. There is deliberately no "forgot password" affordance — the master
 * password is not recoverable, and hinting otherwise would be a lie.
 *
 * Unlocking takes a few hundred milliseconds by design (Argon2id runs in Rust),
 * hence the busy state.
 */

import { useEffect, useRef, useState, type FormEvent } from "react";
import { Loader2, Lock } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, toApiError } from "@/lib/api";

interface UnlockProps {
  onUnlocked: () => void | Promise<void>;
  version: string;
}

export function Unlock({ onUnlocked, version }: UnlockProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Autofocus on mount, and take focus back once the field is enabled again
  // after a failed attempt.
  useEffect(() => {
    if (!busy) inputRef.current?.focus();
  }, [busy]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || password.length === 0) return;

    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      setPassword("");
      await onUnlocked();
    } catch (caught) {
      const apiError = toApiError(caught);
      if (apiError.code === "invalid_master_password") {
        setError("Incorrect master password");
        setPassword("");
      } else {
        toast.error("Could not unlock the vault", {
          description: apiError.message,
        });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-screen flex-col bg-background">
      <main className="flex flex-1 items-center justify-center px-6">
        <form onSubmit={submit} className="w-full max-w-xs space-y-6">
          <div className="space-y-3 text-center">
            <div className="mx-auto grid size-11 place-items-center rounded-2xl bg-muted text-muted-foreground">
              <Lock className="size-5" aria-hidden />
            </div>
            <h1 className="font-heading text-lg font-semibold tracking-tight">
              Vault locked
            </h1>
            <p className="text-sm text-muted-foreground">
              Enter your master password to unlock.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="unlock-master-password" className="sr-only">
              Master password
            </Label>
            <Input
              id="unlock-master-password"
              ref={inputRef}
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                if (error) setError(null);
              }}
              autoComplete="off"
              spellCheck={false}
              disabled={busy}
              placeholder="Master password"
              className="h-10 text-center"
              aria-invalid={error !== null}
              aria-describedby={error ? "unlock-error" : undefined}
            />
            <p
              id="unlock-error"
              role="alert"
              className="min-h-4 text-center text-xs text-destructive"
            >
              {error}
            </p>
          </div>

          <Button
            type="submit"
            size="lg"
            className="w-full"
            disabled={busy || password.length === 0}
          >
            {busy ? (
              <>
                <Loader2 className="animate-spin" aria-hidden />
                Unlocking…
              </>
            ) : (
              "Unlock"
            )}
          </Button>
        </form>
      </main>

      <footer className="pb-6 text-center text-xs text-muted-foreground">
        Password Manager <span className="tabular-nums">v{version}</span>
      </footer>
    </div>
  );
}
