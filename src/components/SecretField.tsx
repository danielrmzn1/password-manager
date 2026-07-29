/**
 * Reveal-on-click and copy-to-clipboard for a single secret field.
 *
 * The value is fetched from the backend only when the user reveals it, and is
 * dropped from React state when they hide it again — so a secret sits in the
 * webview's memory only while it is actually on screen. Copying does not fetch
 * the value at all: `api.copyField` moves it vault → clipboard inside Rust.
 */

import { useCallback, useState } from "react";
import { Copy, Eye, EyeOff, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api, toApiError, type FieldSelector } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Announce where a copied secret went and when it will be wiped. */
export function toastCopied(label: string, clearAfterSecs: number) {
  toast.success(`${label} copied`, {
    description:
      clearAfterSecs > 0
        ? `The clipboard will be cleared in ${clearAfterSecs} seconds.`
        : "Clipboard auto-clear is disabled in settings.",
  });
}

interface CopyFieldButtonProps {
  entryId: string;
  selector: FieldSelector;
  label: string;
  className?: string;
}

/** Copies a stored field without the value ever entering this webview. */
export function CopyFieldButton({
  entryId,
  selector,
  label,
  className,
}: CopyFieldButtonProps) {
  const [busy, setBusy] = useState(false);

  const copy = useCallback(async () => {
    setBusy(true);
    try {
      const clearAfter = await api.copyField(entryId, selector);
      toastCopied(label, clearAfter);
    } catch (error) {
      toast.error(`Could not copy ${label.toLowerCase()}`, {
        description: toApiError(error).message,
      });
    } finally {
      setBusy(false);
    }
  }, [entryId, selector, label]);

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className={cn("size-8", className)}
      onClick={copy}
      disabled={busy}
      aria-label={`Copy ${label.toLowerCase()}`}
      title={`Copy ${label.toLowerCase()}`}
    >
      {busy ? (
        <Loader2 className="size-4 animate-spin" aria-hidden />
      ) : (
        <Copy className="size-4" aria-hidden />
      )}
    </Button>
  );
}

/** Copies a value already visible in the UI, e.g. a freshly generated password. */
export function CopyTextButton({
  value,
  label,
  className,
  variant = "ghost",
}: {
  value: string;
  label: string;
  className?: string;
  variant?: "ghost" | "outline" | "secondary";
}) {
  const [busy, setBusy] = useState(false);

  return (
    <Button
      type="button"
      variant={variant}
      size="icon"
      className={cn("size-8", className)}
      disabled={busy || !value}
      aria-label={`Copy ${label.toLowerCase()}`}
      title={`Copy ${label.toLowerCase()}`}
      onClick={async () => {
        setBusy(true);
        try {
          const clearAfter = await api.copyText(value);
          toastCopied(label, clearAfter);
        } catch (error) {
          toast.error("Could not copy", {
            description: toApiError(error).message,
          });
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy ? (
        <Loader2 className="size-4 animate-spin" aria-hidden />
      ) : (
        <Copy className="size-4" aria-hidden />
      )}
    </Button>
  );
}

interface SecretFieldProps {
  entryId: string;
  selector: FieldSelector;
  label: string;
  /** Whether the entry actually holds a value for this field. */
  present?: boolean;
}

/** A labelled row with a masked value, a reveal toggle and a copy button. */
export function SecretField({
  entryId,
  selector,
  label,
  present = true,
}: SecretFieldProps) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const toggle = useCallback(async () => {
    if (revealed !== null) {
      // Drop it from memory as soon as it is hidden again.
      setRevealed(null);
      return;
    }
    setLoading(true);
    try {
      setRevealed(await api.revealField(entryId, selector));
    } catch (error) {
      toast.error(`Could not reveal ${label.toLowerCase()}`, {
        description: toApiError(error).message,
      });
    } finally {
      setLoading(false);
    }
  }, [revealed, entryId, selector, label]);

  return (
    <div className="space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <div className="flex items-center gap-1">
        <code
          className={cn(
            "min-h-9 flex-1 rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm break-all",
            revealed === null && "select-none tracking-widest",
          )}
        >
          {!present ? (
            <span className="font-sans text-muted-foreground italic">Not set</span>
          ) : revealed !== null ? (
            revealed
          ) : (
            "••••••••••••"
          )}
        </code>

        {present && (
          <>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-8"
              onClick={toggle}
              disabled={loading}
              aria-label={revealed === null ? `Reveal ${label.toLowerCase()}` : `Hide ${label.toLowerCase()}`}
              title={revealed === null ? "Reveal" : "Hide"}
            >
              {loading ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : revealed === null ? (
                <Eye className="size-4" aria-hidden />
              ) : (
                <EyeOff className="size-4" aria-hidden />
              )}
            </Button>
            <CopyFieldButton entryId={entryId} selector={selector} label={label} />
          </>
        )}
      </div>
    </div>
  );
}
