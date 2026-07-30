/**
 * The vault's right pane: everything stored on one entry.
 *
 * Secrets are never part of this component's state. The password and any secret
 * custom field are rendered by `SecretField`, which fetches a value only while
 * it is on screen, and copying always goes through `api.copyField` so the value
 * moves vault -> clipboard inside Rust.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ExternalLink, Loader2, Pencil, Star, Trash2 } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toast } from "sonner";

import {
  CopyFieldButton,
  CopyTextButton,
  SecretField,
} from "@/components/SecretField";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { api, toApiError, type EntryDetail as EntryData } from "@/lib/api";
import { displayHost, formatAbsolute, formatRelative } from "@/lib/format";

interface EntryDetailProps {
  entryId: string;
  onEdit: () => void;
  /** The entry is gone — the parent should clear its selection and reload. */
  onDeleted: () => void;
  /** Something on the entry changed — the parent should reload its list. */
  onChanged: () => void;
}

export function EntryDetail({
  entryId,
  onEdit,
  onDeleted,
  onChanged,
}: EntryDetailProps) {
  const [detail, setDetail] = useState<EntryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadToken, setReloadToken] = useState(0);
  const [favoriteBusy, setFavoriteBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    api
      .getEntry(entryId)
      .then((loaded) => {
        if (!cancelled) setDetail(loaded);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setDetail(null);
        toast.error("Could not load entry", {
          description: toApiError(error).message,
        });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [entryId, reloadToken]);

  const toggleFavorite = useCallback(async () => {
    if (!detail) return;
    setFavoriteBusy(true);
    try {
      await api.setFavorite(detail.id, !detail.favorite);
      setReloadToken((token) => token + 1);
      onChanged();
    } catch (error) {
      toast.error("Could not update favourite", {
        description: toApiError(error).message,
      });
    } finally {
      setFavoriteBusy(false);
    }
  }, [detail, onChanged]);

  const remove = useCallback(async () => {
    setDeleting(true);
    try {
      await api.deleteEntry(entryId);
      toast.success("Entry deleted");
      setConfirmOpen(false);
      onDeleted();
    } catch (error) {
      toast.error("Could not delete entry", {
        description: toApiError(error).message,
      });
    } finally {
      setDeleting(false);
    }
  }, [entryId, onDeleted]);

  if (loading && !detail) return <DetailPlaceholder />;

  if (!detail) {
    return (
      <div className="grid h-full place-items-center p-8">
        <p className="text-sm text-muted-foreground">
          This entry could not be loaded.
        </p>
      </div>
    );
  }

  const urls = detail.urls.filter((url) => url.trim().length > 0);
  const isLogin = detail.kind === "login";

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-start gap-3 border-b px-6 py-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-lg font-semibold" title={detail.title}>
              {detail.title}
            </h2>
            <Badge variant="secondary">
              {isLogin ? "Login" : "Secure note"}
            </Badge>
          </div>
          {detail.username && (
            <p className="truncate text-sm text-muted-foreground">
              {detail.username}
            </p>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-1">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={() => void toggleFavorite()}
            disabled={favoriteBusy}
            aria-label={
              detail.favorite ? "Remove from favourites" : "Add to favourites"
            }
            title={detail.favorite ? "Remove from favourites" : "Add to favourites"}
          >
            {favoriteBusy ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <Star
                className={detail.favorite ? "size-4 fill-current" : "size-4"}
                aria-hidden
              />
            )}
          </Button>

          <Button type="button" variant="outline" onClick={onEdit}>
            <Pencil className="size-4" aria-hidden />
            Edit
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-destructive"
            onClick={() => setConfirmOpen(true)}
            aria-label="Delete entry"
            title="Delete entry"
          >
            <Trash2 className="size-4" aria-hidden />
          </Button>
        </div>
      </header>

      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-6 px-6 py-5">
          {(isLogin || detail.username) && (
            <Field label="Username">
              <div className="flex items-center gap-1">
                <span className="min-h-9 flex-1 rounded-md border bg-muted/40 px-3 py-2 text-sm break-all">
                  {detail.username || (
                    <span className="text-muted-foreground italic">Not set</span>
                  )}
                </span>
                {detail.username && (
                  <CopyFieldButton
                    entryId={detail.id}
                    selector={{ field: "username" }}
                    label="Username"
                  />
                )}
              </div>
            </Field>
          )}

          {(isLogin || detail.has_password) && (
            <SecretField
              entryId={detail.id}
              selector={{ field: "password" }}
              label="Password"
              present={detail.has_password}
            />
          )}

          {urls.length > 0 && (
            <Field label={urls.length === 1 ? "Website" : "Websites"}>
              <ul className="space-y-1">
                {urls.map((url, index) => (
                  <li key={`${url}-${index}`} className="flex items-center gap-1">
                    <span
                      className="min-h-9 flex-1 truncate rounded-md border bg-muted/40 px-3 py-2 text-sm"
                      title={url}
                    >
                      {displayHost(url)}
                    </span>
                    <CopyTextButton value={url} label="Address" />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => void openExternally(url)}
                      aria-label={`Open ${displayHost(url)} in your browser`}
                      title="Open in your browser"
                    >
                      <ExternalLink className="size-4" aria-hidden />
                    </Button>
                  </li>
                ))}
              </ul>
            </Field>
          )}

          {detail.custom_fields.length > 0 && (
            <div className="space-y-4">
              {detail.custom_fields.map((field) =>
                field.secret ? (
                  <SecretField
                    key={field.id}
                    entryId={detail.id}
                    selector={{ field: "custom", id: field.id }}
                    label={field.label}
                  />
                ) : (
                  <Field key={field.id} label={field.label}>
                    <div className="flex items-center gap-1">
                      <span className="min-h-9 flex-1 rounded-md border bg-muted/40 px-3 py-2 text-sm break-all">
                        {field.value || (
                          <span className="text-muted-foreground italic">
                            Empty
                          </span>
                        )}
                      </span>
                      {field.value && (
                        <CopyFieldButton
                          entryId={detail.id}
                          selector={{ field: "custom", id: field.id }}
                          label={field.label}
                        />
                      )}
                    </div>
                  </Field>
                ),
              )}
            </div>
          )}

          {detail.has_notes && (
            <Field label="Notes">
              <div className="flex items-start gap-1">
                <div className="min-h-9 flex-1 rounded-md border bg-muted/40 px-3 py-2 text-sm whitespace-pre-wrap break-words">
                  {detail.notes}
                </div>
                <CopyFieldButton
                  entryId={detail.id}
                  selector={{ field: "notes" }}
                  label="Notes"
                />
              </div>
            </Field>
          )}

          {detail.tags.length > 0 && (
            <Field label="Tags">
              <div className="flex flex-wrap gap-1.5">
                {detail.tags.map((tag) => (
                  <Badge key={tag} variant="outline">
                    {tag}
                  </Badge>
                ))}
              </div>
            </Field>
          )}

          <Separator />

          <dl className="grid gap-x-6 gap-y-2 text-xs text-muted-foreground sm:grid-cols-3">
            <Meta label="Updated" at={detail.updated_at} />
            <Meta label="Created" at={detail.created_at} />
            {detail.has_password && (
              <Meta label="Password changed" at={detail.password_updated_at} />
            )}
          </dl>
        </div>
      </ScrollArea>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this entry?</AlertDialogTitle>
            <AlertDialogDescription>
              “{detail.title}” and everything stored on it — password, notes and
              custom fields — will be removed from the vault. This cannot be
              undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              onClick={(event) => {
                event.preventDefault();
                void remove();
              }}
            >
              {deleting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              Delete entry
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** A labelled block, matching `SecretField`'s label treatment. */
function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}

function Meta({ label, at }: { label: string; at: number }) {
  return (
    <div>
      <dt className="font-medium">{label}</dt>
      <dd title={formatAbsolute(at)}>{formatRelative(at)}</dd>
    </div>
  );
}

/**
 * Hand the URL to the OS browser instead of navigating the webview: a remote
 * origin must never be loaded inside the app's own window.
 */
async function openExternally(url: string) {
  const trimmed = url.trim();
  const target = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  try {
    await openUrl(target);
  } catch (error) {
    toast.error("Could not open the link", {
      description: toApiError(error).message,
    });
  }
}

function DetailPlaceholder() {
  return (
    <div className="space-y-6 px-6 py-5" aria-hidden>
      <div className="h-6 w-1/3 animate-pulse rounded bg-muted" />
      <div className="space-y-2">
        <div className="h-3 w-20 animate-pulse rounded bg-muted" />
        <div className="h-9 w-full animate-pulse rounded-md bg-muted" />
      </div>
      <div className="space-y-2">
        <div className="h-3 w-20 animate-pulse rounded bg-muted" />
        <div className="h-9 w-full animate-pulse rounded-md bg-muted" />
      </div>
    </div>
  );
}
