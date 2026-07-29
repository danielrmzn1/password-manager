/**
 * Create / edit dialog for a vault entry.
 *
 * The detail command deliberately never returns the stored password, so in edit
 * mode the password starts as `null`, which the backend reads as "leave
 * unchanged". A string is only sent once the user actually types one (or applies
 * a generated value); merely revealing the current password does not count as an
 * edit. The same rule applies to secret custom fields.
 */

import { useCallback, useEffect, useId, useState } from "react";
import {
  Eye,
  EyeOff,
  Loader2,
  Plus,
  Trash2,
  Wand2,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { GeneratorPanel } from "@/components/GeneratorPanel";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  emptyEntryInput,
  toApiError,
  type EntryDetail,
  type EntryInput,
  type EntryKind,
  type GeneratorCapabilities,
} from "@/lib/api";

interface CustomFieldRow {
  /** Stable React key; not sent to the backend. */
  key: string;
  /** `null` for a row the user just added. */
  id: string | null;
  label: string;
  /** `null` means "keep the stored value" (an untouched secret field). */
  value: string | null;
  secret: boolean;
}

interface EntryFormProps {
  capabilities: GeneratorCapabilities;
  /** Omit to create a new entry. */
  entryId?: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: (id: string) => void;
}

export function EntryForm({
  capabilities,
  entryId,
  open,
  onOpenChange,
  onSaved,
}: EntryFormProps) {
  const uid = useId();
  const editing = entryId !== undefined;

  const [kind, setKind] = useState<EntryKind>("login");
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [notes, setNotes] = useState("");
  const [urls, setUrls] = useState<string[]>([""]);
  const [tagsText, setTagsText] = useState("");
  const [favorite, setFavorite] = useState(false);
  const [fields, setFields] = useState<CustomFieldRow[]>([]);

  /** `null` = nothing typed yet. Only sent when `passwordDirty`. */
  const [password, setPassword] = useState<string | null>("");
  const [passwordDirty, setPasswordDirty] = useState(false);
  /** "keep" hides the input behind an explicit "Change password" action. */
  const [passwordMode, setPasswordMode] = useState<"keep" | "edit">("edit");
  const [showPassword, setShowPassword] = useState(false);
  const [revealing, setRevealing] = useState(false);
  const [revealedCurrent, setRevealedCurrent] = useState(false);
  const [hasStoredPassword, setHasStoredPassword] = useState(false);

  const [revealedRows, setRevealedRows] = useState<string[]>([]);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [titleError, setTitleError] = useState<string | null>(null);

  const resetTo = useCallback((detail: EntryDetail | null) => {
    if (detail === null) {
      const blank = emptyEntryInput();
      setKind(blank.kind);
      setTitle(blank.title);
      setUsername(blank.username);
      setNotes(blank.notes);
      setUrls([""]);
      setTagsText("");
      setFavorite(blank.favorite);
      setFields([]);
      setPassword("");
      setPasswordDirty(false);
      setPasswordMode("edit");
      setHasStoredPassword(false);
    } else {
      setKind(detail.kind);
      setTitle(detail.title);
      setUsername(detail.username);
      setNotes(detail.notes);
      setUrls(detail.urls.length > 0 ? detail.urls : [""]);
      setTagsText(detail.tags.join(", "));
      setFavorite(detail.favorite);
      setFields(
        detail.custom_fields.map((field) => ({
          key: field.id,
          id: field.id,
          label: field.label,
          value: field.value,
          secret: field.secret,
        })),
      );
      // No password ever arrives here: `null` keeps the stored one.
      setPassword(null);
      setPasswordDirty(false);
      setPasswordMode(detail.has_password ? "keep" : "edit");
      setHasStoredPassword(detail.has_password);
    }
    setShowPassword(false);
    setRevealedCurrent(false);
    setRevealedRows([]);
    setGeneratorOpen(false);
    setTitleError(null);
  }, []);

  // Load (or blank out) whenever the dialog opens.
  useEffect(() => {
    if (!open) return;

    if (entryId === undefined) {
      resetTo(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    resetTo(null);
    api
      .getEntry(entryId)
      .then((detail) => {
        if (cancelled) return;
        resetTo(detail);
      })
      .catch((error) => {
        if (cancelled) return;
        toast.error("Could not load the entry", {
          description: toApiError(error).message,
        });
        onOpenChange(false);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
    // `resetTo` is stable and `onOpenChange` is only used on the error path.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, entryId]);

  // Drop every secret from webview memory as soon as the dialog is closed.
  useEffect(() => {
    if (open) return;
    setPassword(null);
    setPasswordDirty(false);
    setShowPassword(false);
    setRevealedCurrent(false);
    setRevealedRows([]);
    setGeneratorOpen(false);
    setFields((current) =>
      current.map((field) =>
        field.secret ? { ...field, value: field.id === null ? "" : null } : field,
      ),
    );
  }, [open]);

  const updateField = (key: string, patch: Partial<CustomFieldRow>) =>
    setFields((current) =>
      current.map((field) =>
        field.key === key ? { ...field, ...patch } : field,
      ),
    );

  const applyGenerated = (value: string) => {
    setPassword(value);
    setPasswordDirty(true);
    setPasswordMode("edit");
    setShowPassword(true);
    setGeneratorOpen(false);
    toast.success("Generated password applied", {
      description: "Save the entry to store it in your vault.",
    });
  };

  const revealCurrent = async () => {
    if (entryId === undefined) return;
    setRevealing(true);
    try {
      const value = await api.revealField(entryId, { field: "password" });
      setPassword(value);
      setPasswordMode("edit");
      setShowPassword(true);
      setRevealedCurrent(true);
    } catch (error) {
      toast.error("Could not reveal the password", {
        description: toApiError(error).message,
      });
    } finally {
      setRevealing(false);
    }
  };

  const submit = async () => {
    const trimmedTitle = title.trim();
    if (!trimmedTitle) {
      setTitleError("A title is required.");
      return;
    }
    setTitleError(null);

    // `null` means "leave the stored password alone", which is the normal case in
    // edit mode because the form is populated without it. A new note has no
    // password field at all, hence the empty string when creating one.
    const passwordPayload = editing
      ? passwordDirty
        ? (password ?? "")
        : null
      : kind === "login"
        ? (password ?? "")
        : "";

    const tags = Array.from(
      new Set(
        tagsText
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
      ),
    );

    const input: EntryInput = {
      kind,
      title: trimmedTitle,
      // Switching an existing login to a secure note must not destroy data.
      // Previously the username and URLs were blanked while the password was
      // kept, which was both inconsistent and a silent-data-loss footgun on a
      // mis-click. `kind` is a classification, not a delete button: the credential
      // fields are carried through, and the detail view simply shows whichever of
      // them are actually populated.
      username: username.trim(),
      password: passwordPayload,
      urls: urls.map((url) => url.trim()).filter(Boolean),
      notes,
      custom_fields: fields
        .filter((field) => field.label.trim().length > 0)
        .map((field) => ({
          id: field.id,
          label: field.label.trim(),
          value: field.value,
          secret: field.secret,
        })),
      tags,
      favorite,
    };

    setSaving(true);
    try {
      if (entryId !== undefined) {
        await api.updateEntry(entryId, input);
        toast.success("Entry saved");
        onSaved(entryId);
      } else {
        const created = await api.createEntry(input);
        toast.success("Entry created");
        onSaved(created);
      }
      onOpenChange(false);
    } catch (error) {
      toast.error(editing ? "Could not save the entry" : "Could not create the entry", {
        description: toApiError(error).message,
      });
    } finally {
      setSaving(false);
    }
  };

  const isLogin = kind === "login";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit entry" : "New entry"}</DialogTitle>
          <DialogDescription>
            {editing
              ? "Changes are encrypted and written to your vault when you save."
              : "Everything you enter is encrypted before it touches the disk."}
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" aria-hidden />
            Loading entry…
          </div>
        ) : (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <div className="max-h-[60vh] space-y-6 overflow-y-auto px-1">
              {/* --- basics ------------------------------------------- */}
              <div className="grid gap-4 sm:grid-cols-[10rem_minmax(0,1fr)]">
                <div className="space-y-2">
                  <Label htmlFor={`${uid}-kind`}>Type</Label>
                  <Select
                    value={kind}
                    onValueChange={(value) => setKind(value as EntryKind)}
                  >
                    <SelectTrigger id={`${uid}-kind`} className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="login">Login</SelectItem>
                      <SelectItem value="note">Secure note</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor={`${uid}-title`}>Title</Label>
                  <Input
                    id={`${uid}-title`}
                    value={title}
                    autoFocus={!editing}
                    maxLength={120}
                    placeholder="GitHub"
                    aria-invalid={titleError !== null}
                    aria-describedby={
                      titleError !== null ? `${uid}-title-error` : undefined
                    }
                    onChange={(event) => {
                      setTitle(event.target.value);
                      if (titleError !== null) setTitleError(null);
                    }}
                  />
                  {titleError !== null && (
                    <p
                      id={`${uid}-title-error`}
                      className="text-xs text-destructive"
                    >
                      {titleError}
                    </p>
                  )}
                </div>
              </div>

              {isLogin && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor={`${uid}-username`}>Username</Label>
                    <Input
                      id={`${uid}-username`}
                      value={username}
                      autoComplete="off"
                      spellCheck={false}
                      placeholder="you@example.com"
                      onChange={(event) => setUsername(event.target.value)}
                    />
                  </div>

                  {/* --- password ---------------------------------- */}
                  <div className="space-y-2">
                    <Label htmlFor={`${uid}-password`}>Password</Label>

                    {passwordMode === "keep" ? (
                      <div className="flex items-center gap-2">
                        <Input
                          id={`${uid}-password`}
                          type="password"
                          value=""
                          readOnly
                          autoComplete="off"
                          spellCheck={false}
                          placeholder="Unchanged"
                          className="flex-1"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => void revealCurrent()}
                          disabled={revealing}
                        >
                          {revealing ? (
                            <Loader2 className="size-3.5 animate-spin" aria-hidden />
                          ) : (
                            <Eye className="size-3.5" aria-hidden />
                          )}
                          Reveal current
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            // Switching to "edit" is what actually swaps the
                            // masked *Unchanged* field for a typeable one.
                            setPasswordMode("edit");
                            setPassword("");
                            setPasswordDirty(false);
                            setShowPassword(false);
                            setRevealedCurrent(false);
                          }}
                        >
                          Change password
                        </Button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <div className="relative flex-1">
                          <Input
                            id={`${uid}-password`}
                            type={showPassword ? "text" : "password"}
                            value={password ?? ""}
                            autoComplete="new-password"
                            spellCheck={false}
                            placeholder={
                              hasStoredPassword && !passwordDirty
                                ? "Unchanged"
                                : "Type or generate a password"
                            }
                            className="pr-9 font-mono"
                            onChange={(event) => {
                              setPassword(event.target.value);
                              setPasswordDirty(true);
                              setRevealedCurrent(false);
                            }}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            className="absolute top-1/2 right-1 -translate-y-1/2"
                            onClick={() => setShowPassword((value) => !value)}
                            aria-label={
                              showPassword ? "Hide password" : "Show password"
                            }
                            title={showPassword ? "Hide" : "Show"}
                          >
                            {showPassword ? (
                              <EyeOff className="size-3.5" aria-hidden />
                            ) : (
                              <Eye className="size-3.5" aria-hidden />
                            )}
                          </Button>
                        </div>

                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setGeneratorOpen(true)}
                        >
                          <Wand2 className="size-3.5" aria-hidden />
                          Generate
                        </Button>

                        {hasStoredPassword && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setPassword(null);
                              setPasswordDirty(false);
                              setShowPassword(false);
                              setRevealedCurrent(false);
                              setPasswordMode("keep");
                            }}
                          >
                            Keep current
                          </Button>
                        )}
                      </div>
                    )}

                    {revealedCurrent && !passwordDirty && (
                      <p className="text-xs text-muted-foreground">
                        This is the stored password. Saving without editing it
                        leaves it unchanged.
                      </p>
                    )}
                  </div>

                  {/* --- urls -------------------------------------- */}
                  <div className="space-y-2">
                    <Label htmlFor={`${uid}-url-0`}>Websites</Label>
                    <div className="space-y-2">
                      {urls.map((url, index) => (
                        <div key={index} className="flex items-center gap-2">
                          <Input
                            id={`${uid}-url-${index}`}
                            value={url}
                            autoComplete="off"
                            spellCheck={false}
                            placeholder="https://example.com"
                            onChange={(event) =>
                              setUrls((current) =>
                                current.map((item, position) =>
                                  position === index ? event.target.value : item,
                                ),
                              )
                            }
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            onClick={() =>
                              setUrls((current) => {
                                const next = current.filter(
                                  (_, position) => position !== index,
                                );
                                return next.length > 0 ? next : [""];
                              })
                            }
                            aria-label={`Remove website ${index + 1}`}
                            title="Remove"
                          >
                            <X className="size-4" aria-hidden />
                          </Button>
                        </div>
                      ))}
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => setUrls((current) => [...current, ""])}
                    >
                      <Plus className="size-3.5" aria-hidden />
                      Add website
                    </Button>
                  </div>
                </>
              )}

              {/* --- notes ------------------------------------------- */}
              <div className="space-y-2">
                <Label htmlFor={`${uid}-notes`}>Notes</Label>
                <Textarea
                  id={`${uid}-notes`}
                  value={notes}
                  rows={isLogin ? 3 : 8}
                  spellCheck={false}
                  placeholder={
                    isLogin
                      ? "Recovery codes, security answers, anything else."
                      : "Everything in this note is encrypted."
                  }
                  onChange={(event) => setNotes(event.target.value)}
                />
              </div>

              <Separator />

              {/* --- custom fields ---------------------------------- */}
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <p className="text-sm font-medium">Custom fields</p>
                    <p className="text-xs text-muted-foreground">
                      Extra values such as a PIN, an API key or a recovery code.
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setFields((current) => [
                        ...current,
                        {
                          key: crypto.randomUUID(),
                          id: null,
                          label: "",
                          value: "",
                          secret: false,
                        },
                      ])
                    }
                  >
                    <Plus className="size-3.5" aria-hidden />
                    Add field
                  </Button>
                </div>

                {fields.length > 0 && (
                  <ul className="space-y-2">
                    {fields.map((field) => {
                      // An existing secret field arrives with `value === null`;
                      // typing replaces it, otherwise it is left untouched.
                      const keepsStoredValue =
                        field.secret && field.id !== null && field.value === null;
                      const revealed = revealedRows.includes(field.key);

                      return (
                        <li
                          key={field.key}
                          className="grid gap-2 rounded-lg border bg-card p-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto]"
                        >
                          <Input
                            value={field.label}
                            aria-label="Field label"
                            placeholder="Label"
                            maxLength={60}
                            onChange={(event) =>
                              updateField(field.key, {
                                label: event.target.value,
                              })
                            }
                          />

                          <div className="relative">
                            <Input
                              value={field.value ?? ""}
                              aria-label="Field value"
                              type={
                                field.secret && !revealed ? "password" : "text"
                              }
                              autoComplete="off"
                              spellCheck={false}
                              placeholder={
                                keepsStoredValue ? "Unchanged" : "Value"
                              }
                              className={
                                field.secret ? "pr-9 font-mono" : undefined
                              }
                              onChange={(event) => {
                                const typed = event.target.value;
                                updateField(field.key, {
                                  // Clearing an existing secret field means
                                  // "keep what is stored", not "store empty".
                                  value:
                                    field.secret &&
                                    field.id !== null &&
                                    typed === ""
                                      ? null
                                      : typed,
                                });
                              }}
                            />
                            {field.secret && (
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                className="absolute top-1/2 right-1 -translate-y-1/2"
                                onClick={() =>
                                  setRevealedRows((current) =>
                                    current.includes(field.key)
                                      ? current.filter(
                                          (item) => item !== field.key,
                                        )
                                      : [...current, field.key],
                                  )
                                }
                                aria-label={
                                  revealed
                                    ? "Hide field value"
                                    : "Show field value"
                                }
                                title={revealed ? "Hide" : "Show"}
                              >
                                {revealed ? (
                                  <EyeOff className="size-3.5" aria-hidden />
                                ) : (
                                  <Eye className="size-3.5" aria-hidden />
                                )}
                              </Button>
                            )}
                          </div>

                          <div className="flex items-center justify-end gap-3">
                            <div className="flex items-center gap-2">
                              <Switch
                                id={`${uid}-secret-${field.key}`}
                                checked={field.secret}
                                onCheckedChange={(checked) =>
                                  updateField(field.key, { secret: checked })
                                }
                              />
                              <Label
                                htmlFor={`${uid}-secret-${field.key}`}
                                className="text-xs font-normal text-muted-foreground"
                              >
                                Hidden
                              </Label>
                            </div>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              onClick={() =>
                                setFields((current) =>
                                  current.filter(
                                    (item) => item.key !== field.key,
                                  ),
                                )
                              }
                              aria-label={`Remove field ${field.label || "without a label"}`}
                              title="Remove field"
                            >
                              <Trash2 className="size-4" aria-hidden />
                            </Button>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>

              <Separator />

              {/* --- tags & favorite -------------------------------- */}
              <div className="space-y-2">
                <Label htmlFor={`${uid}-tags`}>Tags</Label>
                <Input
                  id={`${uid}-tags`}
                  value={tagsText}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="work, email, 2fa"
                  onChange={(event) => setTagsText(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Separate tags with commas.
                </p>
              </div>

              <div className="flex items-center justify-between gap-6">
                <div className="space-y-0.5">
                  <Label htmlFor={`${uid}-favorite`} className="font-normal">
                    Favorite
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Keeps this entry pinned to the top of your vault.
                  </p>
                </div>
                <Switch
                  id={`${uid}-favorite`}
                  checked={favorite}
                  onCheckedChange={setFavorite}
                />
              </div>
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={saving}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={saving}>
                {saving && (
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                )}
                {editing ? "Save changes" : "Create entry"}
              </Button>
            </DialogFooter>
          </form>
        )}

        {/* The generator lives in its own dialog so its inputs cannot
            accidentally submit the entry form. */}
        <Dialog open={generatorOpen} onOpenChange={setGeneratorOpen}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Generate a password</DialogTitle>
              <DialogDescription>
                Generated in the Rust core with a cryptographic random source.
              </DialogDescription>
            </DialogHeader>
            <div className="max-h-[60vh] overflow-y-auto px-1">
              <GeneratorPanel
                capabilities={capabilities}
                compact
                onUse={applyGenerated}
              />
            </div>
          </DialogContent>
        </Dialog>
      </DialogContent>
    </Dialog>
  );
}
