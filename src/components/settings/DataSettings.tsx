/**
 * Import and backup.
 *
 * All three operations open their own native file dialog inside Rust, so nothing
 * here touches the filesystem. Backup passwords are held in state only while
 * their dialog is open and are cleared the moment the operation finishes.
 */

import { useCallback, useState } from "react";
import { AlertTriangle, Download, FileUp, Loader2, Upload, X } from "lucide-react";
import { toast } from "sonner";

import { MasterPasswordStrength } from "@/components/PasswordStrength";
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
  Hint,
  ReadOnlyRow,
  SettingsSection,
} from "@/components/settings/parts";
import {
  api,
  toApiError,
  type ImportReport,
  type PasswordAssessment,
} from "@/lib/api";
import { pluralize } from "@/lib/format";

type Busy = "csv" | "export" | "restore" | null;

interface DataSettingsProps {
  onVaultChanged: () => void;
}

export function DataSettings({ onVaultChanged }: DataSettingsProps) {
  const [busy, setBusy] = useState<Busy>(null);
  /** Rendered in whichever section produced it, rather than only as a toast. */
  const [result, setResult] = useState<{
    source: "csv" | "backup";
    title: string;
    report: ImportReport;
  } | null>(null);
  const [exportedPath, setExportedPath] = useState<string | null>(null);

  const [exportOpen, setExportOpen] = useState(false);
  const [restoreOpen, setRestoreOpen] = useState(false);

  const importCsv = useCallback(async () => {
    setBusy("csv");
    try {
      const report = await api.importCsv();
      setResult({ source: "csv", title: "CSV import", report });
      toast.success(
        report.imported > 0
          ? `Imported ${pluralize(report.imported, "entry", "entries")}`
          : "Nothing was imported",
        { description: "See the summary below for the details." },
      );
      onVaultChanged();
    } catch (error) {
      const failure = toApiError(error);
      toast.error("Import failed", { description: failure.message });
    } finally {
      setBusy(null);
    }
  }, [onVaultChanged]);

  const exportBackup = useCallback(
    async (password: string) => {
      setBusy("export");
      try {
        const path = await api.exportBackup(password);
        if (path === null) {
          toast.info("Export cancelled");
          return;
        }
        setExportedPath(path);
        toast.success("Encrypted backup written", { description: path });
      } catch (error) {
        toast.error("Could not write the backup", {
          description: toApiError(error).message,
        });
      } finally {
        setBusy(null);
      }
    },
    [],
  );

  const restoreBackup = useCallback(
    async (password: string) => {
      setBusy("restore");
      try {
        const report = await api.importBackup(password);
        setResult({ source: "backup", title: "Backup restore", report });
        toast.success(
          report.imported > 0
            ? `Merged ${pluralize(report.imported, "entry", "entries")}`
            : "Nothing new to merge",
          { description: "See the summary below for the details." },
        );
        onVaultChanged();
      } catch (error) {
        const failure = toApiError(error);
        toast.error(
          failure.code === "invalid_master_password"
            ? "That backup password is not right"
            : "Could not restore the backup",
          { description: failure.message },
        );
      } finally {
        setBusy(null);
      }
    },
    [onVaultChanged],
  );

  return (
    <div className="space-y-6">
      <SettingsSection
        title="Import from another password manager"
        description="Bring your logins across from a CSV export. Entries are added to your vault; nothing already in it is overwritten."
      >
        <Hint>
          The exports from Bitwarden, Chrome, Firefox, 1Password, LastPass and
          KeePass are understood directly, along with most other CSVs whose
          headers are recognisable. A CSV export from any password manager is
          plaintext — delete the file once the import is done.
        </Hint>

        <Button onClick={() => void importCsv()} disabled={busy !== null}>
          {busy === "csv" ? (
            <Loader2 className="size-4 animate-spin" aria-hidden />
          ) : (
            <FileUp className="size-4" aria-hidden />
          )}
          Choose a CSV file…
        </Button>

        {result?.source === "csv" && (
          <ImportResultPanel
            title={result.title}
            report={result.report}
            onDismiss={() => setResult(null)}
          />
        )}
      </SettingsSection>

      <SettingsSection
        title="Encrypted backup"
        description="A backup is a single file, encrypted with a password you choose here. Keep one somewhere separate from this machine — if you lose your vault and your master password, there is no recovery path."
      >
        <Hint>
          There is deliberately no plaintext export. Everything in the backup
          file is encrypted, so the file itself is safe to store on a USB stick
          or in ordinary cloud storage — its security rests entirely on the
          password you pick, so make it a strong one and store it separately.
        </Hint>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setExportOpen(true)}
            disabled={busy !== null}
          >
            <Download className="size-4" aria-hidden />
            Export a backup…
          </Button>

          <Button
            variant="outline"
            onClick={() => setRestoreOpen(true)}
            disabled={busy !== null}
          >
            <Upload className="size-4" aria-hidden />
            Restore from a backup…
          </Button>
        </div>

        {exportedPath && (
          <ReadOnlyRow label="Last backup written to" value={exportedPath} />
        )}

        <Hint>
          Restoring <strong className="font-medium text-foreground">merges</strong>{" "}
          the backup into your current vault rather than replacing it. Entries
          you have since added stay put, and newer versions win on conflict.
        </Hint>

        {result?.source === "backup" && (
          <ImportResultPanel
            title={result.title}
            report={result.report}
            onDismiss={() => setResult(null)}
          />
        )}
      </SettingsSection>

      <ExportDialog
        open={exportOpen}
        busy={busy === "export"}
        onOpenChange={setExportOpen}
        onConfirm={exportBackup}
      />

      <RestoreDialog
        open={restoreOpen}
        busy={busy === "restore"}
        onOpenChange={setRestoreOpen}
        onConfirm={restoreBackup}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------

function ImportResultPanel({
  title,
  report,
  onDismiss,
}: {
  title: string;
  report: ImportReport;
  onDismiss: () => void;
}) {
  return (
    <div className="space-y-4 rounded-lg border bg-muted/40 p-4">
      <div className="flex items-start justify-between gap-4">
        <p className="text-sm font-medium">{title} — summary</p>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={onDismiss}
          aria-label="Dismiss the import summary"
        >
          <X className="size-4" aria-hidden />
        </Button>
      </div>

      <dl className="grid grid-cols-3 gap-3">
        <Stat label="Imported" value={report.imported} />
        <Stat label="Duplicates skipped" value={report.duplicates} />
        <Stat label="Empty rows" value={report.empty_rows} />
      </dl>

      {report.warnings.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-muted-foreground">
            {pluralize(report.warnings.length, "warning")}
          </p>
          <ul className="space-y-1">
            {report.warnings.map((warning, index) => (
              <li
                key={`${index}-${warning}`}
                className="flex items-start gap-1.5 text-xs leading-relaxed text-muted-foreground"
              >
                <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden />
                <span>{warning}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-lg font-medium tabular-nums">{value}</dd>
    </div>
  );
}

// ---------------------------------------------------------------------------

function ExportDialog({
  open,
  busy,
  onOpenChange,
  onConfirm,
}: {
  open: boolean;
  busy: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null);

  const reset = useCallback(() => {
    setPassword("");
    setConfirm("");
    setAssessment(null);
  }, []);

  const matches = confirm.length > 0 && password === confirm;
  const canSubmit = !busy && (assessment?.acceptable ?? false) && matches;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Export an encrypted backup</DialogTitle>
          <DialogDescription>
            Choose the password that will protect the backup file. It is
            independent of your master password, and it is the only way to open
            the file later — there is no reset.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canSubmit) return;
            // Keep the password only in this local, never in state past here.
            const value = password;
            reset();
            onOpenChange(false);
            await onConfirm(value);
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="backup-password">Backup password</Label>
            <Input
              id="backup-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
              spellCheck={false}
              autoFocus
            />
            <MasterPasswordStrength
              password={password}
              onAssessment={setAssessment}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="backup-password-confirm">Confirm password</Label>
            <Input
              id="backup-password-confirm"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              spellCheck={false}
              aria-invalid={confirm.length > 0 && !matches}
            />
            {confirm.length > 0 && !matches && (
              <p className="text-xs text-destructive">
                The two passwords do not match.
              </p>
            )}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                reset();
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={!canSubmit}>
              {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
              Choose a location…
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RestoreDialog({
  open,
  busy,
  onOpenChange,
  onConfirm,
}: {
  open: boolean;
  busy: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setPassword("");
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Restore from a backup</DialogTitle>
          <DialogDescription>
            Enter the password the backup file was created with. Its entries are
            merged into your current vault — nothing is replaced or deleted.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={async (event) => {
            event.preventDefault();
            if (busy || !password) return;
            // Keep the password only in this local, never in state past here.
            const value = password;
            setPassword("");
            onOpenChange(false);
            await onConfirm(value);
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="restore-password">Backup password</Label>
            <Input
              id="restore-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              autoFocus
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setPassword("");
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={busy || !password}>
              {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
              Choose a backup file…
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
