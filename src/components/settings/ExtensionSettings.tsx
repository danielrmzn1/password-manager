/**
 * Browser-extension bridge.
 *
 * The bridge is a loopback listener the extension talks to. It is opt-in, and
 * pairing requires a one-time code shown here, so an arbitrary page or another
 * extension cannot start pulling credentials. `bridgeInfo` is polled only while
 * a pairing dialog is open — the rest of the time it is refreshed after actions.
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2, Puzzle, Unplug } from "lucide-react";
import { toast } from "sonner";

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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import {
  Hint,
  ReadOnlyRow,
  SettingRow,
  SettingsSection,
} from "@/components/settings/parts";
import {
  api,
  events,
  toApiError,
  type BridgeInfo,
  type Settings,
} from "@/lib/api";

/** How often to re-check pairing state while the code is on screen. */
const PAIRING_POLL_MS = 1500;

interface ExtensionSettingsProps {
  settings: Settings;
  onPatch: (patch: Partial<Settings>) => Promise<Settings | null>;
}

export function ExtensionSettings({ settings, onPatch }: ExtensionSettingsProps) {
  const [info, setInfo] = useState<BridgeInfo | null>(null);
  const [pairingCode, setPairingCode] = useState<string | null>(null);
  const [busy, setBusy] = useState<"toggle" | "pair" | "unpair" | null>(null);

  const refresh = useCallback(async () => {
    try {
      setInfo(await api.bridgeInfo());
    } catch {
      // Not actionable: the switch below already reflects the stored preference.
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // While the code is displayed, watch for the extension completing the exchange.
  useEffect(() => {
    if (!pairingCode) return;

    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      setPairingCode(null);
      void refresh();
      toast.success("Extension paired", {
        description:
          "It can now request credentials while the vault is unlocked.",
      });
    };

    const timer = setInterval(() => {
      api
        .bridgeInfo()
        .then((next) => {
          setInfo(next);
          if (next.paired) finish();
        })
        .catch(() => {
          /* transient; the next tick retries */
        });
    }, PAIRING_POLL_MS);
    const listener = events.onBridgePaired(finish);

    return () => {
      done = true;
      clearInterval(timer);
      void listener.then((unlisten) => unlisten());
    };
  }, [pairingCode, refresh]);

  const toggleBridge = useCallback(
    async (enabled: boolean) => {
      setBusy("toggle");
      const saved = await onPatch({ bridge_enabled: enabled });
      if (saved) await refresh();
      setBusy(null);
    },
    [onPatch, refresh],
  );

  const beginPairing = useCallback(async () => {
    setBusy("pair");
    try {
      setPairingCode(await api.bridgeBeginPairing());
    } catch (error) {
      toast.error("Could not start pairing", {
        description: toApiError(error).message,
      });
    } finally {
      setBusy(null);
    }
  }, []);

  const cancelPairing = useCallback(async () => {
    setPairingCode(null);
    try {
      await api.bridgeCancelPairing();
    } catch {
      // The code expires on its own; nothing useful to tell the user.
    }
    void refresh();
  }, [refresh]);

  const unpair = useCallback(async () => {
    setBusy("unpair");
    try {
      await api.bridgeUnpair();
      toast.success("Extension unpaired", {
        description: "It can no longer request anything from the vault.",
      });
      await refresh();
    } catch (error) {
      toast.error("Could not unpair", {
        description: toApiError(error).message,
      });
    } finally {
      setBusy(null);
    }
  }, [refresh]);

  const running = info?.running ?? false;
  const paired = info?.paired ?? false;

  return (
    <div className="space-y-6">
      <SettingsSection
        title="Browser extension"
        description="An optional Chromium extension can fill saved logins on matching sites. It talks to this app over a local bridge — nothing goes through a server, and no credentials are stored in the browser."
        action={
          <Badge
            variant={paired ? "secondary" : running ? "outline" : "ghost"}
          >
            {paired ? "Paired" : running ? "Waiting to pair" : "Off"}
          </Badge>
        }
      >
        <SettingRow
          id="bridge-enabled"
          label="Allow the browser extension to connect"
          hint="Opens a listener on 127.0.0.1 that is reachable only from this machine, and only usable by the one extension you pair with it. It is off by default. While the vault is locked the bridge answers nothing — no autofill happens until you unlock."
          control={
            <Switch
              id="bridge-enabled"
              checked={settings.bridge_enabled}
              onCheckedChange={(checked) => void toggleBridge(checked)}
              disabled={busy === "toggle"}
            />
          }
        />

        {running && info?.port !== null && info?.port !== undefined && (
          <ReadOnlyRow
            label="Listening on"
            value={`127.0.0.1:${info.port}`}
          />
        )}

        {paired && info?.extension_id && (
          <ReadOnlyRow label="Paired extension" value={info.extension_id} />
        )}

        {settings.bridge_enabled && !running && (
          <Hint>
            The bridge is enabled but not currently listening. Unlock the vault,
            or check that nothing else has taken the port.
          </Hint>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {running && !paired && (
            <Button
              onClick={() => void beginPairing()}
              disabled={busy !== null}
            >
              {busy === "pair" ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : (
                <Puzzle className="size-4" aria-hidden />
              )}
              Pair extension
            </Button>
          )}

          {paired && (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" disabled={busy !== null}>
                  <Unplug className="size-4" aria-hidden />
                  Unpair
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Unpair this extension?</AlertDialogTitle>
                  <AlertDialogDescription>
                    The extension immediately loses access to your vault and
                    autofill stops working. Nothing in the vault changes. You can
                    pair it again — or pair a different browser — with a fresh
                    code whenever you like.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Keep it paired</AlertDialogCancel>
                  <AlertDialogAction
                    variant="destructive"
                    onClick={() => void unpair()}
                  >
                    Unpair
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        </div>

        <Hint>
          The extension itself lives in this repository’s{" "}
          <code className="font-mono">extension/</code> folder. Open{" "}
          <code className="font-mono">chrome://extensions</code>, turn on
          developer mode, and use “Load unpacked” to point at that folder.
        </Hint>
      </SettingsSection>

      <Dialog
        open={pairingCode !== null}
        onOpenChange={(open) => {
          if (!open) void cancelPairing();
        }}
      >
        <DialogContent showCloseButton={false}>
          <DialogHeader>
            <DialogTitle>Pairing code</DialogTitle>
            <DialogDescription>
              Open the extension popup and type this code to link it to this
              vault. It is valid for 2 minutes and can only be used once.
            </DialogDescription>
          </DialogHeader>

          <div
            className="rounded-lg border bg-muted/40 py-6 text-center"
            aria-live="polite"
          >
            <span
              className="font-mono text-4xl font-semibold tracking-[0.35em] tabular-nums"
              aria-label={`Pairing code ${pairingCode?.split("").join(" ") ?? ""}`}
            >
              {pairingCode}
            </span>
          </div>

          <Hint>
            This code only authorises the extension; it is not a password and
            gives no access on its own. This dialog closes by itself once pairing
            completes.
          </Hint>

          <DialogFooter>
            <Button variant="outline" onClick={() => void cancelPairing()}>
              Cancel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
