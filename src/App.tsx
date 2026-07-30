/**
 * Root component: owns bootstrap, the lock/unlock/setup routing decision, and
 * the app-wide backend event subscriptions.
 *
 * The backend is the authority on lock state — this component reacts to
 * `vault://locked` rather than running its own timer, so a wedged webview cannot
 * keep the vault unlocked.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { AppShell, type Route } from "@/components/AppShell";
import { ThemeSync } from "@/components/theme-provider";
import { GeneratorScreen } from "@/screens/GeneratorScreen";
import { Onboarding } from "@/screens/Onboarding";
import { SettingsScreen } from "@/screens/SettingsScreen";
import { Unlock } from "@/screens/Unlock";
import { VaultScreen } from "@/screens/VaultScreen";
import {
  api,
  events,
  toApiError,
  type Bootstrap,
  type Settings,
  type SyncStatusEvent,
} from "@/lib/api";

/** How often to tell the backend the user is still active. */
const ACTIVITY_PING_MS = 20_000;

export default function App() {
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [route, setRoute] = useState<Route>("vault");
  const [syncStatus, setSyncStatus] = useState<SyncStatusEvent>({
    state: "idle",
    message: null,
  });
  /** Bumped to make the vault screen reload after an external change. */
  const [refreshToken, setRefreshToken] = useState(0);

  const reload = useCallback(async () => {
    try {
      setBootstrap(await api.bootstrap());
    } catch (error) {
      toast.error("Could not start up", {
        description: toApiError(error).message,
      });
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  // --- backend events ---
  useEffect(() => {
    const unlisteners = [
      events.onLocked((reason) => {
        setBootstrap((current) =>
          current ? { ...current, status: "locked" } : current,
        );
        setRoute("vault");
        if (reason === "timeout") {
          toast.info("Vault locked", {
            description:
              "It was locked automatically after a period of inactivity.",
          });
        }
      }),
      events.onChanged(() => setRefreshToken((n) => n + 1)),
      events.onSyncStatus((status) => {
        setSyncStatus(status);
        if (status.state === "error" && status.message) {
          toast.error("Sync failed", { description: status.message });
        }
      }),
      events.onClipboardCleared(() =>
        toast.info("Clipboard cleared", {
          description: "The copied secret has been wiped.",
        }),
      ),
      events.onBridgeFill((entryId) =>
        toast.info("Credential sent to the browser extension", {
          description: `Entry ${entryId.slice(0, 8)}… was autofilled.`,
        }),
      ),
    ];

    return () => {
      for (const pending of unlisteners) {
        void pending.then((unlisten) => unlisten());
      }
    };
  }, []);

  useActivityPing(bootstrap?.status === "unlocked");

  const handleLock = useCallback(async () => {
    try {
      await api.lock();
    } catch {
      // The `vault://locked` event drives the UI; a failure here is not
      // actionable for the user.
    }
    setBootstrap((current) =>
      current ? { ...current, status: "locked" } : current,
    );
  }, []);

  const handleSync = useCallback(async () => {
    try {
      const report = await api.syncNow();
      const { outcome } = report;
      const changed =
        outcome.added_from_remote +
        outcome.updated_from_remote +
        outcome.deleted_by_remote;
      toast.success(
        report.action === "up_to_date"
          ? "Already up to date"
          : changed > 0
            ? `Synced — ${changed} change${changed === 1 ? "" : "s"} merged`
            : "Synced",
        { description: report.warning ?? undefined },
      );
      setRefreshToken((n) => n + 1);
    } catch (error) {
      toast.error("Sync failed", { description: toApiError(error).message });
    }
  }, []);

  const handleSettingsChange = useCallback((settings: Settings) => {
    setBootstrap((current) => (current ? { ...current, settings } : current));
  }, []);

  if (!bootstrap) {
    return (
      <div className="grid h-screen place-items-center bg-background">
        <Loader2
          className="size-6 animate-spin text-muted-foreground"
          aria-label="Loading"
        />
      </div>
    );
  }

  return (
    <>
      <ThemeSync theme={bootstrap.settings.theme} />

      {bootstrap.status === "uninitialized" && (
        <Onboarding capabilities={bootstrap.capabilities} onComplete={reload} />
      )}

      {bootstrap.status === "locked" && (
        <Unlock onUnlocked={reload} version={bootstrap.version} />
      )}

      {bootstrap.status === "unlocked" && (
        <AppShell
          route={route}
          onRouteChange={setRoute}
          onLock={handleLock}
          onSync={handleSync}
          syncConfigured={bootstrap.sync_configured}
          syncStatus={syncStatus}
          version={bootstrap.version}
        >
          {route === "vault" && (
            <VaultScreen
              capabilities={bootstrap.capabilities}
              refreshToken={refreshToken}
            />
          )}
          {route === "generator" && (
            <GeneratorScreen capabilities={bootstrap.capabilities} />
          )}
          {route === "settings" && (
            <SettingsScreen
              settings={bootstrap.settings}
              onSettingsChange={handleSettingsChange}
              capabilities={bootstrap.capabilities}
              version={bootstrap.version}
              syncStatus={syncStatus}
              onSync={handleSync}
              onVaultChanged={reload}
            />
          )}
        </AppShell>
      )}
    </>
  );
}

/**
 * Report user activity to the backend so the auto-lock timer tracks real use.
 *
 * Throttled to one call per interval rather than one per event: the backend only
 * needs to know activity happened recently, not exactly when.
 */
function useActivityPing(active: boolean) {
  const dirty = useRef(false);

  useEffect(() => {
    if (!active) return;

    const mark = () => {
      dirty.current = true;
    };
    const observed: (keyof WindowEventMap)[] = [
      "pointerdown",
      "keydown",
      "wheel",
      "focus",
    ];
    for (const event of observed) {
      window.addEventListener(event, mark, { passive: true });
    }

    const timer = setInterval(() => {
      if (!dirty.current) return;
      dirty.current = false;
      void api.touch().catch(() => {
        /* locked in the meantime; the lock event already handled the UI */
      });
    }, ACTIVITY_PING_MS);

    return () => {
      for (const event of observed) {
        window.removeEventListener(event, mark);
      }
      clearInterval(timer);
    };
  }, [active]);
}
