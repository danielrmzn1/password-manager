/**
 * Chrome around the unlocked app: left navigation rail, sync indicator, and the
 * lock button. Feature screens render as `children`.
 */

import {
  AlertCircle,
  Cloud,
  CloudOff,
  KeyRound,
  Loader2,
  Lock,
  RefreshCw,
  Settings as SettingsIcon,
  Wand2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { SyncStatusEvent } from "@/lib/api";
import { cn } from "@/lib/utils";

export type Route = "vault" | "generator" | "settings";

const NAV: { route: Route; label: string; icon: typeof KeyRound }[] = [
  { route: "vault", label: "Vault", icon: KeyRound },
  { route: "generator", label: "Generator", icon: Wand2 },
  { route: "settings", label: "Settings", icon: SettingsIcon },
];

interface AppShellProps {
  route: Route;
  onRouteChange: (route: Route) => void;
  onLock: () => void;
  onSync: () => void;
  syncConfigured: boolean;
  syncStatus: SyncStatusEvent;
  version: string;
  children: React.ReactNode;
}

export function AppShell({
  route,
  onRouteChange,
  onLock,
  onSync,
  syncConfigured,
  syncStatus,
  version,
  children,
}: AppShellProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <nav
        className="flex w-16 shrink-0 flex-col items-center gap-1 border-r bg-sidebar py-3"
        aria-label="Main"
      >
        {NAV.map(({ route: target, label, icon: Icon }) => {
          const active = route === target;
          return (
            <Tooltip key={target}>
              <TooltipTrigger asChild>
                <Button
                  variant={active ? "secondary" : "ghost"}
                  size="icon"
                  className={cn("size-10", active && "text-foreground")}
                  onClick={() => onRouteChange(target)}
                  aria-current={active ? "page" : undefined}
                  aria-label={label}
                >
                  <Icon className="size-5" aria-hidden />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="right">{label}</TooltipContent>
            </Tooltip>
          );
        })}

        <div className="flex-1" />

        {syncConfigured && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="size-10"
                onClick={onSync}
                disabled={syncStatus.state === "syncing"}
                aria-label="Sync now"
              >
                <SyncIcon state={syncStatus.state} />
              </Button>
            </TooltipTrigger>
            <TooltipContent side="right">
              {syncStatus.state === "syncing"
                ? "Syncing…"
                : syncStatus.state === "error"
                  ? (syncStatus.message ?? "Sync failed")
                  : "Sync now"}
            </TooltipContent>
          </Tooltip>
        )}

        {!syncConfigured && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="grid size-10 place-items-center text-muted-foreground">
                <CloudOff className="size-4" aria-hidden />
              </span>
            </TooltipTrigger>
            <TooltipContent side="right">Sync is not set up</TooltipContent>
          </Tooltip>
        )}

        <Separator className="my-1 w-8" />

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="size-10"
              onClick={onLock}
              aria-label="Lock vault"
            >
              <Lock className="size-5" aria-hidden />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="right">
            Lock vault
            <span className="ml-2 text-muted-foreground">v{version}</span>
          </TooltipContent>
        </Tooltip>
      </nav>

      <main className="min-w-0 flex-1 overflow-hidden">{children}</main>
    </div>
  );
}

function SyncIcon({ state }: { state: SyncStatusEvent["state"] }) {
  if (state === "syncing") {
    return <Loader2 className="size-4 animate-spin" aria-hidden />;
  }
  if (state === "error") {
    return <AlertCircle className="size-4 text-destructive" aria-hidden />;
  }
  return <Cloud className="size-4" aria-hidden />;
}

/** Small reusable sync button for the settings screen. */
export function SyncNowButton({
  onSync,
  status,
}: {
  onSync: () => void;
  status: SyncStatusEvent;
}) {
  return (
    <Button
      variant="outline"
      onClick={onSync}
      disabled={status.state === "syncing"}
    >
      {status.state === "syncing" ? (
        <Loader2 className="size-4 animate-spin" aria-hidden />
      ) : (
        <RefreshCw className="size-4" aria-hidden />
      )}
      {status.state === "syncing" ? "Syncing…" : "Sync now"}
    </Button>
  );
}
