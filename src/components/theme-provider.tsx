/**
 * Theme wiring.
 *
 * `next-themes` owns the `.dark` class on `<html>`; the backend owns the
 * persisted preference (it lives in `settings.json` so the lock screen renders in
 * the right theme before the vault is unlocked). `ThemeSync` keeps the two in
 * step whenever the stored setting changes.
 */

import { useEffect } from "react";
import { ThemeProvider as NextThemesProvider, useTheme } from "next-themes";

import type { Theme } from "@/lib/api";

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      // The window has no server-rendered markup and no cross-tab state to
      // reconcile, so the transition suppression is unnecessary here.
      disableTransitionOnChange
    >
      {children}
    </NextThemesProvider>
  );
}

/** Applies the backend's stored theme preference. Renders nothing. */
export function ThemeSync({ theme }: { theme: Theme | undefined }) {
  const { setTheme } = useTheme();

  useEffect(() => {
    if (theme) setTheme(theme);
  }, [theme, setTheme]);

  return null;
}
