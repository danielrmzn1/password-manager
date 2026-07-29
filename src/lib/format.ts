/** Presentation helpers shared across screens. */

import type { Strength } from "@/lib/api";

/** Human-readable relative time from a unix-epoch-milliseconds timestamp. */
export function formatRelative(ms: number): string {
  if (!ms) return "never";

  const seconds = Math.round((Date.now() - ms) / 1000);
  if (seconds < 45) return "just now";

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["week", 60 * 60 * 24 * 7],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

  for (const [unit, secondsPerUnit] of units) {
    if (seconds >= secondsPerUnit) {
      return formatter.format(-Math.floor(seconds / secondsPerUnit), unit);
    }
  }
  return formatter.format(-seconds, "second");
}

/** Absolute date, for tooltips where precision matters. */
export function formatAbsolute(ms: number): string {
  if (!ms) return "never";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(ms));
}

export const STRENGTH_LABELS: Record<Strength, string> = {
  very_weak: "Very weak",
  weak: "Weak",
  fair: "Fair",
  strong: "Strong",
  very_strong: "Very strong",
};

/**
 * Tailwind classes for a strength level, driven by the `--strength-*` theme
 * tokens defined in `index.css` so both light and dark modes stay correct.
 */
export const STRENGTH_BAR_CLASS: Record<Strength, string> = {
  very_weak: "bg-strength-weakest",
  weak: "bg-strength-weak",
  fair: "bg-strength-fair",
  strong: "bg-strength-strong",
  very_strong: "bg-strength-strongest",
};

export const STRENGTH_TEXT_CLASS: Record<Strength, string> = {
  very_weak: "text-strength-weakest",
  weak: "text-strength-weak",
  fair: "text-strength-fair",
  strong: "text-strength-strong",
  very_strong: "text-strength-strongest",
};

/** Fraction of the meter to fill, 0..1. Saturates at 128 bits. */
export function strengthFraction(bits: number): number {
  return Math.max(0.04, Math.min(1, bits / 128));
}

export function formatEntropy(bits: number): string {
  return `${Math.round(bits)} bits`;
}

/** Host portion of a URL, for compact display in the entry list. */
export function displayHost(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return "";
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;
    return new URL(withScheme).host.replace(/^www\./, "");
  } catch {
    return trimmed;
  }
}

/** Initials for the entry list avatar. */
export function initials(title: string): string {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

/** "5 minutes", "30 seconds", "Never" — for timeout selects. */
export function formatDuration(seconds: number): string {
  if (seconds === 0) return "Never";
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.round(minutes / 60);
  return `${hours} hour${hours === 1 ? "" : "s"}`;
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return `${count} ${count === 1 ? singular : (plural ?? `${singular}s`)}`;
}
