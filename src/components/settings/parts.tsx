/**
 * Small presentational building blocks shared by the settings sections.
 *
 * Kept deliberately dumb: no backend calls, no state. Every setting in this
 * screen is expected to carry a one-line plain-language explanation, so the
 * layout primitives here all make room for one.
 */

import { AlertTriangle } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

/** A titled group of related settings. */
export function SettingsSection({
  title,
  description,
  action,
  children,
  className,
}: {
  title: string;
  description?: React.ReactNode;
  /** Optional control rendered top-right, e.g. a status badge. */
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("[--card-spacing:--spacing(5)]", className)}>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <CardTitle>{title}</CardTitle>
          {action}
        </div>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-6">{children}</CardContent>
    </Card>
  );
}

/** Explanatory copy under a control. */
export function Hint({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <p className={cn("text-xs leading-relaxed text-muted-foreground", className)}>
      {children}
    </p>
  );
}

/** An inline caution — for trade-offs the user should notice but is allowed to make. */
export function Caution({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-start gap-1.5 text-xs leading-relaxed text-destructive/85">
      <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}

/**
 * One setting: label on the left, control on the right, explanation underneath.
 * `id` must match the control's own `id` so the label is properly associated.
 */
export function SettingRow({
  id,
  label,
  control,
  hint,
  extra,
}: {
  id: string;
  label: React.ReactNode;
  control: React.ReactNode;
  hint?: React.ReactNode;
  /** Rendered below the hint, e.g. a conditional caution. */
  extra?: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-6">
        <Label htmlFor={id} className="leading-snug">
          {label}
        </Label>
        <div className="shrink-0">{control}</div>
      </div>
      {hint && <Hint>{hint}</Hint>}
      {extra}
    </div>
  );
}

/** A stacked form field: label, input, then help text. */
export function FormField({
  id,
  label,
  hint,
  children,
  className,
}: {
  id: string;
  label: React.ReactNode;
  hint?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <Hint>{hint}</Hint>}
    </div>
  );
}

/** A read-only key/value line, e.g. the resolved sync object key. */
export function ReadOnlyRow({
  label,
  value,
  mono = true,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 rounded-lg border bg-muted/40 px-3 py-2">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span
        className={cn(
          "text-xs break-all text-foreground",
          mono && "font-mono",
        )}
      >
        {value}
      </span>
    </div>
  );
}
