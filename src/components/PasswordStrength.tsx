/**
 * Strength meter, shared by onboarding, the generator and the entry form.
 *
 * Two entry points because the two sources of a strength figure differ:
 * `StrengthMeter` renders a known entropy value (generated secrets), while
 * `MasterPasswordStrength` asks the backend to assess a password the user typed
 * (dictionary- and pattern-aware, via zxcvbn).
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Check } from "lucide-react";

import { api, type PasswordAssessment, type Strength } from "@/lib/api";
import {
  STRENGTH_BAR_CLASS,
  STRENGTH_LABELS,
  STRENGTH_TEXT_CLASS,
  formatEntropy,
  strengthFraction,
} from "@/lib/format";
import { cn } from "@/lib/utils";

interface StrengthMeterProps {
  strength: Strength;
  entropyBits: number;
  /** Hide the numeric bit count when space is tight. */
  showBits?: boolean;
  className?: string;
}

export function StrengthMeter({
  strength,
  entropyBits,
  showBits = true,
  className,
}: StrengthMeterProps) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-baseline justify-between text-xs">
        <span className={cn("font-medium", STRENGTH_TEXT_CLASS[strength])}>
          {STRENGTH_LABELS[strength]}
        </span>
        {showBits && (
          <span className="text-muted-foreground tabular-nums">
            {formatEntropy(entropyBits)}
          </span>
        )}
      </div>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuenow={Math.round(entropyBits)}
        aria-valuemin={0}
        aria-valuemax={128}
        aria-label="Password strength"
      >
        <div
          className={cn(
            "h-full rounded-full transition-all duration-300",
            STRENGTH_BAR_CLASS[strength],
          )}
          style={{ width: `${strengthFraction(entropyBits) * 100}%` }}
        />
      </div>
    </div>
  );
}

interface MasterPasswordStrengthProps {
  password: string;
  /** Called whenever the assessment changes, so the parent can gate its submit button. */
  onAssessment?: (assessment: PasswordAssessment | null) => void;
  className?: string;
}

/**
 * Live assessment of a candidate master password.
 *
 * The assessment runs in Rust; the password is sent for evaluation but is never
 * stored, hashed or logged there. Debounced so that typing does not fire a
 * command per keystroke.
 */
export function MasterPasswordStrength({
  password,
  onAssessment,
  className,
}: MasterPasswordStrengthProps) {
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null);

  useEffect(() => {
    if (!password) {
      setAssessment(null);
      onAssessment?.(null);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(() => {
      api
        .assessPassword(password)
        .then((result) => {
          if (cancelled) return;
          setAssessment(result);
          onAssessment?.(result);
        })
        .catch(() => {
          if (cancelled) return;
          setAssessment(null);
          onAssessment?.(null);
        });
    }, 150);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // `onAssessment` is intentionally excluded: callers commonly pass an inline
    // arrow, and including it would re-run the effect on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [password]);

  if (!password || !assessment) {
    return (
      <p className={cn("text-xs text-muted-foreground", className)}>
        Use a long passphrase you have never used anywhere else.
      </p>
    );
  }

  return (
    <div className={cn("space-y-2", className)}>
      <StrengthMeter
        strength={assessment.strength}
        entropyBits={assessment.entropy_bits}
      />

      {assessment.problems.map((problem) => (
        <p
          key={problem}
          className="flex items-start gap-1.5 text-xs text-destructive"
        >
          <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden />
          <span>{problem}</span>
        </p>
      ))}

      {assessment.problems.length === 0 && (
        <p className="flex items-start gap-1.5 text-xs text-strength-strong">
          <Check className="mt-0.5 size-3 shrink-0" aria-hidden />
          <span>Strong enough to protect your vault.</span>
        </p>
      )}

      {assessment.warning && (
        <p className="text-xs text-muted-foreground">{assessment.warning}</p>
      )}
      {assessment.suggestions.slice(0, 2).map((suggestion) => (
        <p key={suggestion} className="text-xs text-muted-foreground">
          {suggestion}
        </p>
      ))}
    </div>
  );
}
