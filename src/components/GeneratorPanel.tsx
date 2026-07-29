/**
 * The password / passphrase generator.
 *
 * Used standalone on the generator screen and, with `compact`, embedded in the
 * entry form. Every value comes from `api.generate` — generation happens in Rust
 * with a CSPRNG, never in this webview. Options changes are debounced so that
 * dragging a slider does not fire a command per pixel.
 *
 * The generated value is on screen while it is in state, and copying it uses
 * `api.copyText` (correct here: the value is already visible, and it is not in
 * the vault yet).
 */

import { useCallback, useEffect, useId, useState } from "react";
import { AlertTriangle, Loader2, RefreshCw, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { StrengthMeter } from "@/components/PasswordStrength";
import { CopyTextButton } from "@/components/SecretField";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  api,
  defaultCharacterOptions,
  defaultPassphraseOptions,
  toApiError,
  type Capitalization,
  type CharacterOptions,
  type GeneratedSecret,
  type GeneratorCapabilities,
  type GeneratorOptions,
  type PassphraseOptions,
} from "@/lib/api";
import { pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";

/** Milliseconds to wait after the last option change before regenerating. */
const DEBOUNCE_MS = 120;

const CAPITALIZATION_LABELS: Record<Capitalization, string> = {
  lowercase: "lowercase",
  titlecase: "Titlecase",
  uppercase: "UPPERCASE",
};

interface GeneratorPanelProps {
  capabilities: GeneratorCapabilities;
  /** When provided, an extra primary action hands the value to the caller. */
  onUse?: (value: string) => void;
  /** Tighter spacing and no standalone chrome, for use inside a dialog. */
  compact?: boolean;
  /** Optional external control of the options (used by the presets screen). */
  options?: GeneratorOptions;
  onOptionsChange?: (options: GeneratorOptions) => void;
}

export function GeneratorPanel({
  capabilities,
  onUse,
  compact = false,
  options: controlled,
  onOptionsChange,
}: GeneratorPanelProps) {
  const uid = useId();

  // Both modes keep their own draft, so switching tabs does not lose settings.
  const [charOptions, setCharOptions] = useState<CharacterOptions>(() =>
    controlled?.mode === "characters"
      ? controlled
      : defaultCharacterOptions(capabilities),
  );
  const [phraseOptions, setPhraseOptions] = useState<PassphraseOptions>(() =>
    controlled?.mode === "passphrase"
      ? controlled
      : defaultPassphraseOptions(capabilities),
  );
  const [mode, setMode] = useState<GeneratorOptions["mode"]>(
    controlled?.mode ?? "characters",
  );

  // Adopt options pushed in from outside (e.g. applying a saved preset).
  useEffect(() => {
    if (!controlled) return;
    setMode(controlled.mode);
    if (controlled.mode === "characters") setCharOptions(controlled);
    else setPhraseOptions(controlled);
  }, [controlled]);

  const options: GeneratorOptions =
    mode === "characters" ? charOptions : phraseOptions;

  const emit = useCallback(
    (next: GeneratorOptions) => {
      if (next.mode === "characters") setCharOptions(next);
      else setPhraseOptions(next);
      onOptionsChange?.(next);
    },
    [onOptionsChange],
  );

  const updateChar = (patch: Partial<CharacterOptions>) =>
    emit({ ...charOptions, ...patch });
  const updatePhrase = (patch: Partial<PassphraseOptions>) =>
    emit({ ...phraseOptions, ...patch });

  const changeMode = (next: GeneratorOptions["mode"]) => {
    setMode(next);
    onOptionsChange?.(next === "characters" ? charOptions : phraseOptions);
  };

  // --- generation -----------------------------------------------------------

  const [result, setResult] = useState<GeneratedSecret | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  /** Bumped by the regenerate button to re-run the effect with equal options. */
  const [nonce, setNonce] = useState(0);

  // Serialised so the effect re-runs on any option change without needing the
  // object identity to be stable.
  const optionsKey = JSON.stringify(options);

  useEffect(() => {
    const request = JSON.parse(optionsKey) as GeneratorOptions;
    let cancelled = false;
    setBusy(true);

    const timer = setTimeout(() => {
      api
        .generate(request)
        .then((generated) => {
          if (cancelled) return;
          setResult(generated);
          setError(null);
        })
        .catch((cause) => {
          if (cancelled) return;
          const apiError = toApiError(cause);
          setResult(null);
          // Invalid options are shown inline: the user is mid-adjustment and a
          // toast per keystroke would be noise.
          setError(apiError.message);
          if (apiError.code !== "invalid_options") {
            toast.error("Could not generate a password", {
              description: apiError.message,
            });
          }
        })
        .finally(() => {
          if (!cancelled) setBusy(false);
        });
    }, DEBOUNCE_MS);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [optionsKey, nonce]);

  const regenerate = () => setNonce((n) => n + 1);

  // --- symbol picker --------------------------------------------------------

  const allSymbols = Array.from(capabilities.all_symbols);
  const selectedSymbols = new Set(Array.from(charOptions.symbol_set));

  const toggleSymbol = (symbol: string) => {
    const next = new Set(selectedSymbols);
    if (next.has(symbol)) next.delete(symbol);
    else next.add(symbol);
    // Keep the stored order identical to `all_symbols`.
    updateChar({
      symbol_set: allSymbols.filter((char) => next.has(char)).join(""),
    });
  };

  const poolHint =
    result === null
      ? null
      : options.mode === "characters"
        ? `Each character is drawn from an alphabet of ${result.pool_size}.`
        : `Each word is drawn from a list of ${result.pool_size.toLocaleString()}.`;

  return (
    <div className={cn(compact ? "space-y-4" : "space-y-6")}>
      {/* --- result ---------------------------------------------------- */}
      <div
        className={cn(
          "rounded-xl border bg-card",
          compact ? "p-3" : "p-4 shadow-xs",
        )}
      >
        {error !== null ? (
          <p className="flex items-start gap-2 py-2 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>{error}</span>
          </p>
        ) : (
          <div className={cn(compact ? "space-y-3" : "space-y-4")}>
            <div className="flex items-start gap-2">
              <output
                className={cn(
                  "min-w-0 flex-1 py-1 font-mono break-all transition-opacity",
                  compact ? "text-base" : "text-xl leading-snug",
                  busy && "opacity-50",
                )}
                aria-live="polite"
                aria-label="Generated password"
              >
                {result?.value ?? (
                  <span className="font-sans text-sm text-muted-foreground">
                    Generating…
                  </span>
                )}
              </output>

              <div className="flex shrink-0 items-center gap-1">
                <CopyTextButton value={result?.value ?? ""} label="Password" />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={regenerate}
                  disabled={busy}
                  aria-label="Regenerate password"
                  title="Regenerate"
                >
                  {busy ? (
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                  ) : (
                    <RefreshCw className="size-4" aria-hidden />
                  )}
                </Button>
              </div>
            </div>

            {result !== null && (
              <StrengthMeter
                strength={result.strength}
                entropyBits={result.entropy_bits}
              />
            )}

            {poolHint !== null && (
              <p className="text-xs text-muted-foreground">{poolHint}</p>
            )}

            {onUse && (
              <Button
                type="button"
                className="w-full"
                size="lg"
                disabled={result === null}
                onClick={() => {
                  if (result !== null) onUse(result.value);
                }}
              >
                Use this password
              </Button>
            )}
          </div>
        )}
      </div>

      {/* --- options --------------------------------------------------- */}
      <Tabs
        value={mode}
        onValueChange={(value) =>
          changeMode(value as GeneratorOptions["mode"])
        }
        className={cn(compact ? "gap-4" : "gap-5")}
      >
        <TabsList className="w-full">
          <TabsTrigger value="characters">Password</TabsTrigger>
          <TabsTrigger value="passphrase">Passphrase</TabsTrigger>
        </TabsList>

        {/* Characters ------------------------------------------------- */}
        <TabsContent
          value="characters"
          className={cn(compact ? "space-y-4" : "space-y-6")}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label htmlFor={`${uid}-length`}>Length</Label>
              <span className="font-mono text-sm tabular-nums text-muted-foreground">
                {charOptions.length}
              </span>
            </div>
            <Slider
              id={`${uid}-length`}
              min={capabilities.min_length}
              max={capabilities.max_length}
              step={1}
              value={[charOptions.length]}
              onValueChange={(value) => updateChar({ length: value[0] })}
              aria-label="Password length"
            />
            <div className="flex justify-between text-xs text-muted-foreground tabular-nums">
              <span>{capabilities.min_length}</span>
              <span>{capabilities.max_length}</span>
            </div>
          </div>

          <Separator />

          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">Character types</legend>
            <div className="grid gap-3 sm:grid-cols-2">
              <ClassCheckbox
                id={`${uid}-upper`}
                label="Uppercase"
                hint="A–Z"
                checked={charOptions.uppercase}
                onChange={(checked) => updateChar({ uppercase: checked })}
              />
              <ClassCheckbox
                id={`${uid}-lower`}
                label="Lowercase"
                hint="a–z"
                checked={charOptions.lowercase}
                onChange={(checked) => updateChar({ lowercase: checked })}
              />
              <ClassCheckbox
                id={`${uid}-digits`}
                label="Digits"
                hint="0–9"
                checked={charOptions.digits}
                onChange={(checked) => updateChar({ digits: checked })}
              />
              <ClassCheckbox
                id={`${uid}-symbols`}
                label="Special characters"
                hint={capabilities.default_symbols.slice(0, 6)}
                checked={charOptions.symbols}
                onChange={(checked) => updateChar({ symbols: checked })}
              />
            </div>
          </fieldset>

          {charOptions.symbols && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="space-y-0.5">
                  <p className="text-sm font-medium">Which special characters</p>
                  <p className="text-xs text-muted-foreground">
                    {pluralize(selectedSymbols.size, "character")} of{" "}
                    {allSymbols.length} enabled
                  </p>
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() =>
                      updateChar({ symbol_set: capabilities.all_symbols })
                    }
                  >
                    Select all
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() =>
                      updateChar({ symbol_set: capabilities.default_symbols })
                    }
                  >
                    <RotateCcw className="size-3" aria-hidden />
                    Reset
                  </Button>
                </div>
              </div>

              <div className="grid grid-cols-[repeat(auto-fill,minmax(2rem,1fr))] gap-1.5">
                {allSymbols.map((symbol) => {
                  const on = selectedSymbols.has(symbol);
                  return (
                    <button
                      key={symbol}
                      type="button"
                      onClick={() => toggleSymbol(symbol)}
                      aria-pressed={on}
                      aria-label={`Special character ${symbol}`}
                      title={symbol}
                      className={cn(
                        "grid h-8 place-items-center rounded-md border font-mono text-sm transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
                        on
                          ? "border-primary bg-primary text-primary-foreground"
                          : "border-border bg-background text-muted-foreground hover:bg-muted",
                      )}
                    >
                      {symbol}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <Separator />

          <div className="space-y-4">
            <SwitchRow
              id={`${uid}-ambiguous`}
              label="Exclude ambiguous characters"
              hint={`Leaves out ${capabilities.ambiguous} so the password is safe to read aloud or retype.`}
              checked={charOptions.exclude_ambiguous}
              onChange={(checked) => updateChar({ exclude_ambiguous: checked })}
            />
            <SwitchRow
              id={`${uid}-require`}
              label="Include at least one of each selected type"
              hint="Guarantees every enabled character type actually appears."
              checked={charOptions.require_each_class}
              onChange={(checked) => updateChar({ require_each_class: checked })}
            />
          </div>
        </TabsContent>

        {/* Passphrase ------------------------------------------------- */}
        <TabsContent
          value="passphrase"
          className={cn(compact ? "space-y-4" : "space-y-6")}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label htmlFor={`${uid}-words`}>Words</Label>
              <span className="font-mono text-sm tabular-nums text-muted-foreground">
                {phraseOptions.word_count}
              </span>
            </div>
            <Slider
              id={`${uid}-words`}
              min={capabilities.min_words}
              max={capabilities.max_words}
              step={1}
              value={[phraseOptions.word_count]}
              onValueChange={(value) => updatePhrase({ word_count: value[0] })}
              aria-label="Number of words"
            />
            <p className="text-xs text-muted-foreground">
              EFF wordlist ·{" "}
              {capabilities.wordlist_size.toLocaleString()} words ·{" "}
              {capabilities.bits_per_word.toFixed(1)} bits per word.
            </p>
          </div>

          <Separator />

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor={`${uid}-separator`}>Separator</Label>
              <Input
                id={`${uid}-separator`}
                value={phraseOptions.separator}
                maxLength={8}
                spellCheck={false}
                autoComplete="off"
                placeholder="None"
                className="font-mono"
                onChange={(event) =>
                  updatePhrase({ separator: event.target.value })
                }
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor={`${uid}-caps`}>Capitalization</Label>
              <Select
                value={phraseOptions.capitalization}
                onValueChange={(value) =>
                  updatePhrase({ capitalization: value as Capitalization })
                }
              >
                <SelectTrigger id={`${uid}-caps`} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(
                    Object.keys(CAPITALIZATION_LABELS) as Capitalization[]
                  ).map((value) => (
                    <SelectItem key={value} value={value}>
                      {CAPITALIZATION_LABELS[value]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <Separator />

          <div className="space-y-4">
            <SwitchRow
              id={`${uid}-number`}
              label="Include a number"
              hint="Adds a digit to one of the words."
              checked={phraseOptions.include_number}
              onChange={(checked) => updatePhrase({ include_number: checked })}
            />
            <SwitchRow
              id={`${uid}-symbol`}
              label="Include a special character"
              hint="Adds one symbol, for sites that demand it."
              checked={phraseOptions.include_symbol}
              onChange={(checked) => updatePhrase({ include_symbol: checked })}
            />
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ClassCheckbox({
  id,
  label,
  hint,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-2.5">
      <Checkbox
        id={id}
        checked={checked}
        onCheckedChange={(value) => onChange(value === true)}
      />
      <Label htmlFor={id} className="font-normal">
        {label}
        <span className="font-mono text-xs text-muted-foreground">{hint}</span>
      </Label>
    </div>
  );
}

function SwitchRow({
  id,
  label,
  hint,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="space-y-0.5">
        <Label htmlFor={id} className="font-normal">
          {label}
        </Label>
        <p className="text-xs text-muted-foreground">{hint}</p>
      </div>
      <Switch
        id={id}
        checked={checked}
        onCheckedChange={onChange}
        className="mt-0.5"
      />
    </div>
  );
}
