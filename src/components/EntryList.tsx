/**
 * The vault's left pane: a search box and the scrollable list of entries.
 *
 * Purely presentational — the parent owns the query, the filtering and the
 * selection. Entry summaries never contain a password, so rendering them here
 * is safe; anything secret is fetched on demand by the detail pane.
 */

import { Search, Star, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { EntrySummary } from "@/lib/api";
import { displayHost, initials, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";

interface EntryListProps {
  /** Already filtered and ordered by the parent. */
  entries: EntrySummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  query: string;
  onQueryChange: (query: string) => void;
  loading: boolean;
}

export function EntryList({
  entries,
  selectedId,
  onSelect,
  query,
  onQueryChange,
  loading,
}: EntryListProps) {
  const searching = query.trim().length > 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="relative px-3 pb-2">
        <Search
          className="pointer-events-none absolute top-1/2 left-6 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          id="vault-search"
          type="text"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape" && query) onQueryChange("");
          }}
          placeholder="Search vault"
          aria-label="Search vault"
          autoComplete="off"
          spellCheck={false}
          className={cn("pl-9", searching && "pr-9")}
        />
        {searching && (
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="absolute top-1/2 right-4 -translate-y-1/2"
            onClick={() => onQueryChange("")}
            aria-label="Clear search"
          >
            <X className="size-3.5" aria-hidden />
          </Button>
        )}
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-0.5 px-3 pb-3">
          {loading && <PlaceholderRows />}

          {!loading &&
            entries.map((entry) => (
              <EntryRow
                key={entry.id}
                entry={entry}
                selected={entry.id === selectedId}
                onSelect={onSelect}
              />
            ))}

          {!loading && entries.length === 0 && (
            <p className="px-2 py-8 text-center text-sm text-muted-foreground">
              {searching ? "No entries match" : "No entries yet"}
            </p>
          )}
        </div>
      </ScrollArea>

      {!loading && entries.length > 0 && (
        <div className="border-t px-5 py-2 text-xs text-muted-foreground">
          {pluralize(entries.length, "entry", "entries")}
          {searching && " found"}
        </div>
      )}
    </div>
  );
}

function EntryRow({
  entry,
  selected,
  onSelect,
}: {
  entry: EntrySummary;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const firstUrl = entry.urls.find((url) => url.trim().length > 0);
  const secondary = entry.username || (firstUrl ? displayHost(firstUrl) : "");

  return (
    <button
      type="button"
      onClick={() => onSelect(entry.id)}
      aria-current={selected ? "true" : undefined}
      className={cn(
        "flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left outline-none transition-colors",
        "focus-visible:ring-[3px] focus-visible:ring-ring/50",
        selected
          ? "bg-accent text-accent-foreground"
          : "hover:bg-muted/60",
      )}
    >
      <span
        className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-xs font-semibold text-muted-foreground"
        aria-hidden
      >
        {initials(entry.title)}
      </span>

      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate text-sm font-medium">{entry.title}</span>
          {entry.favorite && (
            <>
              <Star
                className="size-3 shrink-0 fill-current text-muted-foreground"
                aria-hidden
              />
              <span className="sr-only">Favourite</span>
            </>
          )}
        </span>
        <span className="block truncate text-xs text-muted-foreground">
          {secondary || (entry.kind === "note" ? "Secure note" : "No username")}
        </span>
      </span>
    </button>
  );
}

/** Placeholder rows while the first load is in flight. */
function PlaceholderRows() {
  return (
    <div aria-hidden>
      {[0, 1, 2, 3, 4].map((row) => (
        <div key={row} className="flex items-center gap-3 px-2 py-2">
          <div className="size-9 shrink-0 animate-pulse rounded-md bg-muted" />
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="h-3 w-2/5 animate-pulse rounded bg-muted" />
            <div className="h-2.5 w-3/5 animate-pulse rounded bg-muted" />
          </div>
        </div>
      ))}
    </div>
  );
}
