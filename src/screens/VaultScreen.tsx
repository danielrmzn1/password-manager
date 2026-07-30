/**
 * The vault: a master/detail view over the entry list.
 *
 * The list is loaded once per change (mount, `refreshToken`, save, delete) and
 * filtered in the webview — entry summaries carry no secret material, so local
 * filtering is safe and makes search feel instant. Every secret shown in the
 * detail pane is fetched separately, on demand.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Plus } from "lucide-react";
import { toast } from "sonner";

import { EntryDetail } from "@/components/EntryDetail";
import { EntryForm } from "@/components/EntryForm";
import { EntryList } from "@/components/EntryList";
import { Button } from "@/components/ui/button";
import {
  api,
  toApiError,
  type EntrySummary,
  type GeneratorCapabilities,
} from "@/lib/api";
import { displayHost } from "@/lib/format";

interface VaultScreenProps {
  capabilities: GeneratorCapabilities;
  /** Bumped by the app when a sync merge or an import changed the vault. */
  refreshToken: number;
}

export function VaultScreen({ capabilities, refreshToken }: VaultScreenProps) {
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  /** `undefined` puts the form in create mode. */
  const [editingId, setEditingId] = useState<string | undefined>(undefined);

  const load = useCallback(async (preferId?: string) => {
    try {
      const loaded = await api.listEntries();
      setEntries(loaded);
      setSelectedId((current) => {
        const wanted = preferId ?? current;
        return wanted && loaded.some((entry) => entry.id === wanted)
          ? wanted
          : null;
      });
    } catch (error) {
      toast.error("Could not load the vault", {
        description: toApiError(error).message,
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshToken]);

  const visible = useMemo(() => {
    const ordered = [...entries].sort(compareEntries);
    const needle = query.trim().toLowerCase();
    if (!needle) return ordered;
    return ordered.filter((entry) => matches(entry, needle));
  }, [entries, query]);

  const openCreate = useCallback(() => {
    setEditingId(undefined);
    setFormOpen(true);
  }, []);

  const openEdit = useCallback(() => {
    if (!selectedId) return;
    setEditingId(selectedId);
    setFormOpen(true);
  }, [selectedId]);

  const handleSaved = useCallback(
    (id: string) => {
      void load(id);
    },
    [load],
  );

  const handleDeleted = useCallback(() => {
    setSelectedId(null);
    void load();
  }, [load]);

  const handleChanged = useCallback(() => {
    void load();
  }, [load]);

  const vaultIsEmpty = !loading && entries.length === 0;

  return (
    <div className="flex h-full">
      <aside className="flex w-88 shrink-0 flex-col border-r">
        <div className="flex items-center justify-between gap-2 px-4 py-3">
          <h1 className="text-sm font-semibold">Vault</h1>
          <Button type="button" onClick={openCreate}>
            <Plus className="size-4" aria-hidden />
            New entry
          </Button>
        </div>

        <EntryList
          entries={visible}
          selectedId={selectedId}
          onSelect={setSelectedId}
          query={query}
          onQueryChange={setQuery}
          loading={loading}
        />
      </aside>

      <section className="min-w-0 flex-1 overflow-hidden">
        {selectedId ? (
          <EntryDetail
            key={`${selectedId}:${refreshToken}`}
            entryId={selectedId}
            onEdit={openEdit}
            onDeleted={handleDeleted}
            onChanged={handleChanged}
          />
        ) : vaultIsEmpty ? (
          <EmptyVault onCreate={openCreate} />
        ) : (
          <NothingSelected />
        )}
      </section>

      <EntryForm
        capabilities={capabilities}
        entryId={editingId}
        open={formOpen}
        onOpenChange={setFormOpen}
        onSaved={handleSaved}
      />
    </div>
  );
}

/** Favourites first, then alphabetical — a stable, predictable order. */
function compareEntries(a: EntrySummary, b: EntrySummary): number {
  if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
  return a.title.localeCompare(b.title, undefined, { sensitivity: "base" });
}

/** Case-insensitive match over the non-secret parts of a summary. */
function matches(entry: EntrySummary, needle: string): boolean {
  const haystack = [
    entry.title,
    entry.username,
    ...entry.tags,
    ...entry.urls.map(displayHost),
  ];
  return haystack.some((value) => value.toLowerCase().includes(needle));
}

function EmptyVault({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="grid h-full place-items-center p-8">
      <div className="max-w-sm space-y-4 text-center">
        <div className="mx-auto grid size-12 place-items-center rounded-xl bg-muted">
          <KeyRound className="size-5 text-muted-foreground" aria-hidden />
        </div>
        <div className="space-y-1.5">
          <h2 className="text-base font-semibold">Your vault is empty</h2>
          <p className="text-sm text-muted-foreground">
            Add your first login or secure note. Everything is encrypted on this
            device before it is written to disk or synced.
          </p>
        </div>
        <Button type="button" onClick={onCreate}>
          <Plus className="size-4" aria-hidden />
          New entry
        </Button>
      </div>
    </div>
  );
}

function NothingSelected() {
  return (
    <div className="grid h-full place-items-center p-8">
      <p className="max-w-xs text-center text-sm text-muted-foreground">
        Select an entry to see its details.
      </p>
    </div>
  );
}
