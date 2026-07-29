//! Deterministic per-entry merge of two vault payloads.
//!
//! Pure function, no I/O — the correctness of multi-device sync rests almost
//! entirely on this file, so it is kept isolated and heavily tested.
//!
//! The rules are specified in `docs/sync-protocol.md`. In short: per-entry
//! last-write-wins by `updated_at`, with tombstones that beat any edit older
//! than the deletion, and local winning exact ties so the operation is
//! deterministic.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::vault::model::{now_ms, Tombstone, VaultEntry, VaultPayload};

/// What a merge did, for reporting in the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct MergeOutcome {
    pub added_from_remote: usize,
    pub updated_from_remote: usize,
    pub kept_local: usize,
    pub deleted_by_remote: usize,
}

impl MergeOutcome {
    pub fn is_noop(&self) -> bool {
        *self == Self::default()
    }
}

/// Merge `remote` into `local`, returning the merged payload.
///
/// Commutative in effect (running it on either device converges to the same
/// content) except for exact `updated_at` ties, which resolve in favour of
/// whichever side is passed as `local`.
pub fn merge(local: &VaultPayload, remote: &VaultPayload) -> (VaultPayload, MergeOutcome) {
    let mut outcome = MergeOutcome::default();

    // 1. Tombstones: union by id, latest deletion wins.
    let mut tombstones: BTreeMap<Uuid, i64> = BTreeMap::new();
    for t in local.tombstones.iter().chain(remote.tombstones.iter()) {
        tombstones
            .entry(t.id)
            .and_modify(|at| *at = (*at).max(t.deleted_at))
            .or_insert(t.deleted_at);
    }

    // 2. Entries: per-id last-write-wins, then tombstone arbitration.
    let mut local_by_id: BTreeMap<Uuid, &VaultEntry> =
        local.entries.iter().map(|e| (e.id, e)).collect();
    let remote_by_id: BTreeMap<Uuid, &VaultEntry> =
        remote.entries.iter().map(|e| (e.id, e)).collect();

    let mut ids: Vec<Uuid> = local_by_id.keys().copied().collect();
    for id in remote_by_id.keys() {
        if !local_by_id.contains_key(id) {
            ids.push(*id);
        }
    }

    let mut entries: Vec<VaultEntry> = Vec::with_capacity(ids.len());
    for id in ids {
        let l = local_by_id.remove(&id);
        let r = remote_by_id.get(&id).copied();

        let (winner, winner_is_remote) = match (l, r) {
            (Some(l), Some(r)) => {
                // Local wins an exact tie, which keeps the result deterministic.
                if r.updated_at > l.updated_at {
                    (r, true)
                } else {
                    (l, false)
                }
            }
            (Some(l), None) => (l, false),
            (None, Some(r)) => (r, true),
            (None, None) => unreachable!("id came from one of the two maps"),
        };

        // A deletion beats any edit that is not strictly newer than it.
        if let Some(&deleted_at) = tombstones.get(&id) {
            if deleted_at >= winner.updated_at {
                if l.is_some() {
                    outcome.deleted_by_remote += 1;
                }
                continue;
            }
            // Otherwise the entry was edited after the deletion: the edit wins
            // and the tombstone must be dropped, or the entry would be deleted
            // again on the next merge.
            tombstones.remove(&id);
        }

        match (l.is_some(), winner_is_remote) {
            (false, true) => outcome.added_from_remote += 1,
            (true, true) => outcome.updated_from_remote += 1,
            (true, false) => {
                if r.is_some() {
                    outcome.kept_local += 1;
                }
            }
            (false, false) => {}
        }

        entries.push(winner.clone());
    }

    // Stable ordering so two devices produce byte-comparable payloads.
    entries.sort_by_key(|e| e.id);

    // 3. Presets: union by id, local wins a conflict.
    let mut presets = local.generator_presets.clone();
    for preset in &remote.generator_presets {
        if !presets.iter().any(|p| p.id == preset.id) {
            presets.push(preset.clone());
        }
    }
    presets.sort_by_key(|p| p.id);

    // 4. Unknown top-level fields: union, local wins. This is what lets data
    //    written by a newer client survive a round trip through an older one.
    let mut extra = remote.extra.clone();
    for (key, value) in &local.extra {
        extra.insert(key.clone(), value.clone());
    }

    let mut merged = VaultPayload {
        schema: local.schema.max(remote.schema),
        entries,
        tombstones: tombstones
            .into_iter()
            .map(|(id, deleted_at)| Tombstone { id, deleted_at })
            .collect(),
        generator_presets: presets,
        extra,
    };

    // 5. Bound tombstone growth.
    merged.gc_tombstones(now_ms());

    (merged, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::EntryKind;

    /// Timestamps must sit inside the tombstone retention window, otherwise the
    /// garbage collector legitimately discards them mid-test. Offsets are
    /// therefore taken from "now" rather than from the unix epoch.
    fn t(offset_ms: i64) -> i64 {
        now_ms() - 60_000 + offset_ms
    }

    fn entry(id: Uuid, title: &str, updated_at: i64) -> VaultEntry {
        let mut e = VaultEntry::new(EntryKind::Login);
        e.id = id;
        e.title = title.into();
        e.updated_at = updated_at;
        e.created_at = updated_at;
        e
    }

    fn payload(entries: Vec<VaultEntry>, tombstones: Vec<Tombstone>) -> VaultPayload {
        VaultPayload {
            entries,
            tombstones,
            ..Default::default()
        }
    }

    fn titles(p: &VaultPayload) -> Vec<String> {
        let mut t: Vec<String> = p.entries.iter().map(|e| e.title.clone()).collect();
        t.sort();
        t
    }

    #[test]
    fn disjoint_additions_both_survive() {
        // The case whole-file last-write-wins would get wrong.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let local = payload(vec![entry(a, "local-only", t(100))], vec![]);
        let remote = payload(vec![entry(b, "remote-only", t(100))], vec![]);

        let (merged, outcome) = merge(&local, &remote);
        assert_eq!(titles(&merged), vec!["local-only", "remote-only"]);
        assert_eq!(outcome.added_from_remote, 1);
    }

    #[test]
    fn newer_side_wins_per_entry() {
        let id = Uuid::new_v4();

        let (merged, outcome) = merge(
            &payload(vec![entry(id, "older-local", t(100))], vec![]),
            &payload(vec![entry(id, "newer-remote", t(200))], vec![]),
        );
        assert_eq!(titles(&merged), vec!["newer-remote"]);
        assert_eq!(outcome.updated_from_remote, 1);

        let (merged, outcome) = merge(
            &payload(vec![entry(id, "newer-local", t(300))], vec![]),
            &payload(vec![entry(id, "older-remote", t(200))], vec![]),
        );
        assert_eq!(titles(&merged), vec!["newer-local"]);
        assert_eq!(outcome.kept_local, 1);
    }

    #[test]
    fn exact_tie_keeps_local_deterministically() {
        let id = Uuid::new_v4();
        let (merged, _) = merge(
            &payload(vec![entry(id, "local", t(500))], vec![]),
            &payload(vec![entry(id, "remote", t(500))], vec![]),
        );
        assert_eq!(titles(&merged), vec!["local"]);
    }

    #[test]
    fn remote_deletion_removes_a_local_entry() {
        let id = Uuid::new_v4();
        let (merged, outcome) = merge(
            &payload(vec![entry(id, "doomed", t(100))], vec![]),
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: t(200),
                }],
            ),
        );
        assert!(merged.entries.is_empty());
        assert_eq!(outcome.deleted_by_remote, 1);
        assert!(merged.is_deleted(id), "tombstone must be retained");
    }

    #[test]
    fn local_deletion_is_not_undone_by_a_stale_remote_copy() {
        // The resurrection bug: remote still has the entry, local deleted it.
        let id = Uuid::new_v4();
        let (merged, _) = merge(
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: t(300),
                }],
            ),
            &payload(vec![entry(id, "stale-remote-copy", t(100))], vec![]),
        );
        assert!(merged.entries.is_empty(), "deleted entry was resurrected");
        assert!(merged.is_deleted(id));
    }

    #[test]
    fn an_edit_after_a_deletion_resurrects_the_entry() {
        let id = Uuid::new_v4();
        let (merged, _) = merge(
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: t(100),
                }],
            ),
            &payload(vec![entry(id, "edited-later", t(200))], vec![]),
        );
        assert_eq!(titles(&merged), vec!["edited-later"]);
        assert!(
            !merged.is_deleted(id),
            "the tombstone must be dropped, or the next merge deletes it again"
        );
    }

    /// A resurrection must be stable: merging the result again must not delete
    /// the entry. This is what the tombstone removal above is for.
    #[test]
    fn resurrection_is_stable_across_a_second_merge() {
        let id = Uuid::new_v4();
        let (first, _) = merge(
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: t(100),
                }],
            ),
            &payload(vec![entry(id, "edited-later", t(200))], vec![]),
        );
        let (second, _) = merge(&first, &first.clone());
        assert_eq!(titles(&second), vec!["edited-later"]);
    }

    #[test]
    fn deletion_exactly_at_the_edit_timestamp_deletes() {
        // `>=` in favour of the deletion: a delete and an edit stamped the same
        // millisecond resolve to deleted, which is the safer direction.
        let id = Uuid::new_v4();
        let (merged, _) = merge(
            &payload(vec![entry(id, "edited", t(100))], vec![]),
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: t(100),
                }],
            ),
        );
        assert!(merged.entries.is_empty());
    }

    #[test]
    fn tombstones_are_unioned_keeping_the_later_deletion() {
        let id = Uuid::new_v4();
        // Bound rather than inlined: `t()` re-reads the clock on each call.
        let earlier = t(100);
        let later = t(400);
        let (merged, _) = merge(
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: earlier,
                }],
            ),
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: later,
                }],
            ),
        );
        assert_eq!(merged.tombstones.len(), 1);
        assert_eq!(merged.tombstones[0].deleted_at, later);
    }

    #[test]
    fn expired_tombstones_are_collected() {
        let id = Uuid::new_v4();
        let ancient = now_ms() - crate::vault::model::TOMBSTONE_RETENTION_MS - 1;
        let (merged, _) = merge(
            &payload(
                vec![],
                vec![Tombstone {
                    id,
                    deleted_at: ancient,
                }],
            ),
            &VaultPayload::default(),
        );
        assert!(merged.tombstones.is_empty());
    }

    #[test]
    fn merge_is_idempotent() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let local = payload(
            vec![entry(a, "one", t(100))],
            vec![Tombstone {
                id: b,
                deleted_at: t(150),
            }],
        );
        let remote = payload(vec![entry(b, "two", t(100))], vec![]);

        let (once, _) = merge(&local, &remote);
        let (twice, outcome) = merge(&once, &remote);
        assert_eq!(titles(&once), titles(&twice));
        assert_eq!(once.tombstones.len(), twice.tombstones.len());
        assert!(outcome.is_noop() || outcome.deleted_by_remote == 0);
    }

    /// Both devices must converge on the same content regardless of which one
    /// runs the merge — the property that makes retry-on-conflict safe.
    #[test]
    fn both_directions_converge_on_the_same_content() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let local = payload(
            vec![
                entry(a, "local-newer", t(300)),
                entry(c, "local-only", t(100)),
            ],
            vec![],
        );
        let remote = payload(
            vec![
                entry(a, "remote-older", t(200)),
                entry(b, "remote-only", t(100)),
            ],
            vec![],
        );

        let (from_local, _) = merge(&local, &remote);
        let (from_remote, _) = merge(&remote, &local);
        assert_eq!(titles(&from_local), titles(&from_remote));
        assert_eq!(
            from_local.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            from_remote.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            "entry ordering must be stable across devices"
        );
    }

    #[test]
    fn secret_values_travel_with_the_winning_entry() {
        let id = Uuid::new_v4();
        let mut newer = entry(id, "site", t(200));
        newer.password = "the-new-password".into();
        let mut older = entry(id, "site", t(100));
        older.password = "the-old-password".into();

        let (merged, _) = merge(&payload(vec![older], vec![]), &payload(vec![newer], vec![]));
        assert_eq!(merged.entries[0].password, "the-new-password");
    }

    #[test]
    fn presets_are_unioned_with_local_winning() {
        use crate::generator::{GeneratorOptions, GeneratorPreset};

        let shared = Uuid::new_v4();
        let remote_only = Uuid::new_v4();

        let mut local = VaultPayload::default();
        local.generator_presets.push(GeneratorPreset {
            id: shared,
            name: "local-name".into(),
            options: GeneratorOptions::default(),
            created_at: 1,
        });

        let mut remote = VaultPayload::default();
        remote.generator_presets.push(GeneratorPreset {
            id: shared,
            name: "remote-name".into(),
            options: GeneratorOptions::default(),
            created_at: 1,
        });
        remote.generator_presets.push(GeneratorPreset {
            id: remote_only,
            name: "remote-only".into(),
            options: GeneratorOptions::default(),
            created_at: 1,
        });

        let (merged, _) = merge(&local, &remote);
        assert_eq!(merged.generator_presets.len(), 2);
        let shared_name = &merged
            .generator_presets
            .iter()
            .find(|p| p.id == shared)
            .unwrap()
            .name;
        assert_eq!(shared_name, "local-name");
    }

    #[test]
    fn unknown_fields_from_both_sides_are_preserved() {
        let mut local = VaultPayload::default();
        local.extra.insert("local_key".into(), serde_json::json!(1));
        local
            .extra
            .insert("shared".into(), serde_json::json!("local"));

        let mut remote = VaultPayload::default();
        remote
            .extra
            .insert("remote_key".into(), serde_json::json!(2));
        remote
            .extra
            .insert("shared".into(), serde_json::json!("remote"));

        let (merged, _) = merge(&local, &remote);
        assert_eq!(merged.extra["local_key"], serde_json::json!(1));
        assert_eq!(merged.extra["remote_key"], serde_json::json!(2));
        assert_eq!(merged.extra["shared"], serde_json::json!("local"));
    }

    #[test]
    fn empty_inputs_are_handled() {
        let (merged, outcome) = merge(&VaultPayload::default(), &VaultPayload::default());
        assert!(merged.entries.is_empty());
        assert!(outcome.is_noop());
    }

    #[test]
    fn merging_an_empty_remote_keeps_everything_local() {
        let a = Uuid::new_v4();
        let local = payload(vec![entry(a, "keep", t(100))], vec![]);
        let (merged, outcome) = merge(&local, &VaultPayload::default());
        assert_eq!(titles(&merged), vec!["keep"]);
        assert!(outcome.is_noop());
    }

    #[test]
    fn schema_takes_the_higher_of_the_two() {
        // A payload written before the schema field existed deserializes to 0;
        // merging it with a current one must not downgrade the result.
        let legacy = VaultPayload {
            schema: 0,
            ..Default::default()
        };
        let current = VaultPayload {
            schema: 1,
            ..Default::default()
        };
        assert_eq!(merge(&legacy, &current).0.schema, 1);
        assert_eq!(merge(&current, &legacy).0.schema, 1);
    }
}
