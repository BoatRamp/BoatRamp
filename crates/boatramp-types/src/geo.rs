//! FA-8 geo-edge: **region tagging + nearest-replica selection**. The genuinely
//! new mechanism of the geo stage — region-aware placement + routing that extends
//! the gateway's health/LB replica picker (G5/G6). boatramp does not enumerate
//! regions; a region is an operator-defined tag (`us-east`, `eu-west`) that this
//! module only *compares*. Nearest = same-region-first by default, refined by an
//! optional operator-supplied region-distance table. Pure, backend-free logic, so
//! it is fully unit-testable without live multi-region infrastructure.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A geographic region tag (operator-defined; only compared, never enumerated).
pub type Region = String;

/// The distance used when two regions are unrelated (no table entry) — larger than
/// any sane configured distance, so an unknown pair sorts after every known one.
pub const FAR: u32 = u32::MAX / 2;

/// A function/placement's region preference (FA-8). Absent ⇒ region-agnostic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegionPreference {
    /// The preferred (home) region — the nearest-first anchor for placement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefer: Option<Region>,
    /// Regions this workload may run in at all (empty = anywhere).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Region>,
}

impl RegionPreference {
    /// Whether `region` is allowed (an empty allow-list permits anywhere).
    pub fn allows(&self, region: &str) -> bool {
        self.allow.is_empty() || self.allow.iter().any(|r| r == region)
    }
}

/// An operator-supplied symmetric region-distance table. Same region is always
/// distance `0`; a missing pair defaults to [`FAR`], so unknown regions sort last
/// but are still reachable (never dropped). Default table = binary nearness
/// (same `0`, different `FAR`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RegionMap {
    /// Directed distances; [`distance`](Self::distance) also tries the reverse.
    edges: BTreeMap<String, u32>,
}

impl RegionMap {
    /// Build from `(a, b, distance)` triples (stored both directions).
    pub fn from_edges(edges: impl IntoIterator<Item = (Region, Region, u32)>) -> Self {
        let mut map = BTreeMap::new();
        for (a, b, d) in edges {
            map.insert(Self::edge_key(&a, &b), d);
            map.insert(Self::edge_key(&b, &a), d);
        }
        Self { edges: map }
    }

    /// The distance between two regions (`0` if equal, the table value, else [`FAR`]).
    pub fn distance(&self, a: &str, b: &str) -> u32 {
        if a == b {
            return 0;
        }
        self.edges
            .get(&Self::edge_key(a, b))
            .or_else(|| self.edges.get(&Self::edge_key(b, a)))
            .copied()
            .unwrap_or(FAR)
    }

    /// Whether the table is empty (no operator-supplied edges) — then nearness is
    /// binary (same region `0`, any other [`FAR`]).
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    fn edge_key(a: &str, b: &str) -> String {
        format!("{a}\u{1}{b}")
    }
}

/// A selection candidate: its region (if tagged) and current health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionCandidate {
    /// The candidate's region tag, if any.
    pub region: Option<Region>,
    /// Whether it is currently healthy (unhealthy candidates sort last).
    pub healthy: bool,
}

/// Rank candidates into a preference order (indices into `candidates`) for
/// nearest-replica routing: **healthy first**, then by ascending distance to the
/// `client` region, then original order (a stable tiebreak the caller's LB refines).
/// Unhealthy candidates are kept at the end (fallback), never dropped. With no
/// `client` region, ordering is by health then original order.
pub fn rank_by_nearest(
    candidates: &[RegionCandidate],
    client: Option<&str>,
    map: &RegionMap,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| {
        let c = &candidates[i];
        let health_rank = if c.healthy { 0 } else { 1 };
        let dist = match (client, &c.region) {
            (Some(client), Some(region)) => map.distance(client, region),
            // An untagged candidate, or an unknown client region, is neutral —
            // placed after same-region matches but before strictly-far ones.
            _ => FAR / 2,
        };
        (health_rank, dist, i)
    });
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(region: Option<&str>, healthy: bool) -> RegionCandidate {
        RegionCandidate {
            region: region.map(String::from),
            healthy,
        }
    }

    #[test]
    fn distance_is_symmetric_with_defaults() {
        let map = RegionMap::from_edges([
            ("us-east".into(), "us-west".into(), 1),
            ("us-east".into(), "eu-west".into(), 3),
        ]);
        assert_eq!(map.distance("us-east", "us-east"), 0);
        assert_eq!(map.distance("us-east", "us-west"), 1);
        assert_eq!(map.distance("us-west", "us-east"), 1); // reverse
        assert_eq!(map.distance("us-east", "eu-west"), 3);
        assert_eq!(map.distance("us-east", "ap-south"), FAR); // unknown pair
    }

    #[test]
    fn nearest_prefers_same_region_then_by_distance() {
        // client in us-east; candidates in eu-west, us-east, us-west (all healthy).
        let candidates = [
            cand(Some("eu-west"), true),
            cand(Some("us-east"), true),
            cand(Some("us-west"), true),
        ];
        let map = RegionMap::from_edges([
            ("us-east".into(), "us-west".into(), 1),
            ("us-east".into(), "eu-west".into(), 3),
        ]);
        // us-east (0) → us-west (1) → eu-west (3).
        assert_eq!(
            rank_by_nearest(&candidates, Some("us-east"), &map),
            vec![1, 2, 0]
        );
    }

    #[test]
    fn unhealthy_candidates_sort_last_even_if_nearer() {
        // The same-region replica is unhealthy → a far healthy one wins, but the
        // near unhealthy one remains as a last-resort fallback.
        let candidates = [
            cand(Some("us-east"), false), // near but down
            cand(Some("eu-west"), true),  // far but up
        ];
        let map = RegionMap::from_edges([("us-east".into(), "eu-west".into(), 5)]);
        let order = rank_by_nearest(&candidates, Some("us-east"), &map);
        assert_eq!(order, vec![1, 0]); // healthy-far first, unhealthy-near last
    }

    #[test]
    fn no_client_region_orders_by_health_then_original() {
        let candidates = [
            cand(Some("eu-west"), false),
            cand(Some("us-east"), true),
            cand(None, true),
        ];
        let map = RegionMap::default();
        // No client region → health first (indices 1 and 2 before 0), stable order.
        assert_eq!(rank_by_nearest(&candidates, None, &map), vec![1, 2, 0]);
    }

    #[test]
    fn region_preference_allow_list() {
        let pref = RegionPreference {
            prefer: Some("us-east".into()),
            allow: vec!["us-east".into(), "us-west".into()],
        };
        assert!(pref.allows("us-east"));
        assert!(!pref.allows("eu-west"));
        // Empty allow-list = anywhere.
        assert!(RegionPreference::default().allows("anywhere"));
    }
}
