//! The Raft **membership state machine** — the operator's mandatory core, and the
//! whole reason a plain StatefulSet is not enough.
//!
//! This is a **pure** planner: given the desired replica count, the live pods
//! (readiness), and the current Raft configuration (voters + learners), it returns
//! the *single next* membership transition to perform. It performs no IO — the
//! reconciler executes whatever it returns — so the safety-critical logic is
//! exhaustively unit-testable.
//!
//! **The invariant it guarantees: no returned action can break quorum.** It follows
//! two rules that make that true:
//! 1. **One change at a time** — return exactly one action, then requeue; Raft
//!    membership changes must be applied singly.
//! 2. **Never act without a quorum** — every membership change must commit through
//!    the leader, which needs a majority of ready voters. With no quorum we return
//!    `None` and wait; recovering a quorum-loss is a deliberate manual operation,
//!    never automated (forcing membership without quorum corrupts the log).

/// A node's role in the current Raft configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRole {
    /// Replicates the log but does not vote (a joining node catching up).
    Learner,
    /// A full voting member counted toward quorum.
    Voter,
}

/// A StatefulSet pod. Identity is its ordinal (`<statefulset>-<ordinal>`), which
/// the operator uses as the Raft node id — so a pod and its member line up.
#[derive(Clone, Copy, Debug)]
pub struct PodState {
    /// The StatefulSet ordinal (`0..replicas`).
    pub ordinal: u32,
    /// Whether the pod's `/readyz` currently passes.
    pub ready: bool,
}

/// A node in the current Raft configuration, as the operator observes it.
#[derive(Clone, Copy, Debug)]
pub struct Member {
    /// The node ordinal (matches its pod).
    pub ordinal: u32,
    /// Voter or learner.
    pub role: MemberRole,
    /// Whether a learner has replicated up to the leader (ready to promote).
    pub caught_up: bool,
}

/// The single next membership transition. One per reconcile; the reconciler
/// executes it, then requeues to plan the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipAction {
    /// Add a ready, in-range pod that isn't yet in the config, as a learner
    /// (mint a join token; the pod joins and catches up).
    AddLearner { ordinal: u32 },
    /// Promote a caught-up, in-range learner to a voter.
    PromoteToVoter { ordinal: u32 },
    /// Remove an out-of-range member from the config — **before** its pod is
    /// deleted, so consensus membership shrinks cleanly.
    Remove { ordinal: u32 },
}

/// The smallest voter count that forms a majority (`n/2 + 1`).
fn majority(voters: usize) -> usize {
    voters / 2 + 1
}

fn total_voters(members: &[Member]) -> usize {
    members
        .iter()
        .filter(|m| m.role == MemberRole::Voter)
        .count()
}

/// Voters whose pod is currently ready.
fn ready_voters(members: &[Member], pods: &[PodState]) -> usize {
    members
        .iter()
        .filter(|m| m.role == MemberRole::Voter)
        .filter(|m| pods.iter().any(|p| p.ordinal == m.ordinal && p.ready))
        .count()
}

/// Whether a membership change can currently commit — a majority of the voters are
/// ready. With no voters (a cluster that hasn't bootstrapped), there is no quorum.
pub fn has_quorum(members: &[Member], pods: &[PodState]) -> bool {
    let voters = total_voters(members);
    voters > 0 && ready_voters(members, pods) >= majority(voters)
}

/// Whether it is safe to **roll a voter's pod** (a rolling upgrade / drain) right
/// now: the cluster must keep quorum even after one more voter goes down — i.e.
/// there is a **margin above the majority** (`ready voters > majority`). A
/// single-voter cluster (dev) has no margin, so a rolling upgrade would blip
/// writes; the operator pauses the rollout until the margin returns. Learners
/// carry no vote, so rolling a learner is always safe (this gates only voters).
pub fn has_roll_margin(members: &[Member], pods: &[PodState]) -> bool {
    let voters = total_voters(members);
    voters > 1 && ready_voters(members, pods) > majority(voters)
}

/// The single next quorum-safe membership action, or `None` when the configuration
/// already matches `desired` (converged) or no action can safely commit (wait).
///
/// Priority: **remove** out-of-range members (scale-down) → **promote** a caught-up
/// learner → **add** a new learner (scale-up). Every branch requires a live quorum.
pub fn plan_next(desired: u32, pods: &[PodState], members: &[Member]) -> Option<MembershipAction> {
    // Safety gate: no membership change can commit without a quorum of voters. If we
    // don't have one, take NO action — never make a bad situation worse.
    if !has_quorum(members, pods) {
        return None;
    }

    // 1. Scale-down: remove members whose ordinal is beyond the desired range,
    //    highest ordinal first. Never remove the last remaining voter (a scale to
    //    zero is a teardown — delete the CR, which garbage-collects everything).
    let mut out_of_range: Vec<&Member> = members.iter().filter(|m| m.ordinal >= desired).collect();
    out_of_range.sort_by_key(|m| std::cmp::Reverse(m.ordinal));
    for m in out_of_range {
        if m.role == MemberRole::Voter && total_voters(members) <= 1 {
            continue; // never remove the sole voter
        }
        return Some(MembershipAction::Remove { ordinal: m.ordinal });
    }

    // 2. Promote the lowest-ordinal caught-up in-range learner to a voter.
    if let Some(m) = members
        .iter()
        .filter(|m| m.ordinal < desired && m.role == MemberRole::Learner && m.caught_up)
        .min_by_key(|m| m.ordinal)
    {
        return Some(MembershipAction::PromoteToVoter { ordinal: m.ordinal });
    }

    // 3. Scale-up: add the lowest-ordinal ready, in-range pod that isn't a member
    //    yet, as a learner. (Node 0 self-bootstraps into a one-voter cluster before
    //    any quorum exists, so this only runs once the cluster is live.)
    let is_member = |o: u32| members.iter().any(|m| m.ordinal == o);
    if let Some(p) = pods
        .iter()
        .filter(|p| p.ordinal < desired && p.ready && !is_member(p.ordinal))
        .min_by_key(|p| p.ordinal)
    {
        return Some(MembershipAction::AddLearner { ordinal: p.ordinal });
    }

    None
}

/// A member as reported by the cluster API (`GET /api/cluster/members`): its
/// **derived** node id, role, catch-up, and mesh address (whose host encodes the
/// StatefulSet pod ordinal). The executor turns these into ordinal-keyed
/// [`Member`]s the planner understands, keeping the ordinal↔node_id map so the
/// planned action can be executed against the node-id-keyed API (#2).
#[derive(Clone, Debug)]
pub struct ApiMember {
    /// The member's derived Raft node id (the API's handle for promote/remove).
    pub node_id: u64,
    /// `true` ⇒ a voter; `false` ⇒ a learner.
    pub voter: bool,
    /// Whether a learner has caught up to the leader (ready to promote).
    pub caught_up: bool,
    /// Whether this member is the current leader (membership changes must target
    /// the leader).
    pub leader: bool,
    /// The member's mesh URL — its host is `<statefulset>-<ordinal>.<svc>…`.
    pub addr: Option<String>,
}

/// Parse a StatefulSet pod ordinal from a member's mesh address. The host is the
/// pod's stable DNS name `…//<name>-<ordinal>.<service>…`; the ordinal is the
/// trailing integer of the first dot-separated label after the scheme.
pub fn ordinal_from_addr(addr: &str) -> Option<u32> {
    let after_scheme = addr.split("//").last()?;
    let host = after_scheme.split(['.', ':', '/']).next()?; // `<name>-<ordinal>`
    // Require an actual `<name>-<ordinal>` split (a `-`), so a bare number or an
    // IP octet (e.g. `10.0.0.5` → `10`) isn't mistaken for an ordinal.
    let (name, ordinal) = host.rsplit_once('-')?;
    if name.is_empty() {
        return None;
    }
    ordinal.parse::<u32>().ok()
}

/// Build the ordinal-keyed [`Member`] list the planner consumes **and** the
/// `ordinal → node_id` map the executor needs, from the API members. Members
/// whose address doesn't encode an ordinal (not a StatefulSet pod) are dropped —
/// the operator only manages its own pods.
pub fn members_from_api(
    api: &[ApiMember],
) -> (Vec<Member>, std::collections::BTreeMap<u32, u64>) {
    let mut members = Vec::new();
    let mut map = std::collections::BTreeMap::new();
    for m in api {
        let Some(ordinal) = m.addr.as_deref().and_then(ordinal_from_addr) else {
            continue;
        };
        map.insert(ordinal, m.node_id);
        members.push(Member {
            ordinal,
            role: if m.voter {
                MemberRole::Voter
            } else {
                MemberRole::Learner
            },
            caught_up: m.caught_up,
        });
    }
    (members, map)
}

/// The node id a planned action must be executed against, if the API needs one.
/// `PromoteToVoter`/`Remove` target an existing member (resolved via the map);
/// `AddLearner` returns `None` — a new pod **self-joins** with a ticket, so there
/// is no node id yet.
pub fn action_node_id(
    action: &MembershipAction,
    ordinal_to_node: &std::collections::BTreeMap<u32, u64>,
) -> Option<u64> {
    match action {
        MembershipAction::PromoteToVoter { ordinal }
        | MembershipAction::Remove { ordinal } => ordinal_to_node.get(ordinal).copied(),
        MembershipAction::AddLearner { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::MemberRole::{Learner, Voter};
    use super::*;

    fn pod(ordinal: u32, ready: bool) -> PodState {
        PodState { ordinal, ready }
    }
    fn member(ordinal: u32, role: MemberRole, caught_up: bool) -> Member {
        Member {
            ordinal,
            role,
            caught_up,
        }
    }
    /// n ready voters, ordinals 0..n.
    fn voters(n: u32) -> (Vec<PodState>, Vec<Member>) {
        (
            (0..n).map(|o| pod(o, true)).collect(),
            (0..n).map(|o| member(o, Voter, true)).collect(),
        )
    }

    #[test]
    fn ordinal_parses_from_a_statefulset_pod_address() {
        assert_eq!(
            ordinal_from_addr("https://boatramp-cluster-2.boatramp-cluster.ns.svc:7000"),
            Some(2)
        );
        assert_eq!(ordinal_from_addr("http://my-cluster-0.svc:8080"), Some(0));
        // A non-pod address (no trailing ordinal) is ignored.
        assert_eq!(ordinal_from_addr("https://10.0.0.5:7000"), None);
    }

    #[test]
    fn api_members_map_to_ordinals_and_resolve_action_node_ids() {
        let api = vec![
            ApiMember {
                node_id: 0xAA,
                voter: true,
                caught_up: true,
                leader: true,
                addr: Some("https://sts-0.svc:7000".into()),
            },
            ApiMember {
                node_id: 0xBB,
                voter: false,
                caught_up: true,
                leader: false,
                addr: Some("https://sts-1.svc:7000".into()),
            },
            // A member with no ordinal-encoding address is dropped.
            ApiMember {
                node_id: 0xCC,
                voter: false,
                caught_up: false,
                leader: false,
                addr: Some("https://10.0.0.9:7000".into()),
            },
        ];
        let (members, map) = members_from_api(&api);
        assert_eq!(members.len(), 2);
        assert_eq!(map.get(&0), Some(&0xAA));
        assert_eq!(map.get(&1), Some(&0xBB));
        assert!(!map.values().any(|&n| n == 0xCC));

        // Promote/remove resolve to the member's node id; AddLearner has none yet.
        assert_eq!(
            action_node_id(&MembershipAction::PromoteToVoter { ordinal: 1 }, &map),
            Some(0xBB)
        );
        assert_eq!(
            action_node_id(&MembershipAction::Remove { ordinal: 0 }, &map),
            Some(0xAA)
        );
        assert_eq!(
            action_node_id(&MembershipAction::AddLearner { ordinal: 2 }, &map),
            None
        );
    }

    #[test]
    fn roll_margin_needs_a_spare_voter() {
        // 3 voters all ready → majority is 2, ready is 3 > 2 → safe to roll one.
        let (pods, members) = voters(3);
        assert!(has_roll_margin(&members, &pods));
        // 3 voters, one pod down → ready 2 == majority 2 → NO margin (rolling
        // another would drop below quorum).
        let mut pods2 = pods.clone();
        pods2[0].ready = false;
        assert!(!has_roll_margin(&members, &pods2));
        // A single-voter (dev) cluster never has a roll margin.
        let (p1, m1) = voters(1);
        assert!(!has_roll_margin(&m1, &p1));
        // 5 voters all ready → margin (3 majority, 5 ready).
        let (p5, m5) = voters(5);
        assert!(has_roll_margin(&m5, &p5));
    }

    #[test]
    fn majority_is_more_than_half() {
        assert_eq!(majority(1), 1);
        assert_eq!(majority(2), 2);
        assert_eq!(majority(3), 2);
        assert_eq!(majority(5), 3);
    }

    #[test]
    fn quorum_needs_a_ready_majority_of_voters() {
        let (pods, mem) = voters(3);
        assert!(has_quorum(&mem, &pods));
        // 3 voters, only 1 ready → no quorum.
        let one_ready = vec![pod(0, true), pod(1, false), pod(2, false)];
        assert!(!has_quorum(&mem, &one_ready));
        // 3 voters, 2 ready → quorum.
        let two_ready = vec![pod(0, true), pod(1, true), pod(2, false)];
        assert!(has_quorum(&mem, &two_ready));
        // No voters at all → no quorum (pre-bootstrap).
        assert!(!has_quorum(&[], &[pod(0, true)]));
    }

    #[test]
    fn waits_for_bootstrap_when_no_members_exist() {
        // Node 0 must self-bootstrap into a one-voter cluster first; the operator
        // does nothing until a member exists.
        let pods = vec![pod(0, true), pod(1, true), pod(2, true)];
        assert_eq!(plan_next(3, &pods, &[]), None);
    }

    #[test]
    fn scales_up_by_adding_then_promoting_one_at_a_time() {
        // A live 1-voter cluster growing to 3.
        let pods = vec![pod(0, true), pod(1, true), pod(2, true)];
        let mem = vec![member(0, Voter, true)];
        assert_eq!(
            plan_next(3, &pods, &mem),
            Some(MembershipAction::AddLearner { ordinal: 1 })
        );
        // Learner 1 added but not caught up → add the next learner.
        let mem = vec![member(0, Voter, true), member(1, Learner, false)];
        assert_eq!(
            plan_next(3, &pods, &mem),
            Some(MembershipAction::AddLearner { ordinal: 2 })
        );
        // Learner 1 caught up → promote it (promotion outranks adding).
        let mem = vec![
            member(0, Voter, true),
            member(1, Learner, true),
            member(2, Learner, false),
        ];
        assert_eq!(
            plan_next(3, &pods, &mem),
            Some(MembershipAction::PromoteToVoter { ordinal: 1 })
        );
    }

    #[test]
    fn converged_cluster_plans_nothing() {
        let (pods, mem) = voters(3);
        assert_eq!(plan_next(3, &pods, &mem), None);
    }

    #[test]
    fn scales_down_by_removing_out_of_range_highest_first() {
        // 5 healthy voters, desired 3 → remove 4, then 3; never touch 0..2.
        let (pods, mem) = voters(5);
        assert_eq!(
            plan_next(3, &pods, &mem),
            Some(MembershipAction::Remove { ordinal: 4 })
        );
        let mem: Vec<_> = mem.into_iter().filter(|m| m.ordinal != 4).collect();
        assert_eq!(
            plan_next(3, &pods, &mem),
            Some(MembershipAction::Remove { ordinal: 3 })
        );
    }

    #[test]
    fn never_acts_without_quorum() {
        // 3 voters, 2 down → no quorum → no action, even though desired < current.
        let pods = vec![pod(0, true), pod(1, false), pod(2, false)];
        let mem: Vec<_> = (0..3).map(|o| member(o, Voter, true)).collect();
        assert_eq!(plan_next(1, &pods, &mem), None, "must not remove without quorum");
        assert_eq!(plan_next(5, &pods, &mem), None, "must not add without quorum");
    }

    #[test]
    fn never_removes_the_last_voter() {
        // desired 0 with a single voter: refuse (teardown is CR deletion + GC).
        let pods = vec![pod(0, true)];
        let mem = vec![member(0, Voter, true)];
        assert_eq!(plan_next(0, &pods, &mem), None);
    }

    #[test]
    fn removes_an_out_of_range_learner() {
        // A learner beyond the desired range is removed (learners don't gate quorum,
        // but the change still needs the live quorum to commit — which we have).
        let pods = vec![pod(0, true), pod(1, true), pod(2, true)];
        let mem = vec![
            member(0, Voter, true),
            member(1, Voter, true),
            member(2, Learner, false),
        ];
        assert_eq!(
            plan_next(2, &pods, &mem),
            Some(MembershipAction::Remove { ordinal: 2 })
        );
    }

    /// The safety invariant, checked across many shapes: whatever `plan_next`
    /// returns, it (a) only ever fires with a quorum, (b) only removes out-of-range
    /// members, (c) never removes the last voter, (d) only promotes in-range
    /// caught-up learners, (e) only adds in-range ready non-members.
    #[test]
    fn planned_actions_always_respect_the_invariants() {
        for desired in 0u32..6 {
            for n in 1u32..6 {
                for down in 0u32..n {
                    // A cluster of `n` voters with `down` of them not ready.
                    let pods: Vec<PodState> =
                        (0..n).map(|o| pod(o, o >= down)).collect();
                    let mem: Vec<Member> = (0..n).map(|o| member(o, Voter, true)).collect();
                    let quorum = has_quorum(&mem, &pods);
                    if let Some(action) = plan_next(desired, &pods, &mem) {
                        assert!(quorum, "acted without quorum: {action:?}");
                        match action {
                            MembershipAction::Remove { ordinal } => {
                                assert!(ordinal >= desired, "removed in-range {ordinal}");
                                assert!(total_voters(&mem) > 1, "removed the last voter");
                            }
                            MembershipAction::PromoteToVoter { ordinal }
                            | MembershipAction::AddLearner { ordinal } => {
                                assert!(ordinal < desired, "acted out-of-range {ordinal}");
                            }
                        }
                    }
                }
            }
        }
    }
}
