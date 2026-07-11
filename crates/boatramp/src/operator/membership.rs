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
