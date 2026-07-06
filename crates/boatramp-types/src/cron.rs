//! A standard 5-field cron schedule: **parse** + **does it fire at this time**.
//! Used to validate `crons` config (offline) and to drive the background cron
//! scheduler. Fields are `minute hour day-of-month month
//! day-of-week`, each a comma list of `*`, `a`, `a-b`, or `*/n` / `a-b/n`
//! (day-of-week `0` and `7` are both Sunday). Standard "Vixie" day semantics:
//! when both day-of-month and day-of-week are restricted, a tick fires if
//! **either** matches.

/// One parsed field: which values (offset from `lo`) are allowed, and whether
/// it was a bare `*` (unrestricted — matters for the day-of-month/week rule).
struct Field {
    allowed: Vec<bool>,
    lo: u32,
    wildcard: bool,
}

impl Field {
    fn parse(spec: &str, lo: u32, hi: u32) -> Result<Self, String> {
        if spec.is_empty() {
            return Err("empty field".to_string());
        }
        let mut allowed = vec![false; (hi - lo + 1) as usize];
        for part in spec.split(',') {
            let (range, step) = match part.split_once('/') {
                Some((range, step)) => {
                    let step: u32 = step.parse().map_err(|_| format!("bad step in {part:?}"))?;
                    if step == 0 {
                        return Err(format!("zero step in {part:?}"));
                    }
                    (range, step)
                }
                None => (part, 1),
            };
            let (start, end) = if range == "*" {
                (lo, hi)
            } else if let Some((a, b)) = range.split_once('-') {
                let (a, b) = (num(a, lo, hi)?, num(b, lo, hi)?);
                if a > b {
                    return Err(format!("descending range {range:?}"));
                }
                (a, b)
            } else {
                if part.contains('/') {
                    return Err(format!("step on a single value {part:?}"));
                }
                let v = num(range, lo, hi)?;
                (v, v)
            };
            let mut v = start;
            while v <= end {
                allowed[(v - lo) as usize] = true;
                v += step;
            }
        }
        Ok(Self {
            allowed,
            lo,
            wildcard: spec == "*",
        })
    }

    fn matches(&self, value: u32) -> bool {
        value
            .checked_sub(self.lo)
            .and_then(|i| self.allowed.get(i as usize))
            .copied()
            .unwrap_or(false)
    }
}

fn num(s: &str, lo: u32, hi: u32) -> Result<u32, String> {
    let n: u32 = s.parse().map_err(|_| format!("not a number: {s:?}"))?;
    if n < lo || n > hi {
        return Err(format!("{n} out of range {lo}..={hi}"));
    }
    Ok(n)
}

/// A parsed cron schedule.
pub struct CronSchedule {
    minute: Field,
    hour: Field,
    dom: Field,
    month: Field,
    dow: Field,
}

impl CronSchedule {
    /// Parse a 5-field schedule. `Err` describes the first problem.
    pub fn parse(schedule: &str) -> Result<Self, String> {
        let fields: Vec<&str> = schedule.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!(
                "schedule {schedule:?} must have 5 fields (minute hour day-of-month month day-of-week)"
            ));
        }
        let field = |i: usize, lo, hi| {
            Field::parse(fields[i], lo, hi).map_err(|e| format!("field {}: {e}", i + 1))
        };
        Ok(Self {
            minute: field(0, 0, 59)?,
            hour: field(1, 0, 23)?,
            dom: field(2, 1, 31)?,
            month: field(3, 1, 12)?,
            // day-of-week 0..=7, with both 0 and 7 = Sunday.
            dow: field(4, 0, 7)?,
        })
    }

    /// Whether the schedule fires at the given wall-clock fields. `dow` is
    /// `0`=Sunday..`6`=Saturday (the caller's convention); `7` in the spec also
    /// means Sunday.
    pub fn fires_at(&self, minute: u32, hour: u32, dom: u32, month: u32, dow: u32) -> bool {
        let dow_match = self.dow.matches(dow) || (dow == 0 && self.dow.matches(7));
        let dom_match = self.dom.matches(dom);
        // Vixie semantics: if both day fields are restricted, OR them; else AND.
        let day = if !self.dom.wildcard && !self.dow.wildcard {
            dom_match || dow_match
        } else {
            dom_match && dow_match
        };
        self.minute.matches(minute) && self.hour.matches(hour) && self.month.matches(month) && day
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects() {
        assert!(CronSchedule::parse("* * * * *").is_ok());
        assert!(CronSchedule::parse("*/5 0-6 1,15 */2 1-5").is_ok());
        assert!(CronSchedule::parse("* * * *").is_err()); // 4 fields
        assert!(CronSchedule::parse("60 * * * *").is_err()); // minute out of range
        assert!(CronSchedule::parse("5-1 * * * *").is_err()); // descending
        assert!(CronSchedule::parse("*/0 * * * *").is_err()); // zero step
        assert!(CronSchedule::parse("5/2 * * * *").is_err()); // step on single value
    }

    #[test]
    fn every_minute_always_fires() {
        let s = CronSchedule::parse("* * * * *").unwrap();
        assert!(s.fires_at(0, 0, 1, 1, 0));
        assert!(s.fires_at(37, 13, 28, 6, 3));
    }

    #[test]
    fn specific_minute_hour() {
        let s = CronSchedule::parse("30 9 * * *").unwrap();
        assert!(s.fires_at(30, 9, 15, 6, 2));
        assert!(!s.fires_at(31, 9, 15, 6, 2));
        assert!(!s.fires_at(30, 10, 15, 6, 2));
    }

    #[test]
    fn step_and_list() {
        let s = CronSchedule::parse("*/15 * * * *").unwrap();
        for m in [0, 15, 30, 45] {
            assert!(s.fires_at(m, 0, 1, 1, 0), "minute {m}");
        }
        assert!(!s.fires_at(7, 0, 1, 1, 0));
    }

    #[test]
    fn dow_sunday_is_zero_or_seven() {
        let zero = CronSchedule::parse("0 0 * * 0").unwrap();
        let seven = CronSchedule::parse("0 0 * * 7").unwrap();
        assert!(zero.fires_at(0, 0, 3, 8, 0)); // a Sunday
        assert!(seven.fires_at(0, 0, 3, 8, 0));
        assert!(!zero.fires_at(0, 0, 4, 8, 1)); // Monday
    }

    #[test]
    fn dom_and_dow_or_when_both_restricted() {
        // "fire on the 1st OR on a Monday" (Vixie).
        let s = CronSchedule::parse("0 0 1 * 1").unwrap();
        assert!(s.fires_at(0, 0, 1, 6, 3)); // the 1st (any weekday)
        assert!(s.fires_at(0, 0, 9, 6, 1)); // a Monday (any day-of-month)
        assert!(!s.fires_at(0, 0, 9, 6, 3)); // neither
    }
}
