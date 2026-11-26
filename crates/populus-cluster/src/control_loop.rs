//! Deterministic delegation capacity controller.

use crate::{
    AssignmentAlgorithm, AssignmentError, AuthorityMode, DEFAULT_MAX_DIRECT_VOTES_PER_MINUTE,
    MATCH_BITS_MAX, select_match_bits,
};
use std::{collections::VecDeque, fmt};

/// Number of recent valid observations retained for rate smoothing.
const RATE_HISTORY_LEN: usize = 5;
const VIEW_COUNT: usize = 3;
const SCALE_UP_PERCENT: u128 = 110;
const SCALE_DOWN_PERCENT: u128 = 70;
const DIRECT_MODE_PERCENT: u128 = 50;
const HARD_OVERLOAD_MULTIPLIER: u128 = 2;
const LOW_LOAD_OBSERVATIONS: usize = 3;

/// Reporting intervals chosen by the controller, in milliseconds.
pub const DELEGATION_REPORT_INTERVALS_MS: [u64; 3] = [5_000, 15_000, 60_000];
/// Default minimum time between non-emergency configuration changes.
pub const DEFAULT_DELEGATION_MIN_DWELL_MS: u64 = 60_000;

/// Delegation parameters currently published by the authority cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationParameters {
    mode: AuthorityMode,
    candidate_count: usize,
    selector: AssignmentAlgorithm,
    match_bits: u16,
    reporting_interval_ms: u64,
}

impl DelegationParameters {
    /// Creates a valid direct- or delegated-mode configuration.
    ///
    /// Direct mode has no candidates or `MatchBits` width. Delegated mode
    /// requires at least one candidate. `MatchBits` widths are only valid for
    /// the `MatchBits` selector.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLoopError::InvalidParameters`] for an inconsistent
    /// mode, candidate count, selector, width, or reporting interval.
    pub fn new(
        mode: AuthorityMode,
        candidate_count: usize,
        selector: AssignmentAlgorithm,
        match_bits: u16,
        reporting_interval_ms: u64,
    ) -> Result<Self, ControlLoopError> {
        let direct_parameters_valid =
            mode != AuthorityMode::Direct || (candidate_count == 0 && match_bits == 0);
        let delegated_parameters_valid = mode != AuthorityMode::Delegated || candidate_count != 0;
        let selector_valid = match selector {
            AssignmentAlgorithm::MatchBits => match_bits <= MATCH_BITS_MAX,
            _ => match_bits == 0,
        };
        if !direct_parameters_valid
            || !delegated_parameters_valid
            || !selector_valid
            || !DELEGATION_REPORT_INTERVALS_MS.contains(&reporting_interval_ms)
        {
            return Err(ControlLoopError::InvalidParameters);
        }
        Ok(Self {
            mode,
            candidate_count,
            selector,
            match_bits,
            reporting_interval_ms,
        })
    }

    /// Returns the active authority mode.
    #[must_use]
    pub const fn mode(self) -> AuthorityMode {
        self.mode
    }

    /// Returns the number of selected ingest candidates.
    #[must_use]
    pub const fn candidate_count(self) -> usize {
        self.candidate_count
    }

    /// Returns the assignment selector.
    #[must_use]
    pub const fn selector(self) -> AssignmentAlgorithm {
        self.selector
    }

    /// Returns the `MatchBits` width, or zero for other selectors.
    #[must_use]
    pub const fn match_bits(self) -> u16 {
        self.match_bits
    }

    /// Returns the current delegated-reporting interval in milliseconds.
    #[must_use]
    pub const fn reporting_interval_ms(self) -> u64 {
        self.reporting_interval_ms
    }
}

/// Tuning for the pure delegation control loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationControlConfig {
    target_votes_per_node_per_minute: u64,
    minimum_dwell_ms: u64,
}

impl Default for DelegationControlConfig {
    fn default() -> Self {
        Self {
            target_votes_per_node_per_minute: DEFAULT_MAX_DIRECT_VOTES_PER_MINUTE,
            minimum_dwell_ms: DEFAULT_DELEGATION_MIN_DWELL_MS,
        }
    }
}

impl DelegationControlConfig {
    /// Creates a controller config with an explicit capacity target and dwell.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLoopError::InvalidConfig`] when the target is zero.
    pub fn new(
        target_votes_per_node_per_minute: u64,
        minimum_dwell_ms: u64,
    ) -> Result<Self, ControlLoopError> {
        if target_votes_per_node_per_minute == 0 {
            return Err(ControlLoopError::InvalidConfig);
        }
        Ok(Self {
            target_votes_per_node_per_minute,
            minimum_dwell_ms,
        })
    }

    /// Returns the target votes per ingest node per minute.
    #[must_use]
    pub const fn target_votes_per_node_per_minute(self) -> u64 {
        self.target_votes_per_node_per_minute
    }

    /// Returns the minimum dwell time between ordinary changes.
    #[must_use]
    pub const fn minimum_dwell_ms(self) -> u64 {
        self.minimum_dwell_ms
    }
}

/// A sampled report from the three independently assigned ingest views.
///
/// Two or more view observations are required to update smoothing history. A
/// single outlying view therefore cannot independently steer the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationRateSample {
    at_ms: u64,
    view_rates_per_minute: [Option<u64>; VIEW_COUNT],
    per_node_rates_per_minute: [Option<u64>; VIEW_COUNT],
    candidate_population: usize,
}

impl DelegationRateSample {
    /// Creates one virtual-time rate sample.
    #[must_use]
    pub const fn new(
        at_ms: u64,
        view_rates_per_minute: [Option<u64>; VIEW_COUNT],
        per_node_rates_per_minute: [Option<u64>; VIEW_COUNT],
        candidate_population: usize,
    ) -> Self {
        Self {
            at_ms,
            view_rates_per_minute,
            per_node_rates_per_minute,
            candidate_population,
        }
    }
}

/// Result of applying one deterministic rate sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationControlDecision {
    parameters: DelegationParameters,
    observed_rate_per_minute: Option<u64>,
    smoothed_rate_per_minute: Option<u64>,
    estimated_per_node_rate_per_minute: Option<u64>,
    hard_overload: bool,
    changed: bool,
}

impl DelegationControlDecision {
    /// Returns the selected delegation parameters.
    #[must_use]
    pub const fn parameters(self) -> DelegationParameters {
        self.parameters
    }

    /// Returns the median of the current available view rates.
    #[must_use]
    pub const fn observed_rate_per_minute(self) -> Option<u64> {
        self.observed_rate_per_minute
    }

    /// Returns the moving average of the recent valid view-rate medians.
    #[must_use]
    pub const fn smoothed_rate_per_minute(self) -> Option<u64> {
        self.smoothed_rate_per_minute
    }

    /// Returns the median observed per-node rate, or its capacity estimate.
    #[must_use]
    pub const fn estimated_per_node_rate_per_minute(self) -> Option<u64> {
        self.estimated_per_node_rate_per_minute
    }

    /// Whether a current view measurement crossed the emergency overload bound.
    #[must_use]
    pub const fn hard_overload(self) -> bool {
        self.hard_overload
    }

    /// Whether this sample changed the published configuration.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.changed
    }
}

/// Stateful, side-effect-free delegation controller.
///
/// Every transition depends only on the current controller state and supplied
/// virtual-time sample. There are no clocks, timers, randomness, or I/O here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationController {
    config: DelegationControlConfig,
    parameters: DelegationParameters,
    last_change_ms: u64,
    last_sample_ms: Option<u64>,
    rate_history: VecDeque<u64>,
    low_load_samples: usize,
}

impl DelegationController {
    /// Starts controlling from an existing parameter set.
    #[must_use]
    pub fn new(
        config: DelegationControlConfig,
        parameters: DelegationParameters,
        now_ms: u64,
    ) -> Self {
        Self {
            config,
            parameters,
            last_change_ms: now_ms,
            last_sample_ms: None,
            rate_history: VecDeque::with_capacity(RATE_HISTORY_LEN),
            low_load_samples: 0,
        }
    }

    /// Returns the currently published parameters.
    #[must_use]
    pub const fn parameters(&self) -> DelegationParameters {
        self.parameters
    }

    /// Applies a report sample and returns the resulting configuration.
    ///
    /// Reports from fewer than two views are treated as missing. With two
    /// reports, their midpoint is used; with three, the median is used. A
    /// hard overload bypasses dwell for scale-up, but never for scale-down.
    ///
    /// # Errors
    ///
    /// Returns [`ControlLoopError::TimeWentBackwards`] for non-monotonic
    /// virtual time or propagates an assignment-sizing error.
    pub fn observe(
        &mut self,
        sample: DelegationRateSample,
    ) -> Result<DelegationControlDecision, ControlLoopError> {
        if self
            .last_sample_ms
            .is_some_and(|last_sample_ms| sample.at_ms < last_sample_ms)
        {
            return Err(ControlLoopError::TimeWentBackwards);
        }
        self.last_sample_ms = Some(sample.at_ms);

        let observed_rate = robust_rate(sample.view_rates_per_minute);
        if let Some(rate) = observed_rate {
            if self.rate_history.len() == RATE_HISTORY_LEN {
                self.rate_history.pop_front();
            }
            self.rate_history.push_back(rate);
        }
        let smoothed_rate = average(&self.rate_history);
        let observed_per_node_rate = robust_rate(sample.per_node_rates_per_minute);
        let estimated_per_node_rate = observed_per_node_rate.or_else(|| {
            smoothed_rate.map(|rate| {
                let candidate_count = self.parameters.candidate_count.max(1);
                let candidate_count = u64::try_from(candidate_count).unwrap_or(u64::MAX);
                let scaled_rate = u128::from(rate) * VIEW_COUNT as u128;
                let estimate = scaled_rate.div_ceil(u128::from(candidate_count));
                u64::try_from(estimate).unwrap_or(u64::MAX)
            })
        });
        let hard_overload = observed_rate.is_some_and(|rate| self.is_hard_overload(rate))
            || observed_per_node_rate.is_some_and(|rate| self.is_hard_overload(rate));
        if let Some(rate) = smoothed_rate {
            let threshold = u128::from(self.config.target_votes_per_node_per_minute)
                * DIRECT_MODE_PERCENT
                / 100;
            if u128::from(rate) < threshold {
                self.low_load_samples = self.low_load_samples.saturating_add(1);
            } else {
                self.low_load_samples = 0;
            }
        }

        let changed = self.update_parameters(
            sample.at_ms,
            sample.candidate_population,
            observed_rate,
            smoothed_rate,
            estimated_per_node_rate,
            hard_overload,
        )?;

        Ok(DelegationControlDecision {
            parameters: self.parameters,
            observed_rate_per_minute: observed_rate,
            smoothed_rate_per_minute: smoothed_rate,
            estimated_per_node_rate_per_minute: estimated_per_node_rate,
            hard_overload,
            changed,
        })
    }

    fn is_hard_overload(&self, rate: u64) -> bool {
        u128::from(rate)
            >= u128::from(self.config.target_votes_per_node_per_minute) * HARD_OVERLOAD_MULTIPLIER
    }

    fn dwell_elapsed(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_change_ms) >= self.config.minimum_dwell_ms
    }

    fn update_parameters(
        &mut self,
        now_ms: u64,
        candidate_population: usize,
        observed_rate: Option<u64>,
        smoothed_rate: Option<u64>,
        estimated_per_node_rate: Option<u64>,
        hard_overload: bool,
    ) -> Result<bool, ControlLoopError> {
        let target = u128::from(self.config.target_votes_per_node_per_minute);
        let current_rate = smoothed_rate.or(observed_rate);
        let mut next = self.parameters;

        match self.parameters.mode {
            AuthorityMode::Direct => {
                let overload = current_rate.is_some_and(|rate| u128::from(rate) >= target)
                    || estimated_per_node_rate.is_some_and(|rate| u128::from(rate) >= target);
                if overload
                    && (hard_overload || self.dwell_elapsed(now_ms))
                    && candidate_population > 0
                {
                    let rate = current_rate.unwrap_or(self.config.target_votes_per_node_per_minute);
                    let count = self.required_candidates(rate, candidate_population);
                    let interval =
                        reporting_interval(rate, self.config.target_votes_per_node_per_minute);
                    next = self.delegated_parameters(count, rate, interval)?;
                }
            }
            AuthorityMode::Delegated => {
                let rate = current_rate.unwrap_or(0);
                let per_node = estimated_per_node_rate.unwrap_or_else(|| {
                    estimate_per_node_rate(rate, self.parameters.candidate_count)
                });
                let high_load = u128::from(per_node) * 100 >= target * SCALE_UP_PERCENT;
                let low_load = u128::from(per_node) * 100 < target * SCALE_DOWN_PERCENT;

                if (hard_overload || high_load)
                    && self.parameters.candidate_count < candidate_population
                {
                    if hard_overload || self.dwell_elapsed(now_ms) {
                        let desired = self.required_candidates(rate, candidate_population).max(
                            self.required_candidates_for_per_node_rate(
                                per_node,
                                candidate_population,
                            ),
                        );
                        let scaled = if hard_overload {
                            desired.max(next_candidate_count(
                                self.parameters.candidate_count,
                                candidate_population,
                            ))
                        } else {
                            desired.max(self.parameters.candidate_count)
                        };
                        next = self.delegated_parameters(
                            scaled,
                            rate,
                            reporting_interval(rate, self.config.target_votes_per_node_per_minute),
                        )?;
                    }
                } else if low_load
                    && self.low_load_samples >= LOW_LOAD_OBSERVATIONS
                    && self.dwell_elapsed(now_ms)
                {
                    let direct_threshold = target * DIRECT_MODE_PERCENT / 100;
                    if self.low_load_samples >= RATE_HISTORY_LEN
                        && u128::from(rate) < direct_threshold
                    {
                        next = DelegationParameters::new(
                            AuthorityMode::Direct,
                            0,
                            self.parameters.selector,
                            0,
                            reporting_interval(rate, self.config.target_votes_per_node_per_minute),
                        )?;
                    } else if self.parameters.candidate_count > 1 {
                        let count = (self.parameters.candidate_count / 2).max(1);
                        next = self.delegated_parameters(
                            count,
                            rate,
                            reporting_interval(rate, self.config.target_votes_per_node_per_minute),
                        )?;
                    }
                } else if self.dwell_elapsed(now_ms) {
                    let interval =
                        reporting_interval(rate, self.config.target_votes_per_node_per_minute);
                    if interval != self.parameters.reporting_interval_ms {
                        next = self.delegated_parameters(
                            self.parameters.candidate_count,
                            rate,
                            interval,
                        )?;
                    }
                }
            }
        }

        if next == self.parameters {
            Ok(false)
        } else {
            self.parameters = next;
            self.last_change_ms = now_ms;
            Ok(true)
        }
    }

    fn required_candidates(&self, rate: u64, candidate_population: usize) -> usize {
        let required = (u128::from(rate) * VIEW_COUNT as u128)
            .div_ceil(u128::from(self.config.target_votes_per_node_per_minute))
            .max(1);
        let cap = u128::try_from(candidate_population).unwrap_or(u128::MAX);
        quantize_candidate_count(required.min(cap), candidate_population)
    }

    fn required_candidates_for_per_node_rate(
        &self,
        per_node_rate: u64,
        candidate_population: usize,
    ) -> usize {
        let required = (u128::try_from(self.parameters.candidate_count).unwrap_or(u128::MAX)
            * u128::from(per_node_rate))
        .div_ceil(u128::from(self.config.target_votes_per_node_per_minute))
        .max(1);
        let cap = u128::try_from(candidate_population).unwrap_or(u128::MAX);
        quantize_candidate_count(required.min(cap), candidate_population)
    }

    fn delegated_parameters(
        &self,
        candidate_count: usize,
        rate: u64,
        interval_ms: u64,
    ) -> Result<DelegationParameters, ControlLoopError> {
        let candidate_count = candidate_count.max(1);
        let match_bits = if self.parameters.selector == AssignmentAlgorithm::MatchBits {
            select_match_bits(
                candidate_count,
                rate.max(1),
                self.config.target_votes_per_node_per_minute,
            )?
        } else {
            0
        };
        DelegationParameters::new(
            AuthorityMode::Delegated,
            candidate_count,
            self.parameters.selector,
            match_bits,
            interval_ms,
        )
    }
}

fn robust_rate(rates: [Option<u64>; VIEW_COUNT]) -> Option<u64> {
    let mut valid = rates.into_iter().flatten().collect::<Vec<_>>();
    if valid.len() < 2 {
        return None;
    }
    valid.sort_unstable();
    if valid.len() == 2 {
        let midpoint = u128::midpoint(u128::from(valid[0]), u128::from(valid[1]));
        return Some(u64::try_from(midpoint).unwrap_or(u64::MAX));
    }
    Some(valid[valid.len() / 2])
}

fn average(rates: &VecDeque<u64>) -> Option<u64> {
    if rates.is_empty() {
        return None;
    }
    let total = rates
        .iter()
        .fold(0_u128, |sum, rate| sum + u128::from(*rate));
    let count = u128::try_from(rates.len()).unwrap_or(u128::MAX);
    Some(u64::try_from(total / count).unwrap_or(u64::MAX))
}

fn estimate_per_node_rate(rate: u64, candidate_count: usize) -> u64 {
    let candidate_count = u64::try_from(candidate_count.max(1)).unwrap_or(u64::MAX);
    let estimate = (u128::from(rate) * VIEW_COUNT as u128).div_ceil(u128::from(candidate_count));
    u64::try_from(estimate).unwrap_or(u64::MAX)
}

fn quantize_candidate_count(required: u128, candidate_population: usize) -> usize {
    if candidate_population == 0 {
        return 0;
    }
    let required = usize::try_from(required).unwrap_or(candidate_population);
    let capped = required.min(candidate_population).max(1);
    let rounded = capped.checked_next_power_of_two().unwrap_or(capped);
    rounded.min(candidate_population)
}

fn next_candidate_count(current: usize, candidate_population: usize) -> usize {
    current
        .saturating_mul(2)
        .max(current.saturating_add(1))
        .min(candidate_population)
}

fn reporting_interval(rate: u64, target: u64) -> u64 {
    let scaled = u128::from(rate) * 100;
    let target = u128::from(target);
    if scaled >= target * SCALE_UP_PERCENT {
        DELEGATION_REPORT_INTERVALS_MS[0]
    } else if scaled >= target * DIRECT_MODE_PERCENT {
        DELEGATION_REPORT_INTERVALS_MS[1]
    } else {
        DELEGATION_REPORT_INTERVALS_MS[2]
    }
}

/// Errors raised while validating or running delegation control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlLoopError {
    /// The capacity target must be nonzero.
    InvalidConfig,
    /// Mode, selector, candidate count, width, or reporting interval disagree.
    InvalidParameters,
    /// A sample's virtual timestamp precedes the previous sample.
    TimeWentBackwards,
    /// `MatchBits` sizing rejected the supplied capacity input.
    Assignment(AssignmentError),
}

impl From<AssignmentError> for ControlLoopError {
    fn from(error: AssignmentError) -> Self {
        Self::Assignment(error)
    }
}

impl fmt::Display for ControlLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("delegation target rate must be nonzero"),
            Self::InvalidParameters => {
                formatter.write_str("delegation mode and assignment parameters are inconsistent")
            }
            Self::TimeWentBackwards => {
                formatter.write_str("delegation control sample time moved backwards")
            }
            Self::Assignment(error) => {
                write!(formatter, "invalid assignment sizing input: {error}")
            }
        }
    }
}

impl std::error::Error for ControlLoopError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn direct(selector: AssignmentAlgorithm) -> DelegationParameters {
        DelegationParameters::new(
            AuthorityMode::Direct,
            0,
            selector,
            0,
            DELEGATION_REPORT_INTERVALS_MS[2],
        )
        .expect("direct parameters are valid")
    }

    fn controller(parameters: DelegationParameters, minimum_dwell_ms: u64) -> DelegationController {
        DelegationController::new(
            DelegationControlConfig::new(1_000, minimum_dwell_ms)
                .expect("positive capacity target"),
            parameters,
            0,
        )
    }

    fn sample(
        at_ms: u64,
        rates: [Option<u64>; 3],
        per_node_rates: [Option<u64>; 3],
        candidates: usize,
    ) -> DelegationRateSample {
        DelegationRateSample::new(at_ms, rates, per_node_rates, candidates)
    }

    #[test]
    fn steady_load_converges_and_stabilizes() {
        let mut controller = controller(direct(AssignmentAlgorithm::MatchBits), 0);
        let mut previous = None;
        let mut changes = 0;
        for minute in 0..20 {
            let decision = controller
                .observe(sample(
                    minute * 60_000,
                    [Some(1_200); 3],
                    [Some(900); 3],
                    64,
                ))
                .expect("steady valid sample");
            changes += usize::from(decision.changed());
            if minute >= 10 {
                if let Some(parameters) = previous {
                    assert_eq!(decision.parameters(), parameters);
                }
                previous = Some(decision.parameters());
            }
        }
        let parameters = controller.parameters();
        assert_eq!(parameters.mode(), AuthorityMode::Delegated);
        assert!(parameters.candidate_count() >= 4);
        assert_eq!(parameters.selector(), AssignmentAlgorithm::MatchBits);
        assert_eq!(parameters.match_bits(), 1);
        assert!(parameters.match_bits() <= MATCH_BITS_MAX);
        assert!(changes <= 2);
    }

    #[test]
    fn hard_overload_bypasses_dwell_and_scales_up_quantized() {
        let mut controller = controller(direct(AssignmentAlgorithm::XorNearest), 600_000);
        let decision = controller
            .observe(sample(1, [Some(2_500); 3], [Some(2_500); 3], 32))
            .expect("hard overload sample");
        assert!(decision.hard_overload());
        assert!(decision.changed());
        assert_eq!(decision.parameters().mode(), AuthorityMode::Delegated);
        assert!(decision.parameters().candidate_count().is_power_of_two());
        assert!(decision.parameters().candidate_count() >= 8);
        assert_eq!(
            decision.parameters().reporting_interval_ms(),
            DELEGATION_REPORT_INTERVALS_MS[0]
        );
    }

    #[test]
    fn measured_per_node_overload_scales_when_total_rate_is_stable() {
        let initial = DelegationParameters::new(
            AuthorityMode::Delegated,
            4,
            AssignmentAlgorithm::XorNearest,
            0,
            DELEGATION_REPORT_INTERVALS_MS[1],
        )
        .expect("delegated parameters are valid");
        let mut controller = controller(initial, 0);
        let decision = controller
            .observe(sample(0, [Some(1_000); 3], [Some(1_500); 3], 64))
            .expect("measured per-node overload sample");
        assert!(decision.changed());
        assert_eq!(decision.parameters().candidate_count(), 8);
        assert!(!decision.hard_overload());
    }

    #[test]
    fn single_missing_view_is_tolerated_but_one_report_is_ignored() {
        let mut controller = controller(direct(AssignmentAlgorithm::XorNearest), 0);
        let ignored = controller
            .observe(sample(0, [Some(10_000), None, None], [None; 3], 32))
            .expect("missing view is valid");
        assert_eq!(ignored.observed_rate_per_minute(), None);
        assert_eq!(ignored.parameters().mode(), AuthorityMode::Direct);

        let accepted = controller
            .observe(sample(1, [Some(1_200), Some(1_300), None], [None; 3], 32))
            .expect("two reports are sufficient");
        assert_eq!(accepted.observed_rate_per_minute(), Some(1_250));
        assert_eq!(accepted.parameters().mode(), AuthorityMode::Delegated);
    }

    #[test]
    fn median_across_views_rejects_malicious_high_and_low_reports() {
        let mut high_controller = controller(direct(AssignmentAlgorithm::XorNearest), 0);
        let high = high_controller
            .observe(sample(
                0,
                [Some(1_100), Some(1_200), Some(u64::MAX)],
                [Some(700), Some(800), Some(u64::MAX)],
                32,
            ))
            .expect("high malicious report is bounded by the median");
        assert_eq!(high.observed_rate_per_minute(), Some(1_200));
        assert!(!high.hard_overload());
        assert_eq!(high.parameters().mode(), AuthorityMode::Delegated);

        let mut low_controller = controller(direct(AssignmentAlgorithm::XorNearest), 0);
        let low = low_controller
            .observe(sample(
                0,
                [Some(900), Some(1_100), Some(0)],
                [Some(700), Some(800), Some(0)],
                32,
            ))
            .expect("low malicious report is bounded by the median");
        assert_eq!(low.observed_rate_per_minute(), Some(900));
        assert_eq!(low.parameters().mode(), AuthorityMode::Direct);
    }

    #[test]
    fn scale_down_requires_low_load_and_dwell() {
        let initial = DelegationParameters::new(
            AuthorityMode::Delegated,
            16,
            AssignmentAlgorithm::XorNearest,
            0,
            DELEGATION_REPORT_INTERVALS_MS[0],
        )
        .expect("delegated parameters are valid");
        let mut controller = controller(initial, 120_000);
        for minute in 0..2 {
            let decision = controller
                .observe(sample(minute * 60_000, [Some(100); 3], [Some(100); 3], 64))
                .expect("low load sample");
            assert_eq!(decision.parameters().candidate_count(), 16);
        }
        let decision = controller
            .observe(sample(120_000, [Some(100); 3], [Some(100); 3], 64))
            .expect("low load after dwell");
        assert!(decision.changed());
        assert_eq!(decision.parameters().mode(), AuthorityMode::Delegated);
        assert_eq!(decision.parameters().candidate_count(), 8);

        let decision = controller
            .observe(sample(180_000, [Some(100); 3], [Some(100); 3], 64))
            .expect("low load continues during the new dwell period");
        assert_eq!(decision.parameters().candidate_count(), 8);

        let decision = controller
            .observe(sample(240_000, [Some(100); 3], [Some(100); 3], 64))
            .expect("sustained collapse returns to direct mode");
        assert_eq!(decision.parameters().mode(), AuthorityMode::Direct);
        assert_eq!(decision.parameters().candidate_count(), 0);
    }

    #[test]
    fn invalid_time_and_candidate_capacity_are_handled() {
        let mut controller = controller(direct(AssignmentAlgorithm::XorNearest), 0);
        controller
            .observe(sample(10, [Some(3_000); 3], [None; 3], 0))
            .expect("no available candidates keeps direct mode");
        assert_eq!(
            controller.observe(sample(9, [Some(3_000); 3], [None; 3], 2)),
            Err(ControlLoopError::TimeWentBackwards)
        );
    }
}
