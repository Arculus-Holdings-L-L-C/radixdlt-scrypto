use crate::blueprints::consensus_manager::ActiveValidatorSet;
use crate::types::*;

#[derive(ScryptoSbor, ScryptoEvent, PartialEq, Eq)]
pub struct RoundChangeEvent {
    pub round: u64,
}

#[derive(ScryptoSbor, ScryptoEvent, PartialEq, Eq)]
pub struct EpochChangeEvent {
    /// The *new* epoch's number.
    pub epoch: u64,
    /// The *new* epoch's validator set.
    pub validator_set: ActiveValidatorSet,
}
