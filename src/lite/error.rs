//! All error types tied to the light client.

use super::super::hash::Hash;

use std::time::SystemTime;

/// The main error type verification methods will return.
/// See [`Kind`] for the different kind of errors.
pub type Error = Kind;

/// All error kinds related to the light client.
// #[derive(Clone)]
pub enum Kind {
    /// The provided header expired.
    Expired { at: SystemTime, now: SystemTime },

    /// Trusted header is from the future.
    DurationOutOfRange,

    /// Header height smaller than expected.
    NonIncreasingHeight { got: u64, expected: u64 },

    /// Header time is in the past compared to already trusted header.
    NonIncreasingTime,

    /// Invalid validator hash.
    InvalidValidatorSet {
        // header_val_hash: Hash,
        // val_hash: Hash,
    },

    /// Invalid next validator hash.
    InvalidNextValidatorSet {
        // header_next_val_hash: Hash,
        // next_val_hash: Hash,
    },

    /// Commit is not for the header we expected.
    InvalidCommitValue {
        // header_hash: Hash,
        // commit_hash: Hash,
    },

    /// Signed power does not account for +2/3 of total voting power.
    InvalidCommit { total: u64, signed: u64 },

    /// This means the trust threshold (default +1/3) is not met.
    InsufficientVotingPower {
        total: u64,
        signed: u64,
    },

    /// This is returned if an invalid TrustThreshold is created.
    InvalidTrustThreshold,

    /// Use the [`Kind::context`] method to wrap the underlying error of
    /// the implementation, if any.
    RequestFailed,

    /// Use the [`Kind::context`] method to wrap the underlying error of
    /// the implementation, if any.
    ImplementationSpecific,
}