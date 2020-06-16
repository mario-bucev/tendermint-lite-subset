//! All traits that are necessary and need to be implemented to use the main
//! verification logic in [`super::verifier`] for a light client.

use super::super::hash::Hash;

use lite::error::{Error, Kind};
use std::time::SystemTime;

pub type Height = u64;

/// Header contains meta data about the block -
/// the height, the time, the hash of the validator set
/// that should sign this header, and the hash of the validator
/// set that should sign the next header.
pub trait Header: Clone {
    /// The header's notion of (bft-)time.
    /// We assume it can be converted to SystemTime.
    //type Time: Into<SystemTime>;

    fn height(&self) -> Height;
    fn bft_time(&self) -> SystemTime;
    fn validators_hash(&self) -> Hash;
    fn next_validators_hash(&self) -> Hash;

    /// Hash of the header (ie. the hash of the block).
    fn hash(&self) -> Hash;
}
/*
/// ValidatorSet is the full validator set.
/// It exposes its hash and its total power.
pub trait ValidatorSet/*: Clone*/ {
    /// Hash of the validator set.
    fn hash(&self) -> Hash;

    /// Total voting power of the set
    fn total_power(&self) -> u64;
}
*/
#[derive(Clone)]
pub struct ValidatorSetImpl {
    hash: Hash,
    total_power: u64,
}

impl ValidatorSetImpl {
    /// Hash of the validator set.
    pub fn hash(&self) -> Hash {
        self.hash.clone()
    }

    /// Total voting power of the set
    #[pure]
    pub fn total_power(&self) -> u64 {
        self.total_power
    }
}


/// Commit is used to prove a Header can be trusted.
/// Verifying the Commit requires access to an associated ValidatorSet
/// to determine what voting power signed the commit.
pub trait Commit: Clone {
    // type ValidatorSet: ValidatorSet;

    /// Hash of the header this commit is for.
    fn header_hash(&self) -> Hash;

    /// Compute the voting power of the validators that correctly signed the commit,
    /// according to their voting power in the passed in validator set.
    /// Will return an error in case an invalid signature was included.
    /// TODO/XXX: This cannot detect if a signature from an incorrect validator
    /// is included. That's fine when we're just trying to see if we can skip,
    /// but when actually verifying it means we might accept commits that have sigs from
    /// outside the correct validator set, which is something we expect to be able to detect
    /// (it's not a real issue, but it would indicate a faulty full node).
    ///
    ///
    /// This method corresponds to the (pure) auxiliary function in the spec:
    /// `votingpower_in(signers(h.Commit),h.Header.V)`.
    /// Note this expects the Commit to be able to compute `signers(h.Commit)`,
    /// ie. the identity of the validators that signed it, so they
    /// can be cross-referenced with the given `vals`.
    fn voting_power_in(&self, vals: &ValidatorSetImpl) -> Result<u64, Error>;

    /// Implementers should add addition validation against the given validator set
    /// or other implementation specific validation here.
    /// E.g. validate that the length of the included signatures in the commit match
    /// with the number of validators.
    fn validate(&self, vals: &ValidatorSetImpl) -> Result<(), Error>;
}

/// TrustThreshold defines how much of the total voting power of a known
/// and trusted validator set is sufficient for a commit to be
/// accepted going forward.
pub trait TrustThreshold: Copy + Clone /*+ Debug*/ {
    fn is_enough_power(&self, signed_voting_power: u64, total_voting_power: u64) -> bool;
}

/// TrustThresholdFraction defines what fraction of the total voting power of a known
/// and trusted validator set is sufficient for a commit to be
/// accepted going forward.
/// The [`Default::default()`] returns true, iff at least a third of the trusted
/// voting power signed (in other words at least one honest validator signed).
/// Some clients might require more than +1/3 and can implement their own
/// [`TrustThreshold`] which can be passed into all relevant methods.
#[derive(Copy, Clone)]
pub struct TrustThresholdFraction {
    numerator: u64,
    denominator: u64,
}


impl TrustThresholdFraction {
    #[pure]
    fn threshold_ok(numerator: u64, denominator: u64) -> bool {
        return numerator <= denominator && denominator > 0 && 3 * numerator >= denominator;
    }

    #[pure]
    fn is_ok(r: &Result<TrustThresholdFraction, Error>) -> bool {
        match r {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Instantiate a TrustThresholdFraction if the given denominator and
    /// numerator are valid.
    ///
    /// The parameters are valid iff `1/3 <= numerator/denominator <= 1`.
    /// In any other case we return [`Error::InvalidTrustThreshold`].
    #[ensures="Self::threshold_ok(numerator, denominator) ==> Self::is_ok(&result)"]
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, Error> {
        if Self::threshold_ok(numerator, denominator) {
            return Ok(Self {
                numerator,
                denominator,
            });
        } else {
            Err(Kind::InvalidTrustThreshold)
        }
    }
}

// TODO: should this go in the central place all impls live instead? (currently lite_impl)
impl TrustThreshold for TrustThresholdFraction {
    fn is_enough_power(&self, signed_voting_power: u64, total_voting_power: u64) -> bool {
        signed_voting_power * self.denominator > total_voting_power * self.numerator
    }
}

impl Default for TrustThresholdFraction {
    fn default() -> Self {
        match Self::new(1, 3) {
            Ok(r) => r,
            Err(_) => unreachable!()
        }
    }
}

/// Requester can be used to request [`SignedHeader`]s and [`ValidatorSet`]s for a
/// given height, e.g., by talking to a tendermint fullnode through RPC.
pub trait Requester<C, H>
where
    C: Commit,
    H: Header,
{
    /// Request the [`SignedHeader`] at height h.
    fn signed_header(&self, h: Height) -> Result<SignedHeader<C, H>, Error>;

    /// Request the validator set at height h.
    fn validator_set(&self, h: Height) -> Result<ValidatorSetImpl, Error>;
}


/// TrustedState contains a state trusted by a lite client,
/// including the last header (at height h-1) and the validator set
/// (at height h) to use to verify the next header.
#[derive(Clone)]
pub struct TrustedState<C, H>
where
    H: Header,
    C: Commit,
{
    last_header: SignedHeader<C, H>, // height H-1
    validators: ValidatorSetImpl,     // height H
}

impl<C, H> TrustedState<C, H>
where
    H: Header,
    C: Commit,
{
    /// Initialize the TrustedState with the given signed header and validator set.
    /// Note that if the height of the passed in header is h-1, the passed in validator set
    /// must have been requested for height h.
    pub fn new(last_header: &SignedHeader<C, H>, validators: &ValidatorSetImpl) -> Self {
        Self {
            last_header: last_header.clone(),
            validators: validators.clone(),
        }
    }

    pub fn last_header(&self) -> &SignedHeader<C, H> {
        &self.last_header
    }

    pub fn validators(&self) -> &ValidatorSetImpl {
        &self.validators
    }
}


/// SignedHeader bundles a [`Header`] and a [`Commit`] for convenience.
#[derive(Clone)]
pub struct SignedHeader<C, H>
where
    C: Commit,
    H: Header,
{
    commit: C,
    header: H,
}

impl<C, H> SignedHeader<C, H>
where
    C: Commit,
    H: Header,
{
    pub fn new(commit: C, header: H) -> Self {
        Self { commit, header }
    }

    pub fn commit(&self) -> &C {
        &self.commit
    }

    pub fn header(&self) -> &H {
        &self.header
    }
}