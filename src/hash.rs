//! Hash functions and their outputs

use ::error::Kind;
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};

/// Output size for the SHA-256 hash function
pub const SHA256_HASH_SIZE: usize = 32;

/// Hash algorithms
#[derive(Copy, Clone)] // Eq, PartialEq cause a crash 
pub enum Algorithm {
    /// SHA-256
    Sha256,
}

/// Hash digests
#[derive(Copy, Clone)] // Eq, PartialEq cause a crash
pub struct Hash([u8; SHA256_HASH_SIZE]);


impl Hash {
    /// Create a new `Hash` with the given algorithm type
    pub fn new(alg: Algorithm, bytes: &[u8]) -> Result<Hash, Kind> {
        match alg {
            Algorithm::Sha256 => {
                if bytes.len() == 32 {
                    let mut h = [0u8; SHA256_HASH_SIZE];
                    h.copy_from_slice(bytes);
                    Ok(Hash(h))
                } else {
                    Err(Kind::Parse)
                }
            }
        }
    }
}

impl PartialEq for Hash {
    // "Fail to parse forall expression" :(
    // #[ensures="result == (forall i: usize :: (0 <= i && i < SHA256_HASH_SIZE) ==> self.0[i] == other.0[i])"]
    fn eq(&self, other: &Self) -> bool {
        let mut i = 0;
        let mut cont_loop = i < SHA256_HASH_SIZE;
        let mut res = true;
        #[invariant="i >= 0"]
        #[invariant="cont_loop ==> i < SHA256_HASH_SIZE"]
        #[invariant="!cont_loop ==> i >= SHA256_HASH_SIZE || !res"]
        while cont_loop {
            assert!(self.0.len() == SHA256_HASH_SIZE);
            assert!(other.0.len() == SHA256_HASH_SIZE);
            if self.0[i] != other.0[i] {
                res = false;
            }
            i += 1;
            assert!(i >= 0);
            cont_loop = i < SHA256_HASH_SIZE && res;
        }
        res
    }
}

impl Eq for Hash {}