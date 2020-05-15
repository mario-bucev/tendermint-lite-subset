// use anomaly::{BoxError, Context};
// use thiserror::Error;

/// Error type
// pub type Error = BoxError;

// TODO: This may need adaptations
pub type Error = Kind;

/// Kinds of errors
// Derive: Clone. Eq, PartialEq Debug, Error
pub enum Kind {
    /// Cryptographic operation failed
    Crypto,

    /// Malformatted or otherwise invalid cryptographic key
    InvalidKey,

    /// Input/output error
    Io,

    /// Length incorrect or too long
    Length,

    /// Parse error
    Parse,

    /// Network protocol-related errors
    Protocol,

    /// Value out-of-range
    OutOfRange,

    /// Signature invalid
    SignatureInvalid,
}
/*
impl Kind {
    /// Add additional context.
    pub fn context(self, source: impl Into<BoxError>) -> Context<Kind> {
        Context::new(self, Some(source.into()))
    }
}
*/