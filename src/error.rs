/// Error type
pub type Error = Kind;

/// Kinds of errors
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