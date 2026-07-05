//! errors.

// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataShieldError {
    InsufficientAnonymity,
    InvalidEpsilon,
}

impl core::fmt::Display for DataShieldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientAnonymity => write!(f, "insufficient anonymity"),
            Self::InvalidEpsilon => write!(f, "invalid epsilon"),
        }
    }
}
