/// Lib EC-VRF error
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// Unknow error
    UnknowError,
    /// Out of range
    OutOfRange,
    /// Unable to convert bytes to scalar
    UnableToConvertBytesToScalar,
    /// Retries exceeded
    RetriesExceeded,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnknowError => write!(f, "Unknow error"),
            Error::OutOfRange => write!(f, "Out of range"),
            Error::UnableToConvertBytesToScalar => write!(f, "Unable to convert bytes to scalar"),
            Error::RetriesExceeded => write!(f, "Retries exceeded"),
        }
    }
}
