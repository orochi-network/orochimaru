/// Lib EC-VRF error
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// Unknow error
    UnknowError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::UnknowError => write!(f, "Unknow error"),
        }
    }
}
