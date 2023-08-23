/// State Machine error
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// Memory access denied
    MemoryAccessDeinied,
    /// Memory invalid interaction
    MemoryInvalidInteraction,
    /// Register unable to read
    RegisterUnableToRead,
    /// Register unable to write
    RegisterUnableToWrite,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::MemoryAccessDeinied => write!(f, "Memory access denied"),
            Error::MemoryInvalidInteraction => write!(f, "Memory invalid interaction"),
            Error::RegisterUnableToRead => write!(f, "Register unable to read"),
            Error::RegisterUnableToWrite => write!(f, "Register unable to write"),
        }
    }
}
