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
    /// Register unable to assign
    RegisterUnableToAssign,
    /// Stack overflow
    StackOverflow,
    /// Stack underflow
    StackUnderflow,
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
            Error::RegisterUnableToAssign => write!(f, "Register unable to assign"),
            Error::StackOverflow => write!(f, "Stack overflow"),
            Error::StackUnderflow => write!(f, "Stack underflow"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    extern crate alloc;

    use alloc::format;

    #[test]
    fn test_error_print() {
        assert_eq!(
            format!("{}", Error::MemoryAccessDeinied),
            "Memory access denied"
        );
        assert_eq!(
            format!("{}", Error::MemoryInvalidInteraction),
            "Memory invalid interaction"
        );
        assert_eq!(
            format!("{}", Error::RegisterUnableToRead),
            "Register unable to read"
        );
        assert_eq!(
            format!("{}", Error::RegisterUnableToWrite),
            "Register unable to write"
        );
        assert_eq!(
            format!("{}", Error::RegisterUnableToAssign),
            "Register unable to assign"
        );
        assert_eq!(format!("{}", Error::StackOverflow), "Stack overflow");
        assert_eq!(format!("{}", Error::StackUnderflow), "Stack underflow");
    }
}
