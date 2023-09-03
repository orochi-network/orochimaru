/// Lib EC-VRF error
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error(pub &'static str, pub &'static str);

impl Error {
    /// Get error code
    pub fn code(&self) -> &'static str {
        self.0
    }

    /// Get error reason
    pub fn reason(&self) -> &'static str {
        self.1
    }

    /// Convert error to JSON string
    pub fn to_json_string(&self) -> String {
        format!(
            "{{\"success\":false,\"message\":\"Code [{}]: {}\"}}",
            self.0, self.1
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Code [{}]: {}", self.0, self.1)
    }
}
