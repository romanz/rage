//! Error type.

use std::fmt;
use std::io;

/// The various errors that can be returned during the decryption process.
#[derive(Debug)]
pub enum Error {
    /// The age header was invalid.
    InvalidHeader,
    /// An I/O error occurred during decryption.
    Io(io::Error),
    /// None of the provided keys could be used to decrypt the age file.
    NoMatchingKeys,
    /// An unknown age format, probably from a newer version.
    UnknownFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidHeader => write!(f, "Header is invalid"),
            Error::Io(e) => e.fmt(f),
            Error::NoMatchingKeys => write!(f, "No matching keys found"),
            Error::UnknownFormat => {
                writeln!(f, "Unknown age format.")?;
                write!(f, "Have you tried upgrading to the latest version?")
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(inner) => Some(inner),
            _ => None,
        }
    }
}
