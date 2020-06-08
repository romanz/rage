//! Primitive cryptographic operations used by `age`.

use hmac::{crypto_mac::MacError, Hmac, Mac};
use sha2::Sha256;
use std::io::{self, Write};

/// `HMAC[key](message)`
///
/// HMAC from [RFC 2104] with SHA-256.
///
/// [RFC 2104]: https://tools.ietf.org/html/rfc2104
pub(crate) struct HmacWriter {
    inner: Hmac<Sha256>,
}

impl HmacWriter {
    /// Constructs a new writer to process input data.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        HmacWriter {
            inner: Hmac::new_varkey(&key).expect("key is the correct length"),
        }
    }

    /// Checks if `mac` is correct for the processed input.
    pub(crate) fn verify(self, mac: &[u8]) -> Result<(), MacError> {
        self.inner.verify(mac)
    }
}

impl Write for HmacWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.inner.input(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
