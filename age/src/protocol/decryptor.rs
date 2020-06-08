//! Decryptors for age.

use secrecy::SecretString;

use crate::{error::Error, format::Header};

#[cfg(feature = "async")]
use futures::io::AsyncRead;

/// Decryptor for an age file encrypted with a passphrase.
pub struct PassphraseDecryptor<R> {
    /// The age file.
    input: R,
    /// The age file's header.
    header: Header,
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PassphraseDecryptor<R> {
    pub(super) fn new_async(input: R, header: Header, _nonce: [u8; 16]) -> Self {
        PassphraseDecryptor { input, header }
    }

    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async(
        self,
        _passphrase: &SecretString,
        _max_work_factor: Option<u8>,
    ) -> Result<R, Error> {
        match &self.header {
            Header::V1(header) => header
                .recipients
                .iter()
                .find_map(|r| {
                    panic!("RecipientStanza: {:?}", r);
                })
                .unwrap_or(Err(Error::NoMatchingKeys))
                .map(|()| self.input),
            Header::Unknown(_) => unreachable!(),
        }
    }
}
