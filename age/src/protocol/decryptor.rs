//! Decryptors for age.

use secrecy::SecretString;

use super::v1_payload_key;
use crate::{
    error::Error,
    format::{Header, RecipientStanza},
    keys::FileKey,
    primitives::stream::{Stream, StreamReader},
};

#[cfg(feature = "async")]
use futures::io::AsyncRead;

struct BaseDecryptor<R> {
    /// The age file.
    input: R,
    /// The age file's header.
    header: Header,
    /// The age file's AEAD nonce
    nonce: [u8; 16],
}

impl<R> BaseDecryptor<R> {
    fn obtain_payload_key<F>(&mut self, filter: F) -> Result<[u8; 32], Error>
    where
        F: FnMut(&RecipientStanza) -> Option<Result<FileKey, Error>>,
    {
        match &self.header {
            Header::V1(header) => header
                .recipients
                .iter()
                .find_map(filter)
                .unwrap_or(Err(Error::NoMatchingKeys))
                .and_then(|file_key| v1_payload_key(header, file_key, self.nonce)),
            Header::Unknown(_) => unreachable!(),
        }
    }
}

/// Decryptor for an age file encrypted with a passphrase.
pub struct PassphraseDecryptor<R>(BaseDecryptor<R>);

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> PassphraseDecryptor<R> {
    pub(super) fn new_async(input: R, header: Header, nonce: [u8; 16]) -> Self {
        PassphraseDecryptor(BaseDecryptor {
            input,
            header,
            nonce,
        })
    }

    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async(
        mut self,
        _passphrase: &SecretString,
        _max_work_factor: Option<u8>,
    ) -> Result<StreamReader<R>, Error> {
        self.0
            .obtain_payload_key(|r| {
                panic!("RecipientStanza: {:?}", r);
            })
            .map(|payload_key| Stream::decrypt_async(&payload_key, self.0.input))
    }
}
