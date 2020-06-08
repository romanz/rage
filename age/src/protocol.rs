//! Encryption and decryption routines for age.

use crate::{
    error::Error,
    format::{Header, RecipientStanza},
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt};

pub mod decryptor;

/// Decryptor for an age file.
pub enum Decryptor<R> {
    /// Decryption with a passphrase.
    Passphrase(decryptor::PassphraseDecryptor<R>),
}

impl<R> From<decryptor::PassphraseDecryptor<R>> for Decryptor<R> {
    fn from(decryptor: decryptor::PassphraseDecryptor<R>) -> Self {
        Decryptor::Passphrase(decryptor)
    }
}

#[cfg(feature = "async")]
impl<R: AsyncRead + Unpin> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub async fn new_async(mut input: R) -> Result<Self, Error> {
        let header = Header::read_async(&mut input).await?;

        match &header {
            Header::V1(v1_header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce).await?;

                // Enforce structural requirements on the v1 header.
                let any_scrypt = v1_header.recipients.iter().any(|r| {
                    if let RecipientStanza::Scrypt(_) = r {
                        true
                    } else {
                        false
                    }
                });

                if any_scrypt && v1_header.recipients.len() == 1 {
                    Ok(decryptor::PassphraseDecryptor::new_async(input, header, nonce).into())
                } else {
                    Err(Error::InvalidHeader)
                }
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }
}
