//! Encryption and decryption routines for age.

use age_core::primitives::hkdf;
use secrecy::ExposeSecret;
use std::io::Read;

use crate::{
    error::Error,
    format::{Header, HeaderV1, RecipientStanza},
    keys::FileKey,
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt};

pub mod decryptor;

const HEADER_KEY_LABEL: &[u8] = b"header";
const PAYLOAD_KEY_LABEL: &[u8] = b"payload";

fn v1_payload_key(
    header: &HeaderV1,
    file_key: FileKey,
    nonce: [u8; 16],
) -> Result<[u8; 32], Error> {
    // Verify the MAC
    header.verify_mac(hkdf(&[], HEADER_KEY_LABEL, file_key.0.expose_secret()))?;

    // Return the payload key
    Ok(hkdf(&nonce, PAYLOAD_KEY_LABEL, file_key.0.expose_secret()))
}

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

impl<R: Read> Decryptor<R> {
    /// Attempts to create a decryptor for an age file.
    ///
    /// Returns an error if the input does not contain a valid age file.
    pub fn new(mut input: R) -> Result<Self, Error> {
        let header = Header::read(&mut input)?;

        match &header {
            Header::V1(v1_header) => {
                let mut nonce = [0; 16];
                input.read_exact(&mut nonce)?;

                // Enforce structural requirements on the v1 header.
                let any_scrypt = v1_header.recipients.iter().any(|r| {
                    if let RecipientStanza::Scrypt(_) = r {
                        true
                    } else {
                        false
                    }
                });

                if any_scrypt && v1_header.recipients.len() == 1 {
                    Ok(decryptor::PassphraseDecryptor::new(input, header, nonce).into())
                } else {
                    Err(Error::InvalidHeader)
                }
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
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
