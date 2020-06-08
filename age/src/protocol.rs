//! Encryption and decryption routines for age.

use crate::{
    error::Error,
    format::{Header, RecipientStanza},
};

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt};

/// Decryptor for an age file.
pub struct Decryptor<R> {
    /// The age file's header.
    header: Header,
    /// The age file.
    input: R,
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
                    Ok(Decryptor { input, header })
                } else {
                    Err(Error::InvalidHeader)
                }
            }
            Header::Unknown(_) => Err(Error::UnknownFormat),
        }
    }

    /// Attempts to decrypt the age file.
    ///
    /// `max_work_factor` is the maximum accepted work factor. If `None`, the default
    /// maximum is adjusted to around 16 seconds of work.
    ///
    /// If successful, returns a reader that will provide the plaintext.
    pub fn decrypt_async(self) -> Result<R, Error> {
        panic!("Header: {:?}", self.header);
    }
}
