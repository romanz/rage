//! The age file format.

use std::io;

use crate::primitives::HmacWriter;

#[cfg(feature = "async")]
use futures::io::{AsyncRead, AsyncReadExt};

pub(crate) mod scrypt;

const AGE_MAGIC: &[u8] = b"age-encryption.org/";
const V1_MAGIC: &[u8] = b"v1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const MAC_TAG: &[u8] = b"---";

#[derive(Debug)]
pub(crate) enum RecipientStanza {
    Scrypt(scrypt::RecipientStanza),
    Plugin,
}

impl From<scrypt::RecipientStanza> for RecipientStanza {
    fn from(stanza: scrypt::RecipientStanza) -> Self {
        RecipientStanza::Scrypt(stanza)
    }
}

pub struct HeaderV1 {
    pub(crate) recipients: Vec<RecipientStanza>,
    pub(crate) mac: [u8; 32],
}

impl HeaderV1 {
    pub(crate) fn verify_mac(&self, mac_key: [u8; 32]) -> Result<(), hmac::crypto_mac::MacError> {
        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_v1_minus_mac(self), &mut mac)
            .expect("can serialize Header into HmacWriter");
        mac.verify(&self.mac)
    }
}

impl Header {
    #[cfg(feature = "async")]
    pub(crate) async fn read_async<R: AsyncRead + Unpin>(mut input: R) -> io::Result<Self> {
        let mut data = vec![];
        loop {
            match read::header(&data) {
                Ok((_, header)) => break Ok(header),
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                    // Read the needed additional bytes. We need to be careful how the
                    // parser is constructed, because if we read more than we need, the
                    // remainder of the input will be truncated.
                    let m = data.len();
                    data.resize(m + n, 0);
                    input.read_exact(&mut data[m..m + n]).await?;
                }
                Err(_) => {
                    break Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
                }
            }
        }
    }
}

pub(crate) enum Header {
    V1(HeaderV1),
    Unknown(String),
}

mod read {
    use age_core::format::read::{age_stanza, arbitrary_string};
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take},
        character::streaming::newline,
        combinator::{map, map_opt},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::base64_arg;

    fn recipient_stanza(input: &[u8]) -> IResult<&[u8], RecipientStanza> {
        preceded(
            tag(RECIPIENT_TAG),
            map_opt(age_stanza, |stanza| match stanza.tag {
                scrypt::SCRYPT_RECIPIENT_TAG => {
                    scrypt::RecipientStanza::from_stanza(stanza).map(RecipientStanza::Scrypt)
                }
                _ => Some(RecipientStanza::Plugin),
            }),
        )(input)
    }

    fn header_v1(input: &[u8]) -> IResult<&[u8], HeaderV1> {
        preceded(
            pair(tag(V1_MAGIC), newline),
            map(
                pair(
                    terminated(separated_nonempty_list(newline, recipient_stanza), newline),
                    preceded(
                        pair(tag(MAC_TAG), tag(b" ")),
                        terminated(
                            map_opt(take(43usize), |tag| base64_arg(&tag, [0; 32])),
                            newline,
                        ),
                    ),
                ),
                |(recipients, mac)| HeaderV1 { recipients, mac },
            ),
        )(input)
    }

    /// From the age specification:
    /// ```text
    /// The first line of the header is age-encryption.org/ followed by an arbitrary
    /// version string. ... We describe version v1, other versions can change anything
    /// after the first line.
    /// ```
    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        preceded(
            tag(AGE_MAGIC),
            alt((
                map(header_v1, Header::V1),
                map(terminated(arbitrary_string, newline), |s| {
                    Header::Unknown(s.to_string())
                }),
            )),
        )(input)
    }
}

mod write {
    use cookie_factory::{
        combinator::{slice, string},
        multi::separated_list,
        sequence::tuple,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::*;

    fn recipient_stanza<'a, W: 'a + Write>(r: &'a RecipientStanza) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientStanza::Scrypt(r) => scrypt::write::recipient_stanza(r)(out),
                RecipientStanza::Plugin => Ok(out),
            }
        }
    }

    pub(super) fn header_v1_minus_mac<'a, W: 'a + Write>(
        h: &'a HeaderV1,
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(AGE_MAGIC),
            slice(V1_MAGIC),
            string("\n"),
            separated_list(
                string("\n"),
                h.recipients.iter().map(move |r| recipient_stanza(r)),
            ),
            string("\n"),
            slice(MAC_TAG),
        ))
    }
}
