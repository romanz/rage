use age_core::format::AgeStanza;
use std::convert::TryInto;

use crate::util::read::base64_arg;

pub(super) const SSH_ED25519_RECIPIENT_TAG: &str = "ssh-ed25519";

const TAG_LEN_BYTES: usize = 4;

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) tag: [u8; TAG_LEN_BYTES],
    pub(crate) rest: super::x25519::RecipientStanza,
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SSH_ED25519_RECIPIENT_TAG {
            return None;
        }

        let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;
        let epk = base64_arg(stanza.args.get(1)?, [0; super::x25519::EPK_LEN_BYTES])?.into();

        Some(RecipientStanza {
            tag,
            rest: super::x25519::RecipientStanza {
                epk,
                encrypted_file_key: stanza.body[..].try_into().ok()?,
            },
        })
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::*;

    pub(crate) fn recipient_stanza<'a, W: 'a + Write>(
        r: &'a RecipientStanza,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_tag = base64::encode_config(&r.tag, base64::STANDARD_NO_PAD);
            let encoded_epk = base64::encode_config(r.rest.epk.as_bytes(), base64::STANDARD_NO_PAD);
            let args = &[encoded_tag.as_str(), encoded_epk.as_str()];
            let writer = age_stanza(SSH_ED25519_RECIPIENT_TAG, args, &r.rest.encrypted_file_key);
            writer(w)
        }
    }
}
