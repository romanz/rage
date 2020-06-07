use age_core::format::AgeStanza;
use std::convert::TryInto;
use x25519_dalek::PublicKey;

use crate::util::read::base64_arg;

pub(super) const X25519_RECIPIENT_TAG: &str = "X25519";

pub(super) const EPK_LEN_BYTES: usize = 32;
pub(super) const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) epk: PublicKey,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != X25519_RECIPIENT_TAG {
            return None;
        }

        let epk = base64_arg(stanza.args.get(0)?, [0; EPK_LEN_BYTES])?;

        Some(RecipientStanza {
            epk: epk.into(),
            encrypted_file_key: stanza.body[..].try_into().ok()?,
        })
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::{RecipientStanza, X25519_RECIPIENT_TAG};

    pub(crate) fn recipient_stanza<'a, W: 'a + Write>(
        r: &'a RecipientStanza,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let encoded_epk = base64::encode_config(r.epk.as_bytes(), base64::STANDARD_NO_PAD);
            let args = &[encoded_epk.as_str()];
            let writer = age_stanza(X25519_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}
