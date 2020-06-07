use age_core::format::AgeStanza;

use crate::util::read::base64_arg;

pub(super) const SSH_RSA_RECIPIENT_TAG: &str = "ssh-rsa";

const TAG_LEN_BYTES: usize = 4;

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) tag: [u8; TAG_LEN_BYTES],
    pub(crate) encrypted_file_key: Vec<u8>,
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SSH_RSA_RECIPIENT_TAG {
            return None;
        }

        let tag = base64_arg(stanza.args.get(0)?, [0; TAG_LEN_BYTES])?;

        Some(RecipientStanza {
            tag,
            encrypted_file_key: stanza.body,
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
            let args = &[encoded_tag.as_str()];
            let writer = age_stanza(SSH_RSA_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}
