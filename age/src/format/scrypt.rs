use age_core::format::AgeStanza;
use std::convert::TryInto;

use crate::util::read::base64_arg;

pub(super) const SCRYPT_RECIPIENT_TAG: &str = "scrypt";

const SALT_LEN: usize = 16;
const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub(crate) struct RecipientStanza {
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) log_n: u8,
    pub(crate) encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl RecipientStanza {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Option<Self> {
        if stanza.tag != SCRYPT_RECIPIENT_TAG {
            return None;
        }

        let salt = base64_arg(stanza.args.get(0)?, [0; SALT_LEN])?;
        let log_n = u8::from_str_radix(stanza.args.get(1)?, 10).ok()?;

        Some(RecipientStanza {
            salt,
            log_n,
            encrypted_file_key: stanza.body[..].try_into().ok()?,
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
            let encoded_salt = base64::encode_config(&r.salt, base64::STANDARD_NO_PAD);
            let args = &[encoded_salt.as_str(), &format!("{}", r.log_n)];
            let writer = age_stanza(SCRYPT_RECIPIENT_TAG, args, &r.encrypted_file_key);
            writer(w)
        }
    }
}
