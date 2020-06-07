//! Key structs and serialization.

use secrecy::Secret;

pub(crate) struct FileKey(pub(crate) Secret<[u8; 16]>);
