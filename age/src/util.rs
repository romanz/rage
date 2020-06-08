pub(crate) mod read {
    pub(crate) fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
        if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
            return None;
        }

        match base64::decode_config_slice(arg, base64::STANDARD_NO_PAD, buf.as_mut()) {
            Ok(_) => Some(buf),
            Err(_) => None,
        }
    }
}
