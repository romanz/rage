/// From the age spec:
/// ```text
/// Each recipient stanza starts with a line beginning with -> and its type name, followed
/// by zero or more SP-separated arguments. The type name and the arguments are arbitrary
/// strings. Unknown recipient types are ignored. The rest of the recipient stanza is a
/// body of canonical base64 from RFC 4648 without padding wrapped at exactly 64 columns.
/// ```
#[derive(Debug)]
pub struct AgeStanza<'a> {
    pub tag: &'a str,
    pub args: Vec<&'a str>,
    pub body: Vec<u8>,
}

pub mod read {
    use nom::{
        bytes::streaming::{tag, take_while1},
        character::streaming::newline,
        combinator::{map, map_opt, opt, verify},
        multi::separated_nonempty_list,
        sequence::{pair, preceded},
        IResult,
    };

    use super::AgeStanza;

    /// From the age specification:
    /// ```text
    /// ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
    /// ```
    pub fn arbitrary_string(input: &[u8]) -> IResult<&[u8], &str> {
        map(take_while1(|c| c >= 33 && c <= 126), |bytes| {
            std::str::from_utf8(bytes).expect("ASCII is valid UTF-8")
        })(input)
    }

    /// Returns the slice of input up to (but not including) the first LF
    /// character, if that slice is entirely Base64 characters
    ///
    /// # Errors
    ///
    /// - Returns Failure on an empty slice.
    /// - Returns Incomplete(1) if a LF is not found.
    fn take_b64_line(input: &[u8]) -> IResult<&[u8], &[u8]> {
        verify(take_while1(|c| c != b'\n'), |bytes: &[u8]| {
            // STANDARD_NO_PAD only differs from STANDARD during serialization; the base64
            // crate always allows padding during parsing. We require canonical
            // serialization, so we explicitly reject padding characters here.
            base64::decode_config(bytes, base64::STANDARD_NO_PAD).is_ok() && !bytes.contains(&b'=')
        })(input)
    }

    fn wrapped_encoded_data(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        map_opt(separated_nonempty_list(newline, take_b64_line), |chunks| {
            // Enforce that the only chunk allowed to be shorter than 64 characters
            // is the last chunk.
            if chunks.iter().rev().skip(1).any(|s| s.len() != 64)
                || chunks.last().map(|s| s.len() > 64) == Some(true)
            {
                None
            } else {
                let data: Vec<u8> = chunks.into_iter().flatten().cloned().collect();
                base64::decode_config(&data, base64::STANDARD_NO_PAD).ok()
            }
        })(input)
    }

    /// Reads an age stanza.
    pub fn age_stanza<'a>(input: &'a [u8]) -> IResult<&'a [u8], AgeStanza<'a>> {
        map(
            pair(
                separated_nonempty_list(tag(" "), arbitrary_string),
                opt(preceded(newline, wrapped_encoded_data)),
            ),
            |(mut args, body)| {
                let tag = args.remove(0);
                AgeStanza {
                    tag,
                    args,
                    body: body.unwrap_or_default(),
                }
            },
        )(input)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn base64_padding_rejected() {
            assert!(take_b64_line(b"Tm8gcGFkZGluZyE\n").is_ok());
            assert!(take_b64_line(b"Tm8gcGFkZGluZyE=\n").is_err());
        }
    }
}
