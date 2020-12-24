use std::fs::File;
use std::io;

use crate::{x25519, Identity};

/// A list of identities that has been parsed from some input file.
pub struct IdentityFile {
    identities: Vec<Box<dyn Identity>>,
}

impl IdentityFile {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Self> {
        File::open(filename)
            .map(io::BufReader::new)
            .and_then(IdentityFile::from_buffer)
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: io::BufRead>(data: R) -> io::Result<Self> {
        let mut identities: Vec<Box<dyn Identity>> = vec![];
        for line in data.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with('#') {
                if let Ok(identity) = line.parse::<x25519::ExternalIdentity>() {
                    identities.push(Box::new(identity));
                }
                continue;
            }

            if let Ok(identity) = line.parse::<x25519::Identity>() {
                identities.push(Box::new(identity));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid identity file",
                ));
            }
        }
        Ok(IdentityFile { identities })
    }

    /// Returns the identities in this file.
    pub fn into_identities(self) -> Vec<Box<dyn Identity>> {
        self.identities
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::IdentityFile;

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn valid_secret_key_encoding(keydata: &str, num_keys: usize) {
        let buf = BufReader::new(keydata.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        assert_eq!(f.identities.len(), num_keys);
        assert_eq!(f.identities[0].to_string().expose_secret(), TEST_SK);
    }

    #[test]
    fn secret_key_encoding() {
        valid_secret_key_encoding(TEST_SK, 1);
    }

    #[test]
    fn secret_key_lf() {
        valid_secret_key_encoding(&format!("{}\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_lf() {
        valid_secret_key_encoding(&format!("{}\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_lf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_lf() {
        valid_secret_key_encoding(&format!("\n\n{}", TEST_SK), 1);
    }

    #[test]
    fn secret_key_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n", TEST_SK), 1);
    }

    #[test]
    fn two_secret_keys_crlf() {
        valid_secret_key_encoding(&format!("{}\r\n{}", TEST_SK, TEST_SK), 2);
    }

    #[test]
    fn secret_key_with_comment_crlf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\r\n{}", TEST_SK), 1);
        valid_secret_key_encoding(&format!("{}\r\n# Foo bar baz", TEST_SK), 1);
    }

    #[test]
    fn secret_key_with_empty_line_crlf() {
        valid_secret_key_encoding(&format!("\r\n\r\n{}", TEST_SK), 1);
    }

    #[test]
    fn incomplete_secret_key_encoding() {
        let buf = BufReader::new(&TEST_SK.as_bytes()[..4]);
        assert!(IdentityFile::from_buffer(buf).is_err());
    }
}
