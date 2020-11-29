//! Support for the age plugin system.

use age_core::{
    format::{FileKey, Stanza},
    plugin::Connection,
};
use secrecy::ExposeSecret;
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::iter;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};

use crate::{
    error::{DecryptError, EncryptError, PluginError},
    protocol::decryptor::Callbacks,
    util::parse_bech32,
};

// Plugin HRPs are age1[name] and AGE-PLUGIN-[NAME]-
const PLUGIN_RECIPIENT_PREFIX: &str = "age1";
const PLUGIN_IDENTITY_PREFIX: &str = "age-plugin-";

const CMD_ERROR: &str = "error";
const CMD_RECIPIENT_STANZA: &str = "recipient-stanza";
const CMD_PROMPT: &str = "prompt";
const CMD_REQUEST_SECRET: &str = "request-secret";
const CMD_FILE_KEY: &str = "file-key";

fn binary_name(plugin_name: &str) -> String {
    format!("age-plugin-{}", plugin_name)
}

/// A plugin-compatible recipient.
#[derive(Clone)]
pub struct Recipient {
    /// The plugin name, extracted from `recipient`.
    name: String,
    /// The recipient.
    recipient: String,
}

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    /// Parses a plugin recipient from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, _)| {
                if hrp.len() > PLUGIN_RECIPIENT_PREFIX.len()
                    && hrp.starts_with(PLUGIN_RECIPIENT_PREFIX)
                {
                    Ok(Recipient {
                        name: hrp.split_at(PLUGIN_RECIPIENT_PREFIX.len()).1.to_owned(),
                        recipient: s.to_owned(),
                    })
                } else {
                    Err("invalid HRP")
                }
            })
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.recipient)
    }
}

impl Recipient {
    /// Returns the plugin name for this recipient.
    pub fn plugin(&self) -> &str {
        &self.name
    }
}

/// A plugin-compatible identity.
#[derive(Clone)]
pub struct Identity {
    /// The plugin name, extracted from `identity`.
    name: String,
    /// The identity.
    identity: String,
}

impl std::str::FromStr for Identity {
    type Err = &'static str;

    /// Parses a plugin identity from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_bech32(s)
            .ok_or("invalid Bech32 encoding")
            .and_then(|(hrp, _)| {
                if hrp.len() > PLUGIN_IDENTITY_PREFIX.len()
                    && hrp.starts_with(PLUGIN_IDENTITY_PREFIX)
                {
                    Ok(Identity {
                        name: hrp
                            .split_at(PLUGIN_IDENTITY_PREFIX.len())
                            .1
                            .trim_end_matches("-")
                            .to_owned(),
                        identity: s.to_owned(),
                    })
                } else {
                    Err("invalid HRP")
                }
            })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identity)
    }
}

impl Identity {
    /// Returns the plugin name for this identity.
    pub fn plugin(&self) -> &str {
        &self.name
    }
}

/// An age plugin.
struct Plugin(PathBuf);

impl Plugin {
    /// Finds the age plugin with the given name in `$PATH`.
    ///
    /// On error, returns the binary name that could not be located.
    fn new(name: &str) -> Result<Self, String> {
        let binary_name = binary_name(name);
        which::which(&binary_name)
            .map(Plugin)
            .map_err(|_| binary_name)
    }

    fn connect(&self, state_machine: &str) -> io::Result<Connection<ChildStdout, ChildStdin>> {
        Connection::open(&self.0, state_machine)
    }
}

/// An age plugin with an associated set of recipients.
///
/// This struct implements [`Recipient`], enabling the plugin to encrypt a file to the
/// entire set of recipients.
pub struct RecipientPluginV1 {
    plugin: Plugin,
    recipients: Vec<Recipient>,
}

impl RecipientPluginV1 {
    /// Creates an age plugin from a plugin name and a list of recipients.
    ///
    /// The list of recipients will be filtered by the plugin name; recipients that don't
    /// match will be ignored.
    ///
    /// Returns an error if the plugin's binary cannot be found in `$PATH`.
    pub fn new(plugin_name: &str, recipients: &[Recipient]) -> Result<Self, EncryptError> {
        Plugin::new(plugin_name)
            .map_err(|binary_name| EncryptError::MissingPlugin { binary_name })
            .map(|plugin| RecipientPluginV1 {
                plugin,
                recipients: recipients
                    .iter()
                    .filter(|r| r.name == plugin_name)
                    .cloned()
                    .collect(),
            })
    }
}

impl crate::Recipient for RecipientPluginV1 {
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError> {
        let parse_errors = |errors: Vec<Stanza>| {
            Err(EncryptError::Plugin(
                errors
                    .into_iter()
                    .map(|s| {
                        if s.args.len() == 2 && s.args[0] == "recipient" {
                            let index: usize = s.args[1].parse().unwrap();
                            PluginError::Recipient {
                                binary_name: binary_name(&self.recipients[index].name),
                                recipient: self.recipients[index].recipient.clone(),
                                message: String::from_utf8_lossy(&s.body).to_string(),
                            }
                        } else {
                            PluginError::from(s)
                        }
                    })
                    .collect(),
            ))
        };

        // Open connection
        let mut conn = self.plugin.connect("--recipient-plugin-v1")?;

        // Phase 1: add-recipient
        conn.unidir_send(|mut phase| {
            for recipient in &self.recipients {
                phase.send("add-recipient", &[&recipient.recipient], &[])?;
            }
            Ok(())
        })?;

        // Phase 2: check for errors
        let errors = conn.unidir_receive(&[CMD_ERROR])?;
        if !errors.is_empty() {
            parse_errors(errors)?;
        }

        // Phase 3: request wrapping
        conn.unidir_send(|mut phase| phase.send("wrap-file-key", &[], file_key.expose_secret()))?;

        // Phase 4: collect either stanzas or errors
        let (stanzas, errors) = conn
            .unidir_receive(&[CMD_RECIPIENT_STANZA, CMD_ERROR])?
            .into_iter()
            .partition::<Vec<_>, _>(|s| s.tag == CMD_RECIPIENT_STANZA);
        match (stanzas.is_empty(), errors.is_empty()) {
            (false, true) => Ok(stanzas
                .into_iter()
                .map(|mut s| {
                    s.args.remove(0);
                    s.tag = s.args.remove(0);
                    s
                })
                .collect()),
            (true, false) => parse_errors(errors),
            _ => unimplemented!(),
        }
    }
}

/// An age plugin with an associated set of identities.
///
/// This struct implements [`Identity`], enabling the plugin to decrypt a file with any
/// identity in the set of identities.
pub struct IdentityPluginV1<C: Callbacks> {
    plugin: Plugin,
    identities: Vec<Identity>,
    callbacks: C,
}

impl<C: Callbacks> IdentityPluginV1<C> {
    /// Creates an age plugin from a plugin name and a list of identities.
    ///
    /// The list of identities will be filtered by the plugin name; identities that don't
    /// match will be ignored.
    ///
    /// Returns an error if the plugin's binary cannot be found in `$PATH`.
    pub fn new(
        plugin_name: &str,
        identities: &[Identity],
        callbacks: C,
    ) -> Result<Self, DecryptError> {
        Plugin::new(plugin_name)
            .map_err(|binary_name| DecryptError::MissingPlugin { binary_name })
            .map(|plugin| IdentityPluginV1 {
                plugin,
                identities: identities
                    .iter()
                    .filter(|r| r.name == plugin_name)
                    .cloned()
                    .collect(),
                callbacks,
            })
    }

    fn unwrap_stanzas<'a>(
        &self,
        stanzas: impl Iterator<Item = &'a Stanza>,
    ) -> Option<Result<FileKey, DecryptError>> {
        // Open connection
        let mut conn = self.plugin.connect("--identity-plugin-v1").unwrap();

        // Phase 1: add identities and stanza
        if let Err(e) = conn.unidir_send(|mut phase| {
            for identity in &self.identities {
                phase.send("add-identity", &[identity.identity.as_str()], &[])?;
            }
            for stanza in stanzas {
                phase.send_stanza("recipient-stanza", &["0"], stanza)?;
            }
            Ok(())
        }) {
            return Some(Err(e.into()));
        };

        // Phase 2: interactively unwrap
        let mut file_key = None;
        let mut errors = vec![];
        if let Err(e) = conn.bidir_receive(
            &[CMD_PROMPT, CMD_REQUEST_SECRET, CMD_FILE_KEY, CMD_ERROR],
            |command, reply| match command.tag.as_str() {
                CMD_PROMPT => {
                    self.callbacks
                        .prompt(&String::from_utf8_lossy(&command.body));
                    reply.ok(None)
                }
                CMD_REQUEST_SECRET => {
                    if let Some(secret) = self
                        .callbacks
                        .request_passphrase(&String::from_utf8_lossy(&command.body))
                    {
                        reply.ok(Some(secret.expose_secret().as_bytes()))
                    } else {
                        reply.fail()
                    }
                }
                CMD_FILE_KEY => {
                    // We only support a single file.
                    assert!(command.args[0] == "0");
                    assert!(file_key.is_none());
                    file_key = Some(
                        TryInto::<[u8; 16]>::try_into(&command.body[..])
                            .map_err(|_| DecryptError::DecryptionFailed)
                            .map(FileKey::from),
                    );
                    reply.ok(None)
                }
                CMD_ERROR => {
                    if command.args.len() == 2 && command.args[0] == "identity" {
                        let index: usize = command.args[1].parse().unwrap();
                        errors.push(PluginError::Identity {
                            binary_name: binary_name(&self.identities[index].name),
                            message: String::from_utf8_lossy(&command.body).to_string(),
                        });
                    } else if command.args.len() == 2 && command.args[0] == "file" {
                        // We only support a single file.
                        assert!(command.args[1] == "0");
                        assert!(file_key.is_none());
                    } else {
                        errors.push(PluginError::from(command));
                    }
                    reply.ok(None)
                }
                _ => unreachable!(),
            },
        ) {
            return Some(Err(e.into()));
        };

        if file_key.is_none() && !errors.is_empty() {
            Some(Err(DecryptError::Plugin(errors)))
        } else {
            file_key
        }
    }
}

impl<C: Callbacks> crate::Identity for IdentityPluginV1<C> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        self.unwrap_stanzas(iter::once(stanza))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, DecryptError>> {
        self.unwrap_stanzas(stanzas.iter())
    }
}
