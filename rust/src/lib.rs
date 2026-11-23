//! ssenc1: diff-friendly file encryption with password and ssh-agent keys.
//!
//! The format is specified in `SPEC.md` at the repository root; this crate is
//! byte-for-byte interoperable with the TypeScript and Bash implementations next to it.
//!
//! ```
//! use ssenc::{decrypt, encrypt, EncryptOptions, Key};
//!
//! let key = Key::password("hunter2");
//! let opts = EncryptOptions { kdf: Some("m=64,t=1,p=1".into()), ..Default::default() };
//! let text = encrypt(b"  secret: 1\n", &[key.clone()], &opts)?;
//! assert!(text.starts_with("#ssenc1 lines ws=1 pad=16\n"));
//! assert_eq!(decrypt(text.as_bytes(), &key)?, b"  secret: 1\n");
//! # Ok::<(), ssenc::Error>(())
//! ```

mod agent;
mod format;
mod ops;
pub mod prim;
mod ssh;
mod util;

pub use crate::format::{Kdf, KdfParams, Mode};
pub use crate::ops::{
    decrypt, detect_mode, encrypt, inspect, rekey, EncryptOptions, InspectResult, Key, RekeyOptions, SlotInfo,
};
pub use crate::ssh::{ssh_fingerprint, ssh_key_type, ssh_parse_public_key, SshSigner};
pub use crate::util::{Error, ErrorKind};

/// Version of this implementation.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
