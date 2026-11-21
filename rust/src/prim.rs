//! HMAC-SHA-256, HKDF32, SIV and Argon2id (SPEC.md section 1).

use crate::util::Error;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub(crate) type Secret32 = Zeroizing<[u8; 32]>;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| Error::env(format!("no secure random source: {e}")))?;
    Ok(out)
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA-256 with a 32-byte output; `salt` `None` means 32 zero bytes.
pub fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let prk = Zeroizing::new(hmac_sha256(salt.unwrap_or(&[0u8; 32]), &[ikm]));
    hmac_sha256(&prk[..], &[info, &[1]])
}

/// The MAC and encryption key of one SIV instance.
pub struct SivKey {
    mac: Secret32,
    enc: Secret32,
}

impl SivKey {
    /// Derives `ssenc1/<purpose>-mac` and `ssenc1/<purpose>-enc` from `parent`.
    pub fn derive(parent: &[u8], purpose: &str) -> SivKey {
        SivKey {
            mac: Zeroizing::new(hkdf32(parent, None, format!("ssenc1/{purpose}-mac").as_bytes())),
            enc: Zeroizing::new(hkdf32(parent, None, format!("ssenc1/{purpose}-enc").as_bytes())),
        }
    }

    pub fn from_raw(kmac: [u8; 32], kenc: [u8; 32]) -> SivKey {
        SivKey {
            mac: Zeroizing::new(kmac),
            enc: Zeroizing::new(kenc),
        }
    }

    pub fn kmac(&self) -> &[u8; 32] {
        &self.mac
    }

    pub fn kenc(&self) -> &[u8; 32] {
        &self.enc
    }

    fn tag(&self, ad: &[u8], pt: &[u8]) -> [u8; 16] {
        let full = hmac_sha256(&self.mac[..], &[&(ad.len() as u64).to_be_bytes(), ad, pt]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full[..16]);
        tag
    }

    fn ctr(&self, tag: &[u8; 16], data: &mut [u8]) {
        let mut iv = *tag;
        iv[8] &= 0x7f;
        iv[12] &= 0x7f;
        let mut cipher = Aes256Ctr::new((&*self.enc).into(), (&iv).into());
        cipher.apply_keystream(data);
    }

    /// Returns `tag || ct`.
    pub fn encrypt(&self, ad: &[u8], pt: &[u8]) -> Vec<u8> {
        let tag = self.tag(ad, pt);
        let mut out = Vec::with_capacity(16 + pt.len());
        out.extend_from_slice(&tag);
        out.extend_from_slice(pt);
        self.ctr(&tag, &mut out[16..]);
        out
    }

    pub fn decrypt(&self, ad: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
        if input.len() < 16 {
            return Err(Error::malformed("ciphertext shorter than the authentication tag"));
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&input[..16]);
        let mut pt = Zeroizing::new(input[16..].to_vec());
        self.ctr(&tag, &mut pt);
        if !constant_time_equal(&tag, &self.tag(ad, &pt)) {
            return Err(Error::auth("authentication failed (wrong key or modified data)"));
        }
        Ok(std::mem::take(&mut *pt))
    }
}

pub(crate) fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Argon2id v0x13 with a 32-byte output; `m` in KiB.
pub fn argon2id(password: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], Error> {
    let params = argon2::Params::new(m, t, p, Some(32))
        .map_err(|e| Error::malformed(format!("argon2id parameters rejected: {e}")))?;
    let ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    ctx.hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::env(format!("argon2id failed: {e}")))?;
    Ok(out)
}
