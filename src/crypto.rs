use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use chacha20poly1305::aead::{Aead, KeyInit};

const BASE64_DECODE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Derives a ChaCha20-Poly1305 shared key from a WireGuard private key
/// and a peer's public key via X25519 Diffie-Hellman.
pub fn derive_shared_key(private_key_b64: &str, public_key_b64: &str) -> Result<[u8; 32]> {
    let priv_bytes: [u8; 32] = BASE64_DECODE
        .decode(private_key_b64.trim())
        .context("Invalid base64 in PrivateKey")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("PrivateKey must be 32 bytes, got {}", v.len()))?;

    let pub_bytes: [u8; 32] = BASE64_DECODE
        .decode(public_key_b64.trim())
        .context("Invalid base64 in PublicKey")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("PublicKey must be 32 bytes, got {}", v.len()))?;

    let secret = StaticSecret::from(priv_bytes);
    let peer_public = PublicKey::from(pub_bytes);
    let shared_secret = secret.diffie_hellman(&peer_public);

    Ok(shared_secret.to_bytes())
}

/// Encrypts and decrypts VPN packets using ChaCha20-Poly1305.
/// Uses a monotonic counter for nonces, ensuring uniqueness per direction.
#[derive(Clone)]
pub struct PacketCipher {
    cipher: ChaCha20Poly1305,
    nonce_counter: Arc<AtomicU64>,
}

impl PacketCipher {
    pub fn new(shared_key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(shared_key)
            .expect("32-byte key is always valid for ChaCha20Poly1305");

        Self {
            cipher,
            nonce_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn next_nonce(&self) -> Nonce {
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypt a plaintext packet.
    /// Returns: [12-byte nonce || ciphertext+tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a packet produced by `encrypt`.
    /// Input: [12-byte nonce || ciphertext+tag]
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN + TAG_LEN {
            anyhow::bail!(
                "Encrypted packet too short ({} bytes, need at least {})",
                data.len(),
                NONCE_LEN + TAG_LEN
            );
        }

        let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
        let ciphertext = &data[NONCE_LEN..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = PacketCipher::new(&key);

        let plaintext = b"Hello, VPN tunnel!";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        assert_ne!(&encrypted[NONCE_LEN..], plaintext);

        let decrypter = PacketCipher::new(&key);
        let decrypted = decrypter.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unique_nonces() {
        let key = [0x42u8; 32];
        let cipher = PacketCipher::new(&key);

        let enc1 = cipher.encrypt(b"packet 1").unwrap();
        let enc2 = cipher.encrypt(b"packet 1").unwrap();

        // Same plaintext, different nonces => different ciphertext
        assert_ne!(enc1, enc2);

        let decrypter = PacketCipher::new(&key);
        assert_eq!(decrypter.decrypt(&enc1).unwrap(), b"packet 1");
        assert_eq!(decrypter.decrypt(&enc2).unwrap(), b"packet 1");
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = [0x42u8; 32];
        let cipher = PacketCipher::new(&key);

        let mut encrypted = cipher.encrypt(b"secret data").unwrap();
        encrypted[NONCE_LEN + 2] ^= 0xff;

        let decrypter = PacketCipher::new(&key);
        assert!(decrypter.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_derive_shared_key_symmetry() {
        let priv_a = [1u8; 32];
        let priv_b = [2u8; 32];

        let secret_a = StaticSecret::from(priv_a);
        let secret_b = StaticSecret::from(priv_b);
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);

        let pub_a_b64 = base64::engine::general_purpose::STANDARD.encode(pub_a.as_bytes());
        let pub_b_b64 = base64::engine::general_purpose::STANDARD.encode(pub_b.as_bytes());
        let priv_a_b64 = base64::engine::general_purpose::STANDARD.encode(priv_a);
        let priv_b_b64 = base64::engine::general_purpose::STANDARD.encode(priv_b);

        let shared_ab = derive_shared_key(&priv_a_b64, &pub_b_b64).unwrap();
        let shared_ba = derive_shared_key(&priv_b_b64, &pub_a_b64).unwrap();

        assert_eq!(shared_ab, shared_ba);
    }
}
