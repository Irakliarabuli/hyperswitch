//! Keepz hybrid envelope encryption.
//!
//! Every request payload is AES-256-CBC encrypted with a fresh random key and
//! IV. The base64 key and IV are joined with a `.` and wrapped with
//! RSA-OAEP (SHA-256 hash and MGF1) using the public key Keepz hands out
//! during onboarding. Responses use the same envelope in reverse and are
//! unwrapped with the integrator's own RSA private key.
//!
//! Keys may be supplied either as PEM blocks or as bare base64 DER
//! (SPKI for the public key, PKCS#8 for the private key), matching what the
//! Keepz merchant portal exports.

use base64::Engine;
use common_utils::{consts::BASE64_ENGINE, errors::CustomResult};
use error_stack::{report, ResultExt};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{PeekInterface, Secret};
use openssl::{
    encrypt::{Decrypter, Encrypter},
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    rsa::Padding,
    symm::{decrypt, encrypt, Cipher},
};
use serde::{Deserialize, Serialize};

const AES_KEY_LEN: usize = 32;
const AES_IV_LEN: usize = 16;
const PEM_MARKER: &str = "-----BEGIN";

/// Outer envelope carried in the request body or query string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzEnvelope {
    pub identifier: Secret<String>,
    pub encrypted_data: String,
    pub encrypted_keys: String,
    pub aes: bool,
}

/// Encrypted body returned by Keepz on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzEncryptedResponse {
    pub encrypted_data: String,
    pub encrypted_keys: String,
    #[serde(default)]
    pub aes: Option<bool>,
}

fn load_public_key(raw: &Secret<String>) -> CustomResult<PKey<Public>, errors::ConnectorError> {
    let raw = raw.peek().trim();
    let key = if raw.contains(PEM_MARKER) {
        PKey::public_key_from_pem(raw.as_bytes())
    } else {
        let der = BASE64_ENGINE
            .decode(raw.split_whitespace().collect::<String>())
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
            .attach_printable("Keepz public key is neither PEM nor base64 DER")?;
        PKey::public_key_from_der(&der)
    };
    key.change_context(errors::ConnectorError::FailedToObtainAuthType)
        .attach_printable("Could not parse Keepz RSA public key")
}

fn load_private_key(raw: &Secret<String>) -> CustomResult<PKey<Private>, errors::ConnectorError> {
    let raw = raw.peek().trim();
    let key = if raw.contains(PEM_MARKER) {
        PKey::private_key_from_pem(raw.as_bytes())
    } else {
        let der = BASE64_ENGINE
            .decode(raw.split_whitespace().collect::<String>())
            .change_context(errors::ConnectorError::FailedToObtainAuthType)
            .attach_printable("Keepz private key is neither PEM nor base64 DER")?;
        PKey::private_key_from_pkcs8(&der)
    };
    key.change_context(errors::ConnectorError::FailedToObtainAuthType)
        .attach_printable("Could not parse integrator RSA private key")
}

/// Serializes `payload` to JSON and wraps it in a Keepz envelope.
pub fn encrypt_envelope<T: Serialize>(
    integrator_id: &Secret<String>,
    keepz_public_key: &Secret<String>,
    payload: &T,
) -> CustomResult<KeepzEnvelope, errors::ConnectorError> {
    let plaintext = serde_json::to_vec(payload)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    let public_key = load_public_key(keepz_public_key)?;

    let mut aes_key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; AES_IV_LEN];
    rand_bytes(&mut aes_key).change_context(errors::ConnectorError::RequestEncodingFailed)?;
    rand_bytes(&mut iv).change_context(errors::ConnectorError::RequestEncodingFailed)?;

    let ciphertext = encrypt(Cipher::aes_256_cbc(), &aes_key, Some(&iv), &plaintext)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Keepz AES encryption failed")?;

    let keys_string = format!(
        "{}.{}",
        BASE64_ENGINE.encode(aes_key),
        BASE64_ENGINE.encode(iv)
    );
    let mut encrypter = Encrypter::new(&public_key)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    configure_oaep(&mut encrypter)?;
    let mut wrapped = vec![
        0u8;
        encrypter
            .encrypt_len(keys_string.as_bytes())
            .change_context(errors::ConnectorError::RequestEncodingFailed)?
    ];
    let written = encrypter
        .encrypt(keys_string.as_bytes(), &mut wrapped)
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Keepz RSA key wrapping failed")?;
    wrapped.truncate(written);

    Ok(KeepzEnvelope {
        identifier: integrator_id.clone(),
        encrypted_data: BASE64_ENGINE.encode(ciphertext),
        encrypted_keys: BASE64_ENGINE.encode(wrapped),
        aes: true,
    })
}

/// Unwraps a Keepz envelope and returns the plaintext JSON bytes.
pub fn decrypt_envelope(
    integrator_private_key: &Secret<String>,
    response: &KeepzEncryptedResponse,
) -> CustomResult<Vec<u8>, errors::ConnectorError> {
    let private_key = load_private_key(integrator_private_key)?;
    let wrapped = BASE64_ENGINE
        .decode(&response.encrypted_keys)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("encryptedKeys is not valid base64")?;

    let mut decrypter = Decrypter::new(&private_key)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    configure_oaep(&mut decrypter)?;
    let mut keys_string = vec![
        0u8;
        decrypter.decrypt_len(&wrapped).change_context(
            errors::ConnectorError::ResponseDeserializationFailed
        )?
    ];
    let written = decrypter
        .decrypt(&wrapped, &mut keys_string)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("Keepz RSA key unwrapping failed; check the integrator private key")?;
    keys_string.truncate(written);

    let keys_string = String::from_utf8(keys_string)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    let (key_b64, iv_b64) = keys_string.split_once('.').ok_or_else(|| {
        report!(errors::ConnectorError::ResponseDeserializationFailed)
            .attach_printable("Keepz encryptedKeys did not contain a `key.iv` pair")
    })?;
    let aes_key = BASE64_ENGINE
        .decode(key_b64)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    let iv = BASE64_ENGINE
        .decode(iv_b64)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
    let ciphertext = BASE64_ENGINE
        .decode(&response.encrypted_data)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("encryptedData is not valid base64")?;

    decrypt(Cipher::aes_256_cbc(), &aes_key, Some(&iv), &ciphertext)
        .change_context(errors::ConnectorError::ResponseDeserializationFailed)
        .attach_printable("Keepz AES decryption failed")
}

trait OaepConfigurable {
    fn set_oaep(&mut self) -> Result<(), openssl::error::ErrorStack>;
}

impl OaepConfigurable for Encrypter<'_> {
    fn set_oaep(&mut self) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_padding(Padding::PKCS1_OAEP)?;
        self.set_rsa_oaep_md(MessageDigest::sha256())?;
        self.set_rsa_mgf1_md(MessageDigest::sha256())
    }
}

impl OaepConfigurable for Decrypter<'_> {
    fn set_oaep(&mut self) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_padding(Padding::PKCS1_OAEP)?;
        self.set_rsa_oaep_md(MessageDigest::sha256())?;
        self.set_rsa_mgf1_md(MessageDigest::sha256())
    }
}

fn configure_oaep<T: OaepConfigurable>(target: &mut T) -> CustomResult<(), errors::ConnectorError> {
    target
        .set_oaep()
        .change_context(errors::ConnectorError::RequestEncodingFailed)
        .attach_printable("Could not configure RSA-OAEP-SHA256")
}

#[cfg(test)]
mod tests {
    use openssl::rsa::Rsa;

    use super::*;

    struct KeyPair {
        public_pem: String,
        private_pem: String,
        public_der_b64: String,
        private_der_b64: String,
    }

    fn generate_keys() -> KeyPair {
        let rsa = Rsa::generate(2048).expect("rsa keygen");
        let pkey = PKey::from_rsa(rsa).expect("pkey");
        KeyPair {
            public_pem: String::from_utf8(pkey.public_key_to_pem().unwrap()).unwrap(),
            private_pem: String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap(),
            public_der_b64: BASE64_ENGINE.encode(pkey.public_key_to_der().unwrap()),
            private_der_b64: BASE64_ENGINE.encode(pkey.private_key_to_pkcs8().unwrap()),
        }
    }

    fn roundtrip(public_key: &str, private_key: &str) {
        let payload = serde_json::json!({
            "integratorId": "int-1",
            "integratorOrderId": "order-1",
            "amount": 12.5
        });
        let envelope = encrypt_envelope(
            &Secret::new("int-1".to_string()),
            &Secret::new(public_key.to_string()),
            &payload,
        )
        .expect("encrypt");
        assert!(envelope.aes);
        assert_eq!(envelope.identifier.peek(), "int-1");

        let response = KeepzEncryptedResponse {
            encrypted_data: envelope.encrypted_data,
            encrypted_keys: envelope.encrypted_keys,
            aes: Some(true),
        };
        let plaintext =
            decrypt_envelope(&Secret::new(private_key.to_string()), &response).expect("decrypt");
        let decoded: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn roundtrip_with_pem_keys() {
        let keys = generate_keys();
        roundtrip(&keys.public_pem, &keys.private_pem);
    }

    #[test]
    fn roundtrip_with_base64_der_keys() {
        let keys = generate_keys();
        roundtrip(&keys.public_der_b64, &keys.private_der_b64);
    }

    #[test]
    fn each_request_uses_fresh_key_material() {
        let keys = generate_keys();
        let payload = serde_json::json!({ "a": 1 });
        let first = encrypt_envelope(
            &Secret::new("i".to_string()),
            &Secret::new(keys.public_pem.clone()),
            &payload,
        )
        .unwrap();
        let second = encrypt_envelope(
            &Secret::new("i".to_string()),
            &Secret::new(keys.public_pem),
            &payload,
        )
        .unwrap();
        assert_ne!(first.encrypted_data, second.encrypted_data);
        assert_ne!(first.encrypted_keys, second.encrypted_keys);
    }

    #[test]
    fn wrong_private_key_is_rejected() {
        let keys = generate_keys();
        let other = generate_keys();
        let envelope = encrypt_envelope(
            &Secret::new("i".to_string()),
            &Secret::new(keys.public_pem),
            &serde_json::json!({ "a": 1 }),
        )
        .unwrap();
        let response = KeepzEncryptedResponse {
            encrypted_data: envelope.encrypted_data,
            encrypted_keys: envelope.encrypted_keys,
            aes: Some(true),
        };
        assert!(decrypt_envelope(&Secret::new(other.private_pem), &response).is_err());
    }

    #[test]
    fn invalid_key_material_is_rejected() {
        assert!(load_public_key(&Secret::new("not a key".to_string())).is_err());
        assert!(load_private_key(&Secret::new("bm90IGEga2V5".to_string())).is_err());
    }
}
