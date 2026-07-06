//! PKCS#11 **HSM** signer (feature `signer-pkcs11`).
//!
//! Signs on a hardware/soft HSM through `cryptoki`; the private key never leaves
//! the token. ES256 pre-hashes the `ToBeSigned` with SHA-256 and signs the digest
//! with `CKM_ECDSA` (which returns the raw `r‖s` form — no DER conversion);
//! Ed25519 signs the message with `CKM_EDDSA`. The public key (trust anchor) is
//! read once from `CKA_EC_POINT` at connect. A fresh, logged-in session is opened
//! per signature (the HSM enforces auth), so the signer holds no live session.
//!
//! Live validation runs against SoftHSM2 behind `#[ignore]` (`pkcs11_live`); the
//! deterministic point/DER unwrapping is unit-tested here.

use async_trait::async_trait;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use boatramp_core::cose::{Signer, TokenAlg, TokenError, TokenPublicKey};

use super::{sha256, SignerError};

const BACKEND: &str = "pkcs11";

/// A PKCS#11 HSM signing key.
pub(crate) struct Pkcs11Signer {
    ctx: Pkcs11,
    slot: Slot,
    key_label: Vec<u8>,
    pin: AuthPin,
    alg: TokenAlg,
    public: TokenPublicKey,
}

impl Pkcs11Signer {
    /// Load the module, find the token by label, and read the signing key's public
    /// half (the trust anchor). Blocking PKCS#11 work — called once at startup.
    pub(crate) fn connect(
        module: &str,
        token_label: &str,
        key_label: &str,
        pin_env: &str,
        alg: TokenAlg,
    ) -> Result<Self, SignerError> {
        let pin = AuthPin::new(SignerError::env(pin_env)?);
        let ctx = Pkcs11::new(module).map_err(|e| SignerError::backend(BACKEND, e))?;
        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| SignerError::backend(BACKEND, e))?;

        let slot = ctx
            .get_slots_with_token()
            .map_err(|e| SignerError::backend(BACKEND, e))?
            .into_iter()
            .find(|&slot| {
                ctx.get_token_info(slot)
                    .map(|info| info.label().trim() == token_label)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                SignerError::backend(BACKEND, format!("no token labelled `{token_label}`"))
            })?;

        let key_label = key_label.as_bytes().to_vec();
        let public = {
            let session = ctx
                .open_ro_session(slot)
                .map_err(|e| SignerError::backend(BACKEND, e))?;
            session
                .login(UserType::User, Some(&pin))
                .map_err(|e| SignerError::backend(BACKEND, e))?;
            let handles = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::PUBLIC_KEY),
                    Attribute::Label(key_label.clone()),
                ])
                .map_err(|e| SignerError::backend(BACKEND, e))?;
            let handle = handles
                .first()
                .ok_or_else(|| SignerError::backend(BACKEND, "public key not found"))?;
            let attrs = session
                .get_attributes(*handle, &[AttributeType::EcPoint])
                .map_err(|e| SignerError::backend(BACKEND, e))?;
            let ec_point = attrs
                .into_iter()
                .find_map(|a| match a {
                    Attribute::EcPoint(bytes) => Some(bytes),
                    _ => None,
                })
                .ok_or_else(|| SignerError::backend(BACKEND, "key has no CKA_EC_POINT"))?;
            parse_ec_point(&ec_point, alg)?
        };

        Ok(Self {
            ctx,
            slot,
            key_label,
            pin,
            alg,
            public,
        })
    }

    /// Open a fresh logged-in session and sign `data` (a digest for ECDSA, the
    /// message for EdDSA) with the private key. Blocking.
    fn sign_blocking(&self, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>, TokenError> {
        let session = self
            .ctx
            .open_ro_session(self.slot)
            .map_err(|e| TokenError::Signer(format!("pkcs11 session: {e}")))?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(|e| TokenError::Signer(format!("pkcs11 login: {e}")))?;
        let handles = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(self.key_label.clone()),
            ])
            .map_err(|e| TokenError::Signer(format!("pkcs11 find key: {e}")))?;
        let key = handles
            .first()
            .ok_or_else(|| TokenError::Signer("pkcs11: private key not found".into()))?;
        session
            .sign(mechanism, *key, data)
            .map_err(|e| TokenError::Signer(format!("pkcs11 sign: {e}")))
    }
}

/// Parse a `CKA_EC_POINT` value into a public key. The value is the DER OCTET
/// STRING wrapping the ANSI X9.62 point (`0x04 ‖ x ‖ y` for P-256, or the raw
/// 32-byte key for Ed25519); some tokens omit the wrapper.
fn parse_ec_point(ec_point: &[u8], alg: TokenAlg) -> Result<TokenPublicKey, SignerError> {
    let point = unwrap_octet_string(ec_point);
    match alg {
        TokenAlg::Es256 => TokenPublicKey::from_hex(&format!("es256:{}", hex::encode(point)))
            .map_err(|e| SignerError::Key(e.to_string())),
        TokenAlg::Ed25519 => TokenPublicKey::from_hex(&format!("ed25519:{}", hex::encode(point)))
            .map_err(|e| SignerError::Key(e.to_string())),
    }
}

/// Strip a DER OCTET STRING (`0x04 <short-len> <value>`) wrapper if present,
/// returning the inner value; otherwise return the input unchanged. Handles the
/// short-form length only (EC points are well under 128 bytes).
fn unwrap_octet_string(der: &[u8]) -> Vec<u8> {
    if der.len() >= 2 && der[0] == 0x04 && (der[1] as usize) == der.len() - 2 && der[1] < 0x80 {
        der[2..].to_vec()
    } else {
        der.to_vec()
    }
}

#[async_trait]
impl Signer for Pkcs11Signer {
    fn alg(&self) -> TokenAlg {
        self.alg
    }

    fn public_key(&self) -> TokenPublicKey {
        self.public.clone()
    }

    async fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, TokenError> {
        match self.alg {
            // CKM_ECDSA signs the digest and returns the raw r‖s form directly.
            TokenAlg::Es256 => self.sign_blocking(&Mechanism::Ecdsa, &sha256(tbs)),
            // CKM_EDDSA signs the message and returns the raw 64-byte signature.
            TokenAlg::Ed25519 => self.sign_blocking(&Mechanism::Eddsa, tbs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_wrapper_is_stripped_when_present() {
        // DER OCTET STRING wrapping a 65-byte uncompressed P-256 point.
        let mut point = vec![0x04u8];
        point.extend(vec![0xABu8; 64]);
        assert_eq!(point.len(), 65);
        let mut wrapped = vec![0x04u8, 65];
        wrapped.extend_from_slice(&point);
        assert_eq!(unwrap_octet_string(&wrapped), point);
        // A bare point (no wrapper) is returned unchanged.
        assert_eq!(unwrap_octet_string(&point), point);
    }

    /// Live round-trip against SoftHSM2 / a real HSM. Env:
    /// `BOATRAMP_TEST_PKCS11_MODULE`/`_TOKEN`/`_KEY`, `PKCS11_PIN`. Provision e.g.
    /// `softhsm2-util --init-token …` + `pkcs11-tool --keypairgen --key-type EC:prime256v1`.
    #[tokio::test]
    #[ignore = "requires SoftHSM2/an HSM (BOATRAMP_TEST_PKCS11_MODULE/_TOKEN/_KEY, PKCS11_PIN)"]
    async fn pkcs11_live() {
        let module = std::env::var("BOATRAMP_TEST_PKCS11_MODULE").expect("module path");
        let token = std::env::var("BOATRAMP_TEST_PKCS11_TOKEN").expect("token label");
        let key = std::env::var("BOATRAMP_TEST_PKCS11_KEY").expect("key label");
        let signer = Pkcs11Signer::connect(&module, &token, &key, "PKCS11_PIN", TokenAlg::Es256)
            .expect("connect to the HSM");
        super::super::assert_signs_and_verifies(&signer).await;
    }
}
