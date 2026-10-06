// MFi authentication coprocessor: reads the accessory certificate and signs challenges.

use std::time::Duration;

use openssl::bn::BigNumRef;
use openssl::ecdsa::EcdsaSig;
use openssl::pkcs7::Pkcs7;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Padding;

pub const CHALLENGE_MIN: usize = 1;
pub const CHALLENGE_MAX: usize = 128;
const AUTH_V3_CHALLENGE_SIZE: usize = 32;
const AUTH_V3_SIGNATURE_SIZE: usize = 64;

pub const REG_DEVICE_VERSION: u8 = 0x00;
pub const REG_PROTOCOL_MAJOR: u8 = 0x02;
pub const REG_ERROR_CODE: u8 = 0x05;
pub const REG_AUTH_CONTROL_STATUS: u8 = 0x10;
pub const REG_SIGNATURE_LENGTH: u8 = 0x11;
pub const REG_SIGNATURE_DATA: u8 = 0x12;
pub const REG_CHALLENGE_LENGTH: u8 = 0x20;
pub const REG_CHALLENGE_DATA: u8 = 0x21;
pub const REG_CERT_LENGTH: u8 = 0x30;
pub const REG_CERT_DATA: u8 = 0x31;

pub const AUTH_START: u8 = 0x01;
pub const AUTH_DONE: u8 = 0x10;

pub const DEV_ADDR_CANDIDATES: [u16; 2] = [0x10, 0x11];

#[derive(Debug)]
pub enum MfiError {
    Timeout(String),
    ChallengeSize(usize),
    AuthFailed { error_code: Option<u8> },
    NoChip { probed: Vec<u16> },
    Io(String),
    KeyMaterial(String),
}

impl core::fmt::Display for MfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MfiError::Timeout(what) => write!(f, "timeout during {what}"),
            MfiError::ChallengeSize(n) => write!(f, "challenge must be 1..=128 bytes, got {n}"),
            MfiError::AuthFailed { error_code: Some(c) } => {
                write!(f, "auth failed (error code 0x{c:02X})")
            }
            MfiError::AuthFailed { error_code: None } => {
                write!(f, "auth failed (error unreadable)")
            }
            MfiError::NoChip { probed } => {
                let addrs: Vec<String> = probed.iter().map(|a| format!("0x{a:02X}")).collect();
                write!(f, "no coprocessor answered at {}", addrs.join("/"))
            }
            MfiError::Io(e) => write!(f, "i2c io: {e}"),
            MfiError::KeyMaterial(e) => write!(f, "file MFi credentials: {e}"),
        }
    }
}

impl std::error::Error for MfiError {}

/// File-backed MFi authentication using a PKCS#7 certificate bundle and a
/// PKCS#8 private key.
pub struct FileCoprocessor {
    // The MFi protocol expects the original PKCS#7 document, not a DER leaf certificate.
    certificate: Vec<u8>,
    key: PKey<Private>,
    key_kind: FileKeyKind,
}

#[derive(Clone, Copy)]
enum FileKeyKind {
    Rsa,
    Ec,
}

impl FileCoprocessor {
    pub fn from_files(
        certificate_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, MfiError> {
        let certificate_path = certificate_path.as_ref();
        let key_path = key_path.as_ref();
        let bundle = std::fs::read(certificate_path).map_err(|e| {
            MfiError::KeyMaterial(format!("read {}: {e}", certificate_path.display()))
        })?;
        let pkcs7 =
            Pkcs7::from_der(&bundle).or_else(|_| Pkcs7::from_pem(&bundle)).map_err(|e| {
                MfiError::KeyMaterial(format!("parse {}: {e}", certificate_path.display()))
            })?;
        let key_data = std::fs::read(key_path)
            .map_err(|e| MfiError::KeyMaterial(format!("read {}: {e}", key_path.display())))?;
        let key = PKey::private_key_from_der(&key_data)
            .or_else(|_| PKey::private_key_from_pem(&key_data))
            .map_err(|e| MfiError::KeyMaterial(format!("parse {}: {e}", key_path.display())))?;
        let key_kind = match key.id() {
            Id::RSA => FileKeyKind::Rsa,
            Id::EC => FileKeyKind::Ec,
            id => {
                return Err(MfiError::KeyMaterial(format!("unsupported private key type {id:?}")));
            }
        };
        let _matching_certificate = pkcs7
            .signed()
            .and_then(|signed| signed.certificates())
            .and_then(|certificates| {
                certificates.iter().find(|certificate| {
                    certificate.public_key().is_ok_and(|public| key.public_eq(&public))
                })
            })
            .ok_or_else(|| {
                MfiError::KeyMaterial(
                    "certificate bundle has no certificate matching the private key".into(),
                )
            })?;

        Ok(Self { certificate: bundle, key, key_kind })
    }
}

impl AuthCoprocessor for FileCoprocessor {
    fn protocol_major(&mut self) -> Result<u8, MfiError> {
        Ok(match self.key_kind {
            FileKeyKind::Rsa => 2,
            FileKeyKind::Ec => 3,
        })
    }

    fn read_certificate(&mut self) -> Result<Vec<u8>, MfiError> {
        Ok(self.certificate.clone())
    }

    fn generate_challenge_response(&mut self, challenge: &[u8]) -> Result<Vec<u8>, MfiError> {
        match self.key_kind {
            FileKeyKind::Rsa => {
                if !(CHALLENGE_MIN..=CHALLENGE_MAX).contains(&challenge.len()) {
                    return Err(MfiError::ChallengeSize(challenge.len()));
                }
                let rsa = self.key.rsa().map_err(|e| MfiError::KeyMaterial(e.to_string()))?;
                let mut signature = vec![0; rsa.size() as usize];
                let size = rsa
                    .private_encrypt(challenge, &mut signature, Padding::NONE)
                    .map_err(|e| MfiError::KeyMaterial(format!("sign challenge: {e}")))?;
                signature.truncate(size);
                Ok(signature)
            }
            FileKeyKind::Ec => {
                if challenge.len() != AUTH_V3_CHALLENGE_SIZE {
                    return Err(MfiError::ChallengeSize(challenge.len()));
                }
                let ec = self.key.ec_key().map_err(|e| MfiError::KeyMaterial(e.to_string()))?;
                let signature = EcdsaSig::sign(challenge, &ec)
                    .map_err(|e| MfiError::KeyMaterial(format!("sign challenge: {e}")))?;
                let mut raw = vec![0; AUTH_V3_SIGNATURE_SIZE];
                write_fixed_integer(signature.r(), &mut raw[..32])?;
                write_fixed_integer(signature.s(), &mut raw[32..])?;
                Ok(raw)
            }
        }
    }
}

fn write_fixed_integer(value: &BigNumRef, output: &mut [u8]) -> Result<(), MfiError> {
    let encoded = value
        .to_vec_padded(output.len() as i32)
        .map_err(|e| MfiError::KeyMaterial(format!("encode ECDSA signature: {e}")))?;
    if encoded.len() != output.len() {
        return Err(MfiError::KeyMaterial("ECDSA signature integer is out of range".into()));
    }
    output.copy_from_slice(&encoded);
    Ok(())
}

/// The MFi coprocessor, on a local i2c bus or behind the STM bridge.
pub trait AuthCoprocessor {
    fn protocol_major(&mut self) -> Result<u8, MfiError>;
    fn read_certificate(&mut self) -> Result<Vec<u8>, MfiError>;
    fn generate_challenge_response(&mut self, challenge: &[u8]) -> Result<Vec<u8>, MfiError>;
}

/// No coprocessor at hand: every operation fails.
pub struct NoCoprocessor;

impl AuthCoprocessor for NoCoprocessor {
    fn protocol_major(&mut self) -> Result<u8, MfiError> {
        Err(MfiError::Io("no MFi coprocessor".into()))
    }
    fn read_certificate(&mut self) -> Result<Vec<u8>, MfiError> {
        Err(MfiError::Io("no MFi coprocessor".into()))
    }
    fn generate_challenge_response(&mut self, _challenge: &[u8]) -> Result<Vec<u8>, MfiError> {
        Err(MfiError::Io("no MFi coprocessor".into()))
    }
}

pub const BUSY_RETRY: Duration = Duration::from_micros(500);
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub const AUTH_POLL: Duration = Duration::from_millis(10);
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::I2cCoprocessor;

// Remote coprocessor over TCP (LIVI Link).
pub mod ncm;
pub use ncm::NcmCoprocessor;

// Dongle-side TCP server for MFi authentication.
pub mod server;
