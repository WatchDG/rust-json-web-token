use b64_url::{B64Config, B64ConfigPadding};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use serde::{Serialize, Serializer};
use sha2::Sha256;

use crate::Header;

lazy_static! {
    static ref B64_CONFIG: B64Config = B64Config {
        padding: B64ConfigPadding { omit: true }
    };
}

#[derive(Debug, Clone)]
pub enum SigningAlgorithm {
    HS256,
}

impl Default for SigningAlgorithm {
    #[inline]
    fn default() -> Self {
        SigningAlgorithm::HS256
    }
}

impl ToString for SigningAlgorithm {
    #[inline]
    fn to_string(&self) -> String {
        match self {
            SigningAlgorithm::HS256 => "HS256".into(),
        }
    }
}

impl Serialize for SigningAlgorithm {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Clone)]
pub enum Signer {
    HmacSha256(Hmac<Sha256>),
}

impl Signer {
    pub fn header(&self) -> Header {
        match self {
            Signer::HmacSha256(_) => Header {
                algorithm: SigningAlgorithm::HS256,
                r#type: Some("JWT".into()),
            },
        }
    }

    pub fn signature_length(&self) -> usize {
        match self {
            Signer::HmacSha256(_) => 32,
        }
    }

    pub fn signature(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Signer::HmacSha256(mut signer) => {
                signer.update(bytes);
                signer.finalize().into_bytes().to_vec()
            }
        }
    }
}
