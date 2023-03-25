use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

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

#[derive(Debug, Clone)]
pub struct Header {
    pub algorithm: SigningAlgorithm,
    pub r#type: Option<String>,
}

impl Serialize for Header {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ss = serializer.serialize_struct("JwtHeader", 2)?;
        ss.serialize_field("alg", &self.algorithm)?;
        if let Some(r#type) = &self.r#type {
            ss.serialize_field("typ", r#type)?;
        }
        ss.end()
    }
}
