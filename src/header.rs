use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::signer::SigningAlgorithm;

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
