use b64_url::{b64_url_encode_with_config, B64Config, B64ConfigPadding};
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use sha2::Sha256;

pub mod header;
pub mod payload;

use header::{Header, SigningAlgorithm};
use payload::Payload;

lazy_static! {
    static ref B64_CONFIG: B64Config = B64Config {
        padding: B64ConfigPadding { omit: true }
    };
}

#[derive(Debug)]
pub struct Jwt {
    pub bytes: Bytes,
    pub header: Header,
    pub header_bytes: Bytes,
    pub payload: Payload,
    pub payload_bytes: Bytes,
    pub signature: String,
    pub signature_bytes: Bytes,
}

#[derive(Debug)]
pub struct JwtBuilder {
    pub payload: Payload,
}

impl JwtBuilder {
    pub fn build(&self, signer: &Signer) -> Jwt {
        let signer = signer.clone();

        let (header, header_string) = signer.get_jwt_header();

        let payload_string = String::from_utf8(b64_url_encode_with_config(
            serde_json::to_string(&self.payload).unwrap().as_bytes(),
            &B64_CONFIG,
        ))
        .unwrap();

        let signature_string = signer.get_jwt_signature(&header_string, &payload_string);

        let mut cursor = 0;
        let mut buffer = BytesMut::with_capacity(
            header_string.len() + payload_string.len() + signature_string.len() + 2,
        );
        buffer.put(header_string.as_bytes());
        let header_indexes = (cursor, cursor + header_string.len());
        buffer.put(".".as_bytes());
        cursor += header_string.len() + 1;
        buffer.put(payload_string.as_bytes());
        let payload_indexes = (cursor, cursor + payload_string.len());
        buffer.put(".".as_bytes());
        cursor += payload_string.len() + 1;
        buffer.put(signature_string.as_bytes());
        let signature_indexes = (cursor, cursor + signature_string.len());
        let bytes = buffer.freeze();

        let header_bytes = bytes.slice(header_indexes.0..header_indexes.1);
        let payload_bytes = bytes.slice(payload_indexes.0..payload_indexes.1);
        let signature_bytes = bytes.slice(signature_indexes.0..signature_indexes.1);

        Jwt {
            bytes,
            header,
            header_bytes,
            payload: self.payload.clone(),
            payload_bytes,
            signature: signature_string.clone(),
            signature_bytes,
        }
    }
}

#[derive(Clone)]
pub enum Signer {
    HmacSha256(Hmac<Sha256>),
}

impl Signer {
    pub fn get_jwt_header(&self) -> (Header, String) {
        match self {
            Signer::HmacSha256(_) => {
                let header = Header {
                    algorithm: SigningAlgorithm::HS256,
                    r#type: Some("JWT".into()),
                };
                let header_string = String::from_utf8(b64_url_encode_with_config(
                    serde_json::to_string(&header).unwrap().as_bytes(),
                    &B64_CONFIG,
                ))
                .unwrap();
                (header, header_string)
            }
        }
    }

    pub fn get_jwt_signature(self, header_string: &String, payload_string: &String) -> String {
        match self {
            Signer::HmacSha256(mut signer) => {
                signer.update(header_string.as_bytes());
                signer.update(b".");
                signer.update(payload_string.as_bytes());
                let result = signer.finalize().into_bytes();
                String::from_utf8(b64_url_encode_with_config(&result, &B64_CONFIG)).unwrap()
            }
        }
    }
}

#[cfg(test)]
mod jwt_builder_tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn new() {
        let mut payload = Payload::new();
        payload.issuer = Some(String::from("hello").into());
        payload.subject = Some(true.into());

        let jwt_builder = JwtBuilder { payload };

        let signer =
            Signer::HmacSha256(Hmac::<Sha256>::new_from_slice(b"your-256-bit-secret").unwrap());

        let jwt = jwt_builder.build(&signer);

        assert_eq!(jwt.bytes, Bytes::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoZWxsbyIsInN1YiI6dHJ1ZX0.Xk_NUrp8IZ4mvrATTB67AlpBmWDTufz6JHFpz_13KZg"));
    }
}
