use b64_url::{
    B64Config, B64ConfigPadding, _b64_url_encode_calculate_destination_capacity,
    _b64_url_encode_with_config,
};
use bytes::Bytes;
use lazy_static::lazy_static;

pub mod header;
pub mod payload;
pub mod signer;

use header::Header;
use payload::Payload;
use signer::Signer;

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
    pub signature: Vec<u8>,
    pub signature_bytes: Bytes,
}

#[derive(Debug, Clone)]
pub struct JwtBuilder {
    pub payload: Payload,
}

impl JwtBuilder {
    pub fn build(self, signer: &Signer) -> Jwt {
        let signer = signer.clone();

        let header = signer.header();
        let header_json = serde_json::to_string(&header).unwrap();
        let payload_json = serde_json::to_string(&self.payload).unwrap();

        let mut buffer = Vec::<u8>::with_capacity(
            _b64_url_encode_calculate_destination_capacity(header_json.len())
                + _b64_url_encode_calculate_destination_capacity(payload_json.len())
                + _b64_url_encode_calculate_destination_capacity(signer.signature_length())
                + 2,
        );

        let header_num_bytes;
        let payload_num_bytes;
        let signature_num_bytes;
        let mut destination_ptr = buffer.as_mut_ptr();
        unsafe {
            header_num_bytes = _b64_url_encode_with_config(
                header_json.as_ptr(),
                header_json.len(),
                destination_ptr,
                &B64_CONFIG,
            );
            destination_ptr = destination_ptr.add(header_num_bytes + 1);
            payload_num_bytes = _b64_url_encode_with_config(
                payload_json.as_ptr(),
                payload_json.len(),
                destination_ptr,
                &B64_CONFIG,
            );
            buffer.set_len(header_num_bytes + payload_num_bytes + 1);
        }
        buffer[header_num_bytes] = 0x2e;

        let signature = signer.signature(buffer.as_slice());
        unsafe {
            destination_ptr = destination_ptr.add(payload_num_bytes + 1);
            signature_num_bytes = _b64_url_encode_with_config(
                signature.as_ptr(),
                signature.len(),
                destination_ptr,
                &B64_CONFIG,
            );
            buffer.set_len(header_num_bytes + payload_num_bytes + signature_num_bytes + 2);
        }
        buffer[header_num_bytes + payload_num_bytes + 1] = 0x2e;

        let bytes = Bytes::from(buffer);
        let header_bytes = bytes.slice(0..header_num_bytes);
        let payload_bytes =
            bytes.slice((header_num_bytes + 1)..(header_num_bytes + payload_num_bytes + 1));
        let signature_bytes = bytes.slice(
            (header_num_bytes + payload_num_bytes + 2)
                ..(header_num_bytes + payload_num_bytes + signature_num_bytes + 2),
        );

        Jwt {
            bytes,
            header,
            header_bytes,
            payload: self.payload,
            payload_bytes,
            signature,
            signature_bytes,
        }
    }
}

#[cfg(test)]
mod jwt_builder_tests {
    use super::*;
    use bytes::Bytes;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

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
