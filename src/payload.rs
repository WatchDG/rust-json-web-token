use serde::{ser::SerializeStruct, Serialize, Serializer};

#[derive(Debug, Clone)]
pub enum Value {
    String(String),
    Boolean(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::String(value) => serializer.serialize_str(value),
            Value::Boolean(value) => serializer.serialize_bool(*value),
            Value::I8(value) => serializer.serialize_i8(*value),
            Value::I16(value) => serializer.serialize_i16(*value),
            Value::I32(value) => serializer.serialize_i32(*value),
            Value::I64(value) => serializer.serialize_i64(*value),
            Value::U8(value) => serializer.serialize_u8(*value),
            Value::U16(value) => serializer.serialize_u16(*value),
            Value::U32(value) => serializer.serialize_u32(*value),
            Value::U64(value) => serializer.serialize_u64(*value),
            Value::F32(value) => serializer.serialize_f32(*value),
            Value::F64(value) => serializer.serialize_f64(*value),
        }
    }
}

impl From<String> for Value {
    #[inline(always)]
    fn from(value: String) -> Self {
        Value::String(value)
    }
}

impl From<bool> for Value {
    #[inline(always)]
    fn from(value: bool) -> Self {
        Value::Boolean(value)
    }
}

impl From<i8> for Value {
    #[inline(always)]
    fn from(value: i8) -> Self {
        Value::I8(value)
    }
}

impl From<i16> for Value {
    #[inline(always)]
    fn from(value: i16) -> Self {
        Value::I16(value)
    }
}

impl From<i32> for Value {
    #[inline(always)]
    fn from(value: i32) -> Self {
        Value::I32(value)
    }
}

impl From<i64> for Value {
    #[inline(always)]
    fn from(value: i64) -> Self {
        Value::I64(value)
    }
}

impl From<u8> for Value {
    #[inline(always)]
    fn from(value: u8) -> Self {
        Value::U8(value)
    }
}

impl From<u16> for Value {
    #[inline(always)]
    fn from(value: u16) -> Self {
        Value::U16(value)
    }
}

impl From<u32> for Value {
    #[inline(always)]
    fn from(value: u32) -> Self {
        Value::U32(value)
    }
}

impl From<u64> for Value {
    #[inline(always)]
    fn from(value: u64) -> Self {
        Value::U64(value)
    }
}

impl From<f32> for Value {
    #[inline(always)]
    fn from(value: f32) -> Self {
        Value::F32(value)
    }
}

impl From<f64> for Value {
    #[inline(always)]
    fn from(value: f64) -> Self {
        Value::F64(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Payload {
    pub issuer: Option<Value>,
    pub subject: Option<Value>,
    pub audience: Option<Value>,
    pub expiration_time: Option<Value>,
}

impl Payload {
    #[inline]
    pub fn new() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            expiration_time: None,
        }
    }
}

impl Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("JWTClaims", 1)?;
        if let Some(issuer) = &self.issuer {
            s.serialize_field("iss", issuer)?;
        }
        if let Some(subject) = &self.subject {
            s.serialize_field("sub", subject)?;
        }
        if let Some(audience) = &self.audience {
            s.serialize_field("aud", audience)?;
        }
        if let Some(expiration_time) = &self.expiration_time {
            s.serialize_field("exp", expiration_time)?;
        }
        s.end()
    }
}
