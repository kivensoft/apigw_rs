use std::time::SystemTime;

use serde_json::{Value, Map};
use base64::{Engine, engine::general_purpose};
use sha2::Sha256;
use hmac::{Hmac, Mac};
#[cfg(feature = "rsa")]
use rsa::{
    RsaPrivateKey, RsaPublicKey, signature::{Signer, Verifier},
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey}
};
use anyhow::Result;

pub const AUTHORIZATION: &str = "Authorization";
pub const BEARER: &str = "Bearer ";
pub const WWW_AUTHENTICATE :&str = "WWW-Authenticate";

/// jwt头部: json字符串的base64编码: {"alg":"HS256","typ":"JWT"}
const HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
/// jwt body: 发布者的键名
const ISSUER_KEY: &str = "iss";
/// jwt body: 过期时间的键名
const EXP_KEY: &str = "exp";

#[cfg(feature = "rsa")]
/// {"alg":"RS256","typ":"JWT"}
const HEADER_RS256_B64: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

type HmacSha256 = Hmac<Sha256>;

/// Parsing jwt string and return sign base64 string
pub fn get_sign(jwt: &str) -> Option<&str> {
    match jwt.rfind('.') {
        Some(n) => jwt.get(n+1..),
        None => None,
    }
}

/// Generate a jwt using the specified parameters, jwt type is HS256
///
/// * `claims`: jwt user custom data, it must be Value::Object or Value::Null
/// * `key`: jwt hmac encrypt key
/// * `issuer` jwt issuer value
/// * `exp`: jwt expire time value(Unit: second), 1 hour like 3600
///
/// Returns:
///
/// Ok(String): jwt string, Err(e): error
///
/// # Examples
///
/// ```rust
/// use jwt;
///
/// let s = jwt::encode(&serde_json::json!({
///     "userId": 1,
///     "username": "kiven",
/// }), "password", "my_app_name", 86400).unwrap();
/// ```
pub fn encode(claims: &Value, key: &str, issuer: &str, exp: u64) -> Result<String> {
    // 复制claims，并添加 issuer 和 exp 属性，形成最终的 claims 条目
    debug_assert!(claims.is_null() || claims.is_object());
    let mut claims = match claims {
        Value::Null => Map::new(),
        Value::Object(v) => v.clone(),
        _ => panic!("jwt encode function param `claims` format error"),
    };
    claims.insert(ISSUER_KEY.to_owned(), issuer.into());
    let exp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() + exp;
    claims.insert(EXP_KEY.to_owned(), Value::Number(exp.into()));
    // 将claims转成json后用base64编码
    let claims_bs = serde_json::to_vec(&claims)?;
    let claims_b64 = general_purpose::URL_SAFE_NO_PAD.encode(claims_bs);

    let mut jwt_data = format!("{HEADER_B64}.{claims_b64}");

    // 计算jwt的签名，即 header_base64 + "." + claims_base64 的签名，并转成base64编码
    let mut hs256 = HmacSha256::new_from_slice(key.as_bytes())?;
    hs256.update(jwt_data.as_bytes());
    let sign_bs = hs256.finalize();
    let sign_b64 = general_purpose::URL_SAFE_NO_PAD.encode(sign_bs.into_bytes());

    // 生成最终的jwt字符串: header_base64 + "." + claims_base64 + "." + sign_base64
    jwt_data.push('.');
    jwt_data.push_str(&sign_b64);

    Ok(jwt_data)
}

/// Generate a jwt using the specified parameters, jwt type is RS256
///
/// * `claims`: jwt user custom data, it must be Value::Object or Value::Null
/// * `issuer` jwt issuer value
/// * `exp`: jwt expire time value(Unit: second), 1 hour like 3600
///
/// Returns:
///
/// Ok(String): jwt string, Err(e): error
///
/// # Examples
///
/// ```rust
/// use jwt;
///
/// let s = jwt::encode_with_rsa(&serde_json::json!({
///     "userId": 1,
///     "username": "kiven",
/// }), "password", "my_app_name", 86400).unwrap();
/// ```
#[cfg(feature = "rsa")]
pub fn encode_with_rsa(claims: &Value, issuer: &str, exp: u64) -> Result<String> {
    encode_with_rsa_key(claims, issuer, exp, rsa_key_data::RSA_PRIVATE_KEY)
}

#[cfg(feature = "rsa")]
pub fn encode_with_rsa_key(claims: &Value, issuer: &str, exp: u64, private_key: &str) -> Result<String> {
    // 复制claims，并添加 issuer 和 exp 属性，形成最终的 claims 条目
    debug_assert!(claims.is_null() || claims.is_object());
    let mut claims = match claims {
        Value::Null => Map::new(),
        Value::Object(v) => v.clone(),
        _ => panic!("jwt encode function param `claims` format error"),
    };
    claims.insert(ISSUER_KEY.to_owned(), issuer.into());
    let exp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() + exp;
    claims.insert(EXP_KEY.to_owned(), Value::Number(exp.into()));
    // 将claims转成json后用base64编码
    let claims_bs = serde_json::to_vec(&claims)?;
    let claims_b64 = general_purpose::URL_SAFE_NO_PAD.encode(claims_bs);

    let mut jwt_data = format!("{HEADER_RS256_B64}.{claims_b64}");

    // 计算jwt的签名，即 header_base64 + "." + claims_base64 的签名，并转成base64编码
    // 签名算法：
    //    1. 先用 sha256 计算 header_base64 + "." + claims_base64 的结果
    //    2. 再用 rsa sign 计算上一个步骤的结果
    //    3. 把rsa计算结果用base64编码，就是最终的签名
    let pri_key = RsaPrivateKey::from_pkcs1_pem(private_key)?;
    let rsa_sign = SigningKey::<Sha256>::new_with_prefix(pri_key.clone());
    let sign_bs = rsa_sign.sign(jwt_data.as_bytes());
    let sign_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&sign_bs);

    // 生成最终的jwt字符串: header_base64 + "." + claims_base64 + "." + sign_base64
    jwt_data.push('.');
    jwt_data.push_str(&sign_b64);

    Ok(jwt_data)
}

/// Parsing and verifying jwt string, using jwt type HS256
///
/// * `jwt`: jwt string
/// * `key`: jwt hmac encrypt key
/// * `issuer` jwt issuer value
///
/// Returns:
///
/// Ok(String): jwt string, Err(e): error
///
/// # Examples
///
/// ```rust
/// let jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOi\
///     JhY2NpbmZvIiwidXNlciI6ImtpdmVuIiwiZXhwIjoxNTE2MjM5MDIyfQ.t\
///     dcZYbN7tavs9LdbfZT7R1SJeu75FVHvtljm8gjNGig";
///
/// let s = jwt::decode(&jwt_str, "password", "accinfo").unwrap();
///
/// assert_eq!("kiven", s["user"].as_str());
/// ```
pub fn decode(jwt: &str, key: &str, issuer: &str) -> Result<Value> {
    // 把jwt按‘.'分为3段
    let (header_claims_b64, sign_b64) = match jwt.rfind('.') {
        Some(n) => (jwt.get(..n).unwrap(), jwt.get(n+1..).unwrap()),
        None => anyhow::bail!("jwt format error, not found '.'"),
    };
    let (header_b64, claims_b64) = match header_claims_b64.find('.') {
        Some(n) => (header_claims_b64.get(..n).unwrap(), header_claims_b64.get(n+1..).unwrap()),
        None => anyhow::bail!("jwt format error, '.' must two but found one"),
    };

    // 校验头部内容是否正确
    if HEADER_B64 != header_b64 {
        anyhow::bail!("jwt format can't support");
    }

    // 反序列化claims，并校验issuer和exp
    let claims_bs = general_purpose::URL_SAFE_NO_PAD.decode(claims_b64)?;
    let claims: Value = serde_json::from_slice(&claims_bs)?;
    check_issuer(&claims, issuer)?;
    check_exp(&claims)?;

    // 校验签名是否正确
    let sign_bs = general_purpose::URL_SAFE_NO_PAD.decode(sign_b64)?;
    let mut hs256 = HmacSha256::new_from_slice(key.as_bytes())?;
    hs256.update(header_claims_b64.as_bytes());
    if let Err(e) = hs256.verify_slice(&sign_bs) {
        log::trace!("jwt Signature verification failed: {e}");
        anyhow::bail!("Signature verification failed");
    }

    Ok(claims)
}

/// Parsing and verifying jwt string, using jwt type RS256
///
/// * `jwt`: jwt string
/// * `issuer` jwt issuer value
///
/// Returns:
///
/// Ok(String): jwt string, Err(e): error
///
/// # Examples
///
/// ```rust
/// use jwt;
///
/// let jwt_str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhY2NpbmZv\
///     IiwidXNlciI6ImtpdmVuIiwiZXhwIjoxNTE2MjM5MDIyfQ.pbpeMJL4ZPZ-vmf3jgtWKT\
///     gvg7erJrjsFhKTd92NvIqe6nO1SESf92YZLF6G-Dj0k8wfitEvuEQH190xSdGuHMMM-QH\
///     _wWIGJCSG6G6QFjB3c5ZxePEqdY118LNp0AhA9odJiy9cZ6tFDJiyWX1aq9rBnYFnEErc\
///     w_m\ZyLC-PC7k9g6IgT7BaTe7_FOkI8y74RA8SMmFELAfwULB1bZaDZ0SLfMzvv8lwAY6\
///     UiPvQso-eGVTPnc1YuIO154Fg9Se2eh_hU6Ktwwl6VBWpikE-TxExfUsD8dmNtL5b3QNe\
///     1Hf17UfeYG5PmNbQsg1ybDlLqyP68Q1Vvfr_54Bu8szfw";
///
/// let s = jwt::decode(&jwt_str, "accinfo").unwrap();
///
/// assert_eq!("kiven", s["user"].as_str());
/// ```
#[cfg(feature = "rsa")]
pub fn decode_with_rsa(jwt: &str, issuer: &str) -> Result<Value> {
    decode_with_rsa_key(jwt, issuer, rsa_key_data::RSA_PUBLIC_KEY)
}

#[cfg(feature = "rsa")]
pub fn decode_with_rsa_key(jwt: &str, issuer: &str, public_key: &str) -> Result<Value> {
    // 把jwt按‘.'分为3段
    let (header_claims_b64, sign_b64) = match jwt.rfind('.') {
        Some(n) => (jwt.get(..n).unwrap(), jwt.get(n+1..).unwrap()),
        None => anyhow::bail!("jwt format error, not found '.'"),
    };
    let (header_b64, claims_b64) = match header_claims_b64.find('.') {
        Some(n) => (header_claims_b64.get(..n).unwrap(), header_claims_b64.get(n+1..).unwrap()),
        None => anyhow::bail!("jwt format error, '.' must two but found one"),
    };

    // 校验头部内容是否正确
    if HEADER_RS256_B64 != header_b64 {
        anyhow::bail!("jwt format can't support");
    }

    // 反序列化claims，并校验issuer和exp
    let claims_bs = general_purpose::URL_SAFE_NO_PAD.decode(claims_b64)?;
    let claims: Value = serde_json::from_slice(&claims_bs)?;
    check_issuer(&claims, issuer)?;
    check_exp(&claims)?;

    // 校验签名是否正确
    let sign_bs = general_purpose::URL_SAFE_NO_PAD.decode(sign_b64)?;
    let pub_key = RsaPublicKey::from_pkcs1_pem(public_key)?;
    let rsa_verify = VerifyingKey::<Sha256>::new_with_prefix(pub_key);
    if let Err(e) = rsa_verify.verify(header_claims_b64.as_bytes(), &sign_bs.into_boxed_slice().into()) {
        log::trace!("jwt Signature verification failed: {e}");
        anyhow::bail!("Signature verification failed");
    }

    Ok(claims)
}

/// Verify whether the issuer is correct from jwt token
///
/// * `claims`: jwt user custom data, it must be Value::Object or Value::Null
/// * `issuer` jwt issuer value
///
/// Returns:
///
/// Ok(()): verfied success, Err(e): error
///
/// # Examples
///
/// ```rust
/// use jwt;
///
/// let s = serde_json::json!({
///         "userId": 1,
///         "username": "kiven",
///         "iss": "kivensoft",
///     });
/// check_issuer(s, "kiensoft");
/// ```
pub fn check_issuer(claims: &Value, issuer: &str) -> Result<()> {
    if let Some(s) = claims.get(ISSUER_KEY) {
        if let Value::String(s) = s {
            if issuer != s {
                anyhow::bail!("Incorrect issuer");
            } else {
                return Ok(());
            }
        }
    }
    anyhow::bail!("issuer format error")
}

/// Verify whether expire from jwt token
///
/// * `claims`: jwt user custom data, it must be Value::Object or Value::Null
///
/// Returns:
///
/// Ok(String): verfied success, Err(e): error
///
/// # Examples
///
/// ```rust
/// use jwt;
///
/// let s = jwt::encode(&serde_json::json!({
///     "userId": 1,
///     "username": "kiven",
///     "iss": "kivensoft",
///     "exp":  4102358400,
///     });
/// check_exp(s);
/// ```
pub fn check_exp(claims: &Value) -> Result<()> {
    if let Some(exp) = claims.get(EXP_KEY) {
        if let Some(exp) =  exp.as_u64() {
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            if now > exp {
                anyhow::bail!("Incorrect exp");
            } else {
                return Ok(());
            }
        }
    }
    anyhow::bail!("exp format error")
}

#[cfg(feature = "rsa")]
mod rsa_key_data {
    pub const RSA_PRIVATE_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA1h9pD+0KYp5Bpda/OTWFVxaXKPO4+36LzNWk53PG4LOrrg2o
rJzdbhFwoqB20ceFQOZm9dK8udY3LFn4Pv1M01pkPRV39+URLds3W+CujnTQiCJ/
vBeWrIf7HYq6TM0oQcmzESvRsVf37xZpvlK21pxgsxg2pyYoqZrx24ttxm81ZtJj
v76QmzbaU3Lz+rYOfwxzeQelXZ0KDxWrptm+FlIspUzSGYxV6RmV66svaxzNi8mi
bQuIx8BWbVHGWU45cISC4+oSnqUirB8i/URgZhwHyYfFO/Tmmf/+NROjXAqbH7lr
bJBtAP+OXYuKfkBNLUqRmXax2uttbaefF0sxQQIDAQABAoIBADEKbKOrJK/Fkz+K
Wa2epnV1xRUqDPn818QIQoaIK8qXHAD3O+Sc4NIuyF9W5R/S1KAypO40X+koOOa9
jG/Qz+GwWDjtS9bI7hBUnu86HICgHIqxbBQGSwok8synU1f3vPqkWZDbOmGlxjFK
LtnaU+n/Ut5x80KBKNr/k9k2q+PAdWrna/LfcjXtVqkZVUl/3xD+Dp7IIM7nQQuX
Lnfvyk86gP+KKUPs23cnPFwqpWibJO7swJ9tlHQXOefVurvCJFzFhjyG8CkpMcn9
R1B9uUZGGTOYrD797vJ3Ll5JM9Wg+9cy2C8ovOGvEY0L6Y9UhGUqESVjYnXM9/bp
tixAG2ECgYEA8elVewkf29b0/5bHNiGimS/6Qo3/Hz4Ijb5xr9ye7LrbjaQbeDAW
4RwnDvz11zJAR9wRKtZApCGH5NEexZykdxjmxQGOGTz/PUpsRhXFpDW+u4BrwHBZ
3l4j/xoOxQbxIvE3hSZLg22FZVhwfWmBOM4P8L9V34IX8awqyYCBx7UCgYEA4pfF
22e7gtbjqkIlTh8ekZJi3obWdOFCR6r+4ySeUG+b3bL91Js0/2RIu5wB0+t9OZ5d
F7N54e0S2p5au2YcD8q1DmJj8b0tgOffHcCgGWnIhDtu6QA8NKxR3lWYHzJTq9Ju
ZhY5yqopXYOhifBQoliAWFecrgh4pqKFTzGk4t0CgYB6t+GzPpe40D0NA5IfdcSk
bWBJLvuC/9cbAMdvbT353XjPS7bbq5mPrNZrlguolUdirNLQpku4d4IWo7c2jBYq
jKlUu0s4pmbc0spGa3kNqm4NdEI1J0mPsrYUDUX80V62WSPPGfQowgBvvwOhu0ng
ZThU6ttHPRmkcbBq9BPiGQKBgGvZY1IHsIcY8qmB7DGfvDP7YdWahg6BfMORztmb
/0I3rQ87d3cvHG2GdNve6DvOtP6sspBqW1O+PCAUCQlzE14s1DpxeDKCIVtegaKu
oUUXRVoy05pRA1bqwdi6ErqegJaihOtQHteoYCHjWgrGeAqdZxElOizXWV2usxa7
gUh9AoGAZiIlLmGG0dDBvWCWjs0oiPCSIpeINtbNEUIZ5CtI9pUAdR2kMOUIRbta
VlGTzzTlP/uGZlLqRhe6QnLii0MeR7B6suM9JHg0bcLN0diwYpiit73+el1KJYwg
1aM3mKtopVX0gWXIAYbgPDGfxCR/0SbK1XVbBEHthO9Ns563CAU=
-----END RSA PRIVATE KEY-----
"#;

    pub const RSA_PUBLIC_KEY: &str = r#"
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA1h9pD+0KYp5Bpda/OTWFVxaXKPO4+36LzNWk53PG4LOrrg2orJzd
bhFwoqB20ceFQOZm9dK8udY3LFn4Pv1M01pkPRV39+URLds3W+CujnTQiCJ/vBeW
rIf7HYq6TM0oQcmzESvRsVf37xZpvlK21pxgsxg2pyYoqZrx24ttxm81ZtJjv76Q
mzbaU3Lz+rYOfwxzeQelXZ0KDxWrptm+FlIspUzSGYxV6RmV66svaxzNi8mibQuI
x8BWbVHGWU45cISC4+oSnqUirB8i/URgZhwHyYfFO/Tmmf/+NROjXAqbH7lrbJBt
AP+OXYuKfkBNLUqRmXax2uttbaefF0sxQQIDAQAB
-----END RSA PUBLIC KEY-----
"#;

    #[allow(dead_code)]
    pub const PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1h9pD+0KYp5Bpda/OTWF
VxaXKPO4+36LzNWk53PG4LOrrg2orJzdbhFwoqB20ceFQOZm9dK8udY3LFn4Pv1M
01pkPRV39+URLds3W+CujnTQiCJ/vBeWrIf7HYq6TM0oQcmzESvRsVf37xZpvlK2
1pxgsxg2pyYoqZrx24ttxm81ZtJjv76QmzbaU3Lz+rYOfwxzeQelXZ0KDxWrptm+
FlIspUzSGYxV6RmV66svaxzNi8mibQuIx8BWbVHGWU45cISC4+oSnqUirB8i/URg
ZhwHyYfFO/Tmmf/+NROjXAqbH7lrbJBtAP+OXYuKfkBNLUqRmXax2uttbaefF0sx
QQIDAQAB
-----END PUBLIC KEY-----
"#;
}
