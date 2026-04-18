//! axum 相关的辅助函数及扩展类

use std::{borrow::Cow, fmt::Display, io::Write, net::SocketAddr};

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts},
    http::{Response, StatusCode, header, request::Parts},
    response::IntoResponse,
};
use compact_str::{CompactString, ToCompactString};
use memchr::memchr2;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub const OK_CODE: u32 = 200;
pub const APPLICATION_JSON: &str = "application/json; charset=utf-8";

/// 通用api接口函数返回值
pub type ApiResult<T> = Result<ApiRes<T>, ApiError>;

/// axum的客户端IP提取器, 当这个与 body 的 [Json] 提取器一起使用时, 请将这个放在 body 参数之前
pub struct ClientIp(pub CompactString);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    #[allow(clippy::manual_async_fn)]
    fn from_request_parts(
        parts: &mut Parts, _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let real_ip = parts
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_compact_string())
                .or_else(|| {
                    parts
                        .headers
                        .get("X-Real-IP")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_compact_string())
                })
                .unwrap_or_else(|| {
                    parts
                        .extensions
                        .get::<ConnectInfo<SocketAddr>>()
                        .map(|ci| ci.0.ip().to_compact_string())
                        .unwrap_or_else(|| "unknown".to_compact_string())
                });

            Ok(ClientIp(real_ip))
        }
    }
}

// 自定义 JSON 字符串响应
pub struct JsonString(pub String);

impl IntoResponse for JsonString {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, APPLICATION_JSON)
            .body(Body::from(self.0))
            .unwrap()
    }
}

pub struct JsonDisplay<'a>(pub &'a str);

impl Display for JsonDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // f.write_str(&json_escape(self.0))
        let escape_start = find_escape(self.0);
        // 没有转义字符, 则返回原值
        if escape_start == u32::MAX {
            f.write_str(self.0)
        } else {
            json_escape_inner(f, self.0, escape_start)
        }
    }
}

// 转义表（查找表优化）, 这是个常量表, 编译时就确定了
const ESCAPE_TABLE: [u8; 128] = {
    let mut table: [u8; 128] = [0; 128];
    table[b'"' as usize] = b'"';
    table[b'\\' as usize] = b'\\';
    table[b'\n' as usize] = b'n';
    table[b'\r' as usize] = b'r';
    table[b'\t' as usize] = b't';
    table[0x08] = b'b';
    table[0x0c] = b'f';
    table
};

pub fn write_json_str<W: std::fmt::Write>(w: &mut W, text: &str) -> std::fmt::Result {
    let escape_start = find_escape(text);
    // 没有转义字符, 则返回原值
    if escape_start == u32::MAX {
        w.write_str(text)?;
    } else {
        json_escape_inner(w, text, escape_start)?;
    }
    Ok(())
}

/// json 字符串转义, 将普通字符串转义成json字符串
pub fn json_escape(text: &str) -> Cow<'_, str> {
    let escape_start = find_escape(text);
    // 没有转义字符, 则返回原值
    if escape_start == u32::MAX {
        Cow::Borrowed(text)
    } else {
        // 预分配容量
        let mut buf = String::with_capacity(text.len() + text.len() / 8 + 64);
        let _ = json_escape_inner(&mut buf, text, escape_start);
        Cow::Owned(buf)
    }
}

fn json_escape_inner<W: std::fmt::Write>(
    w: &mut W, text: &str, escape_start: u32,
) -> std::fmt::Result {
    fn write_slice<W: std::fmt::Write>(w: &mut W, s: &[u8]) -> std::fmt::Result {
        w.write_str(unsafe { std::str::from_utf8_unchecked(s) })
    }

    let mut tow_u8 = [b'\\', 0u8];

    let tbs = text.as_bytes();
    let mut idx = escape_start as usize;
    let mut last_end = 0;

    // 处理字符串, 将需要转义的字符进行转义
    for &b in &tbs[idx..] {
        if b < 128 {
            let t = ESCAPE_TABLE[b as usize];
            // 找到需要转义的字符
            if t != 0 {
                // 先行拷贝上次转义字符到本次转义字符前的所有字符
                if last_end < idx {
                    write_slice(w, &tbs[last_end..idx])?;
                }

                // buf.push(b'\\');
                // buf.push(t);
                tow_u8[1] = t;
                write_slice(w, &tow_u8)?;

                last_end = idx + 1;
            }
        }
        idx += 1;
    }

    // 拷贝尾部的所有字符
    if last_end < idx {
        write_slice(w, &tbs[last_end..idx])?;
    }
    Ok(())
}

/// 判断字符串中是否有json的转义字符, 返回u32::MAX表示没有, 其他值表示第一个转义字符的位置
fn find_escape(text: &str) -> u32 {
    // 查找第一个需要转义的字符
    // for (i, &b) in text.as_bytes().iter().enumerate() {
    //     // 优化, 合并2个判断为1个判断, 减少分支判断, 对CPU友好
    //     // if b < 128 && ESCAPE_TABLE[b as usize] != 0 {
    //     if ((b & 0x80) | ESCAPE_TABLE[(b & 0x7F) as usize]) != 0 {
    //         return i as u32;
    //     }
    // }

    // u32::MAX

    const OTHER_ESCAPE_CHARS: [u8; 5] = [b'\n', b'\r', b'\t', 0x08, 0x0c];

    let bytes = text.as_bytes();

    // 首先用 SIMD 快速扫描常见字符
    if let Some(pos) = memchr2(b'"', b'\\', bytes) {
        return pos as u32;
    }

    if let Some(pos) = memchr::memmem::find(bytes, &OTHER_ESCAPE_CHARS) {
        return pos as u32;
    }

    u32::MAX
}

/// 压缩 JSON 字符串：删除字符串外的所有空白（空格、换行、制表符）
/// 保留字符串内的原始内容
pub fn compress_json(json: &str) -> String {
    let mut buf = Vec::with_capacity(json.len());
    let jbs = json.as_bytes();
    let mut in_string = false;
    let mut escaped = false;

    for &b in jbs {
        if in_string {
            // 在字符串内部：原样保留，只处理转义
            buf.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            // 在字符串外部：跳过所有空白
            if b == b'"' {
                in_string = true;
                buf.push(b);
            } else if b != b' ' && b != b'\t' && b != b'\r' && b != b'\n' {
                buf.push(b);
            }
            // 其他空白字符（空格、\n、\r、\t）直接丢弃
        }
    }

    unsafe { String::from_utf8_unchecked(buf) }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiRes<T> {
    /// 状态码, 类似HTTP的状态码, 200 表示成功, 500 表示失败
    pub code: u32,
    /// 错误消息, 当状态码 != 200 时, 错误消息才有意义, 否则为 [None]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// 请求结果, 当状态码 == 200 时, 结果才有意义, 否则为 [None]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiRes<T> {
    /// 成功响应
    pub fn ok(data: T) -> Self {
        Self { code: 200, msg: None, data: Some(data) }
    }

    /// 成功无数据
    pub fn ok_empty() -> Self {
        ApiRes { code: 200, msg: None, data: None }
    }

    /// 错误响应
    pub fn error<S: Into<String>>(code: u32, msg: S) -> Self {
        Self { code, msg: Some(msg.into()), data: None }
    }

    /// 通用错误响应
    pub fn error_universal<S: Into<String>>(msg: S) -> Self {
        Self { code: 500, msg: Some(msg.into()), data: None }
    }
}

// 实现 IntoResponse，让 ApiResult 可以直接返回
impl<T: Serialize> IntoResponse for ApiRes<T> {
    fn into_response(self) -> Response<Body> {
        let mut body = Vec::with_capacity(512);
        if let Err(e) = serde_json::to_writer(&mut body, &self) {
            let mut buf = SmallVec::<[u8; 128]>::new();
            let _ = write!(&mut buf, "{}", e);
            let e_str = json_escape(unsafe { std::str::from_utf8_unchecked(&buf) });
            let _ = write!(&mut body, r#"{{"code":500,"msg":"序列化错误: {}"}}"#, e_str);
        };

        let status = match StatusCode::from_u16(self.code as u16) {
            Ok(status) => status,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, APPLICATION_JSON)
            .body(Body::from(body))
            .unwrap()
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub code: u32,
    pub msg: String,
}

impl ApiError {
    pub fn error<T: Into<String>>(msg: T) -> Self {
        Self { code: 500, msg: msg.into() }
    }

    pub fn error_with_code<T: Into<String>>(code: u16, msg: T) -> Self {
        Self { code: code as u32, msg: msg.into() }
    }

    pub fn error_with_status<T: Into<String>>(status: StatusCode, msg: T) -> Self {
        Self { code: status.as_u16() as u32, msg: msg.into() }
    }

    pub fn not_found() -> Self {
        Self { code: 404, msg: "Not Found".into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        let mut body = Vec::with_capacity(256);
        let _ = write!(&mut body, r#"{{"code":{},"msg":"{}"}}"#, self.code, JsonDisplay(&self.msg));

        let status = match StatusCode::from_u16(self.code as u16) {
            Ok(status) => status,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, APPLICATION_JSON)
            .body(Body::from(body))
            .unwrap()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.msg)
    }
}

impl std::error::Error for ApiError {}

// 关键：从 anyhow::Error 转换
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self { code: 500, msg: e.to_string() }
    }
}

/// 获取唯一参数, 优先级: body > param > path > default
#[macro_export]
macro_rules! param_from_multi {
    ($body:ident, $query:ident, $path:ident, $field:ident, $default:expr) => {
        $body
            .as_ref()
            .and_then(|b| b.0.$field.as_ref())
            .or($query.$field.as_ref())
            .or($path.$field.as_ref())
            .map_or_else(|| $default, |s| s.as_str())
    };
}

/// 获取唯一参数, 优先级: body > param > path, 没有值返回Err
#[macro_export]
macro_rules! param_required {
    ($body:ident, $query:ident, $path:ident, $field:ident, $fn_once:expr) => {
        $body
            .and_then(|b| b.0.$field.as_ref())
            .or($query.$field.as_ref())
            .or($path.$field.as_ref())
            .ok_or_else($fn_once)
    };
}

/// 返回JsonString类型的返回值
#[macro_export]
macro_rules! api_json {
    () => {
        return r#"{{"code":200}}"#.to_string();
    };
    ($cap:expr, $fmt:literal, $($arg:tt)*) => {{
        use std::fmt::Write as _;
        let mut json = String::with_capacity($cap);
        let _ = write!(&mut json, r#"{{"code":200,"data":{}}}"#, format_args!($fmt, $($arg)*));
        return $crate::JsonString(json);
    }};
}

/// 返回JsonString类型的返回值
#[macro_export]
macro_rules! api_json_err {
    ($msg:literal) => {{
        let mut json = String::with_capacity(256);
        let _ = write!(&mut json, r#"{{"code":200,"msg":"{}"}}"#, $msg);
        return $crate::JsonString(json);
    }};
    ($fmt:literal, $($arg:tt)*) => {{
        let mut json = String::with_capacity(256);
        let _ = write!(&mut json, r#"{{"code":200,"msg":"{}"}}"#, format_args!($fmt, $($arg)*));
        return $crate::JsonString(json);
    }};
}

/// 返回成功的ApiResult
#[macro_export]
macro_rules! api_ok {
    () => {
        return Ok($crate::ApiRes::ok_empty());
    };
    ($data:expr) => {
        return Ok($crate::ApiRes::ok($data));
    };
}

/// 返回失败的ApiResult
#[macro_export]
macro_rules! api_err {
    () => {
        return Err($crate::ApiError::error("系统内部错误"));
    };
    ($msg:expr) => {
        return Err($crate::ApiError::error($msg));
    };
}
