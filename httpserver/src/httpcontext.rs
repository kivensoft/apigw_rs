use std::{
    any::Any,
    borrow::Cow,
    collections::HashMap,
    hint,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use anyhow::Result;
use compact_str::CompactString;
use http::{request::Parts, HeaderMap, HeaderValue, Uri};
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use serde::de::DeserializeOwned;

use crate::{
    http_bail, if_else, HttpError, APPLICATION_FORM_SUFFIX, APPLICATION_JSON_PREFIX, CONTENT_TYPE,
};

pub type GKind = gjson::Kind;
pub type GValue<'a> = gjson::Value<'a>;
type FormParamMap<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;
type HttpCtxAttrs = Vec<(CompactString, Box<dyn Any + Send + Sync>)>;

pub enum BodyData {
    Bytes(Bytes),
    Incoming(Incoming),
}

/// api接口参数类型
pub struct HttpContext {
    /// http请求头
    pub parts: Parts,
    /// 请求体，请求体不是json或表单格式，需要用户手动获取内容
    pub body: BodyData,
    /// 请求路径所匹配的接口地址的长度
    pub match_path_len: u32,
    /// 上下文路径长度
    pub context_path_len: u32,
    /// 客户端地址及端口
    pub addr: SocketAddr,
    /// 请求id(每个请求的id唯一)
    pub id: u32,
    /// 当前登录用户ID (从token中解析, 如果尚未登录，则为空字符串)
    pub uid: CompactString,
    /// 附加属性(用户自定义属性)
    pub attrs: HttpCtxAttrs,
}

impl HttpContext {
    /// 读取请求体内容到字节数组, 即body由Incoming转成Bytes
    pub async fn read_to_bytes(&mut self) -> Result<()> {
        if let BodyData::Incoming(incoming) = &mut self.body {
            let body = incoming.collect().await?.to_bytes();
            let mut body = BodyData::Bytes(body);
            std::mem::swap(&mut self.body, &mut body);
        }
        Ok(())
    }

    /// 获取请求体的incoming对象并返回，body中以0长度Bytes替代
    pub fn take_incoming(&mut self) -> Option<Incoming> {
        if let BodyData::Incoming(_) = &self.body {
            let mut empty = BodyData::Bytes(Bytes::new());
            std::mem::swap(&mut self.body, &mut empty);
            if let BodyData::Incoming(incoming) = empty {
                return Some(incoming);
            }
        }
        None
    }

    /// 检查请求的`Content-Type`是否是`application/json`
    pub fn is_json(&self) -> bool {
        self.is_content_type(APPLICATION_JSON_PREFIX)
    }

    /// 检查请求的`Content-Type`是否是`application/x-www-form-urlencoded`
    pub fn is_form_urlencoded(&self) -> bool {
        self.is_content_type(APPLICATION_FORM_SUFFIX)
    }

    /// Asynchronous parsing of the body content of HTTP requests from JSON format
    ///
    /// Returns:
    ///
    /// **Ok(val)**: body parse success
    ///
    /// **Err(e)**: parse error
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, HttpResponse, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> HttpResponse {
    ///     let req_param = ctx.parse_json::<ReqParam>()?;
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub async fn parse_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        match self.parse_json_opt().await? {
            Some(v) => Ok(v),
            #[cfg(not(feature = "english"))]
            None => http_bail!("缺省请求参数"),
            #[cfg(feature = "english")]
            None => http_bail!("required body"),
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests from JSON format,
    ///
    /// Returns:
    ///
    /// **Ok(Some(val))**: parse body success
    ///
    /// **Ok(None)**: body is empty
    ///
    /// **Err(e)**: parse error
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, HttpResponse, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> HttpResponse {
    ///     let req_param = ctx.parse_json_opt::<ReqParam>()?;
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub async fn parse_json_opt<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        #[cfg(not(feature = "english"))]
        const MISSING_FIELD: &str = "missing field `";

        if !self.is_json() {
            #[cfg(not(feature = "english"))]
            http_bail!("请求必须是 application/json 格式");
            #[cfg(feature = "english")]
            http_bail!("the request must be in application/json format")
        }

        let body = self.body_as_bytes().await?;
        if body.is_empty() {
            return Ok(None);
        }

        match serde_json::from_slice(body) {
            Ok(v) => Ok(Some(v)),
            #[cfg(not(feature = "english"))]
            Err(e) => {
                log::error!("json反序列化请求参数失败: {e:?}");
                let mut emsg = e.to_string();
                if emsg.starts_with(MISSING_FIELD) {
                    let s = &emsg[MISSING_FIELD.len()..];
                    if let Some(pos) = s.find('`') {
                        emsg = format!("字段{}不能为空", &s[..pos]);
                    }
                }
                Err(HttpError::new_with_source(emsg, e))
            }
            #[cfg(feature = "english")]
            Err(e) => {
                log::error!("deserialize body to json fail: {e:?}");
                Err(HttpError::new_with_source(e.to_string(), e))
            }
        }
    }

    pub async fn parse_json_fast(&mut self) -> Result<GValue> {
        if !self.is_json() {
            #[cfg(not(feature = "english"))]
            http_bail!("请求必须是 application/json 格式");
            #[cfg(feature = "english")]
            http_bail!("the request must be in application/json format");
        }

        let bytes = self.body_as_bytes().await?;
        if bytes.is_empty() {
            return Ok(GValue::default());
        }

        match std::str::from_utf8(bytes) {
            Ok(s) => Ok(gjson::parse(s)),
            Err(_) => {
                #[cfg(not(feature = "english"))]
                http_bail!("请求体不是有效的utf8字符串");
                #[cfg(feature = "english")]
                http_bail!("request body is not utf8 string");
            }
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded,
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, HttpResponse, Resp};
    ///
    /// async fn login(ctx: HttpContext) -> HttpResponse {
    ///     let params = ctx.parse_form();
    ///     println!("params.user = {}", params.get("user").unwrap())
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub async fn parse_form(&mut self) -> Result<FormParamMap> {
        if !self.is_form_urlencoded() {
            #[cfg(not(feature = "english"))]
            http_bail!("请求必须是 application/x-www-form-urlencoded 格式");
            #[cfg(feature = "english")]
            http_bail!("the request must be in application/x-www-form-urlencoded format")
        }

        let bytes = self.body_as_bytes().await?;
        if bytes.is_empty() {
            return Ok(FormParamMap::new());
        }

        Ok(parse_form_params_with(&bytes))
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded,
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, HttpResponse, Resp};
    ///
    /// async fn login(ctx: HttpContext) -> HttpResponse {
    ///     let params = ctx.parse_query();
    ///     println!("params.user = {}", params.get("user").unwrap())
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub fn parse_query(&self) -> FormParamMap {
        parse_form_params_with(self.parts.uri.query().unwrap_or("").as_bytes())
    }

    /// 获取在url路径中指定位置的参数值（已做urldecode解码）
    ///
    /// * `index`: 参数位置索引，从0开始
    ///
    /// # Examples
    /// ```
    /// use httpserver::HttpContext;
    ///
    /// async fn handle(ctx: HttpContext) {
    ///     let id = ctx.get_path_param(0).unwrap();
    /// }
    pub fn get_path_param(&self, index: usize) -> Option<Cow<'_, str>> {
        get_path_param(index, self.parts.uri.path(), self.match_path_len)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param<T: FromStr>(&self, key: &str) -> Result<Option<T>> {
        get_param(self.parts.uri.query().unwrap_or("").as_bytes(), key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param_str<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        match self.parts.uri.query() {
            Some(query) => get_param_str(query.as_bytes(), key),
            None => None,
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded query,
    pub async fn get_form_param<T: FromStr>(&mut self, key: &str) -> Result<Option<T>> {
        let bytes = self.body_as_bytes().await?;
        if_else!(!bytes.is_empty(), get_param(bytes, key), Ok(None))
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub async fn get_form_param_str<'a>(&'a mut self, key: &str) -> Result<Option<Cow<'a, str>>> {
        let body = self.body_as_bytes().await?;
        Ok(if_else!(!body.is_empty(), get_param_str(body, key), None))
    }

    /// 从多个地方尝试获取指定参数，优先级为 body > url_query > url_path
    ///
    /// Arguments:
    ///
    /// * `name`: 参数名称
    /// * `path_idx`: 参数在url_path中的位置, None时忽略从path中读取
    pub async fn get_param_from_multi(
        &mut self,
        name: &str,
        path_idx: Option<usize>,
    ) -> Result<Option<CompactString>> {
        let body = self.body_as_bytes().await?.clone();

        // 首先从body中读取值，如果有，直接返回
        if !body.is_empty() {
            if self.is_json() {
                if let Ok(body) = std::str::from_utf8(&body) {
                    let gvalue = gjson::get(body, name);
                    if gvalue.exists() {
                        return Ok(Some(CompactString::new(gvalue.str())));
                    }
                }
            } else if self.is_form_urlencoded() {
                let value = get_param_str(&body, name);
                if value.is_some() {
                    return Ok(value.map(CompactString::new));
                }
            }
        }

        // 其次，从url参数中取值，如果有，直接返回
        let value = self.get_url_param_str(name);
        if value.is_some() {
            return Ok(value.map(CompactString::new));
        }

        // 最后，从path参数中取值，如果有，直接返回
        if let Some(idx) = path_idx {
            let value = self.get_path_param(idx);
            if value.is_some() {
                return Ok(value.map(CompactString::new));
            }
        }
        // 都找不到，返回None
        Ok(None)
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        get_remote_ip(&self.parts.headers, &self.addr)
    }

    /// 获取请求的uri
    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// 获取http头部
    pub fn headers<'a>(&self) -> &HeaderMap<HeaderValue> {
        &self.parts.headers
    }

    /// 获取指定键的http头部变量
    pub fn header<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        get_header(&self.parts.headers, key)
    }

    /// 获取自定义参数
    pub fn attr<T: Any + Send + Sync>(&self, key: &str) -> Option<&T> {
        for (k, v) in &self.attrs {
            if key == k {
                return v.downcast_ref::<T>();
            }
        }
        None
    }

    /// 设置自定义参数
    pub fn set_attr<T: Any + Send + Sync>(&mut self, key: &str, value: T) {
        let value = Box::new(value);
        for (k, v) in self.attrs.iter_mut() {
            if key == k {
                *v = value;
                return;
            }
        }

        self.attrs.push((CompactString::new(key), value));
    }

    /// 获取token中的用户id
    pub fn user_id(&self) -> u32 {
        match self.uid.parse() {
            Ok(n) => n,
            Err(_) => 0,
        }
    }

    /// 判断content-type是否与指定值匹配
    pub fn is_content_type(&self, content_type: &str) -> bool {
        if let Some(value) = self.parts.headers.get(CONTENT_TYPE) {
            value.as_bytes().starts_with(content_type.as_bytes())
        } else {
            false
        }
    }

    async fn body_as_bytes(&mut self) -> Result<&Bytes> {
        self.read_to_bytes().await?;
        match &self.body {
            BodyData::Bytes(bytes) => Ok(bytes),
            BodyData::Incoming(_) => unsafe { hint::unreachable_unchecked() },
        }
    }
}

/// websocket function param
#[cfg(feature = "websocket")]
pub struct WsContext {
    /// http request object
    pub req: crate::WsRequest,
    /// match path length
    pub path_len: u32,
    /// http request client ip address
    pub addr: SocketAddr,
    /// http request ID (each request ID is unique)
    pub id: u32,
    pub websocket: hyper_tungstenite::HyperWebsocket,
}

#[cfg(feature = "websocket")]
impl WsContext {
    /// ```
    pub fn parse_query(&self) -> FormParamMap {
        parse_form_params_with(self.req.uri.query().unwrap_or("").as_bytes())
    }

    /// 获取在url路径中指定位置的参数值（已做urldecode解码）
    ///
    /// * `index`: 参数位置索引，从0开始
    ///
    /// # Examples
    /// ```
    /// use httpserver::HttpContext;
    ///
    /// async fn handle(ctx: HttpContext) {
    ///     let id = ctx.get_path_param(0).unwrap();
    /// }
    pub fn get_path_param<'a>(&'a self, index: usize) -> Option<Cow<'a, str>> {
        get_path_param(index, self.req.uri.path(), self.path_len)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param<T: FromStr>(&self, key: &str) -> Result<Option<T>> {
        get_param(self.req.uri.query().unwrap_or("").as_bytes(), key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param_str<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        match self.req.uri.query() {
            Some(query) => get_param_str(query.as_bytes(), key),
            None => None,
        }
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        get_remote_ip(&self.req.headers, &self.addr)
    }

    /// 获取http头部
    pub fn header<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        get_header(&self.req.headers, key)
    }
}

fn parse_form_params_with(data: &[u8]) -> FormParamMap {
    let mut result = FormParamMap::new();
    if !data.is_empty() {
        for (k, v) in form_urlencoded::parse(data) {
            result.insert(k, v);
        }
    }

    result
}

fn get_param<T: FromStr>(data: &[u8], key: &str) -> Result<Option<T>> {
    for (k, v) in form_urlencoded::parse(data) {
        if k.as_ref() == key {
            match v.parse() {
                Ok(v) => return Ok(Some(v)),
                Err(_) => {
                    #[cfg(not(feature = "english"))]
                    http_bail!("{} 格式错误", key);
                    #[cfg(feature = "english")]
                    http_bail!("{} format error", key);
                }
            }
        }
    }
    Ok(None)
}

fn get_param_str<'a>(data: &'a [u8], key: &str) -> Option<Cow<'a, str>> {
    for (k, v) in form_urlencoded::parse(data) {
        if &k == key {
            return Some(v);
        }
    }
    None
}

fn get_path_param<'a>(index: usize, path: &'a str, path_len: u32) -> Option<Cow<'a, str>> {
    if path_len > 0 {
        let vars = &path[path_len as usize..];
        if let Some(val_str) = vars.split('/').skip(index).next() {
            match urlencoding::decode(val_str) {
                Ok(val) => {
                    return match val.find('+') {
                        Some(_) => Some(Cow::Owned(val.replace('+', " "))),
                        None => Some(val),
                    }
                }
                Err(e) => log::error!("url decode value error: {e:?}"),
            }
        }
    }

    None
}

/// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
fn get_remote_ip(headers: &HeaderMap<HeaderValue>, addr: &SocketAddr) -> Ipv4Addr {
    if let Some(ip) = headers.get("X-Real-IP") {
        if let Ok(ip) = ip.to_str() {
            if let Ok(ip) = ip.parse() {
                return ip;
            }
        }
    }

    if let Some(ip) = headers.get("X-Forwarded-For") {
        if let Ok(ip) = ip.to_str() {
            if let Some(ip) = ip.split(',').next() {
                if let Ok(ip) = ip.parse() {
                    return ip;
                }
            }
        }
    }

    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => std::net::Ipv4Addr::new(0, 0, 0, 0),
    }
}

/// 获取http头部
fn get_header<'a>(headers: &'a HeaderMap<HeaderValue>, key: &str) -> Option<Cow<'a, str>> {
    match headers.get(key) {
        Some(s) => match s.to_str() {
            Ok(s) => Some(Cow::Borrowed(s)),
            Err(_) => {
                #[cfg(not(feature = "english"))]
                log::warn!("请求头:{} 的值不是ascii字符串", key);
                #[cfg(feature = "english")]
                log::warn!("header key:{} is not a ascii string", key);
                None
            }
        },
        None => None,
    }
}
