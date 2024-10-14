use std::{borrow::Cow, collections::HashMap, net::{Ipv4Addr, SocketAddr}, str::FromStr};

use anyhow::Result;
use http::{HeaderMap, HeaderValue};
use hyper::body::Bytes;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{http_bail, log_error, log_warn, HttpError, Request, CONTENT_TYPE};

pub type GKind = gjson::Kind;
pub type GValue<'a> = gjson::Value<'a>;
type FormParamMap<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;
type HttpCtxAttrs = Option<HashMap<String, Value>>;

const APPLICATION_JSON: &str = "application/json";
const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// api function param
pub struct HttpContext {
    /// http request object
    pub req: Request,
    /// http request body
    pub body: Bytes,
    /// match path length
    pub path_len: u32,
    /// http request client ip address
    pub addr: SocketAddr,
    /// http request ID (each request ID is unique)
    pub id: u32,
    /// current login user ID (parsed from token, not logged in is empty)
    pub uid: String,
    /// additional attributes (user-defined)
    pub attrs: HttpCtxAttrs,
}

impl HttpContext {
    /// check request content type is application/json
    pub fn is_json(&self) -> bool {
        !self.body.is_empty() && self.is_content_type(APPLICATION_JSON)
    }

    /// check request content type is application/x-www-form-urlencoded
    pub fn is_form_urlencoded(&self) -> bool {
        !self.body.is_empty() && self.is_content_type(FORM_URLENCODED)
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
    pub fn parse_json<T: DeserializeOwned>(&self) -> Result<T> {
        match self.parse_json_opt()? {
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
    pub fn parse_json_opt<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        #[cfg(not(feature = "english"))]
        const MISSING_FIELD: &str = "missing field `";

        let res = if !self.body.is_empty() {
            if self.is_json() {
                match serde_json::from_slice(&self.body) {
                    Ok(v) => Some(v),
                    #[cfg(not(feature = "english"))]
                    Err(e) => {
                        log_error!(self.id, "json反序列化请求参数失败: {e:?}");
                        let mut emsg = e.to_string();
                        if emsg.starts_with(MISSING_FIELD) {
                            let s = &emsg[MISSING_FIELD.len()..];
                            if let Some(pos) = s.find('`') {
                                emsg = format!("字段{}不能为空", &s[..pos]);
                            }
                        }
                        return Err(HttpError::new_with_source(emsg, e));
                    }
                    #[cfg(feature = "english")]
                    Err(e) => {
                        log_error!(self.id, "deserialize body to json fail: {e:?}");
                        return Err(HttpError::new_with_source(e.to_string(), e));
                    }
                }
            } else {
                #[cfg(not(feature = "english"))]
                http_bail!("请求必须是 application/json 格式");
                #[cfg(feature = "english")]
                http_bail!("the request must be in application/json format")
            }
        } else {
            None
        };

        Ok(res)
    }

    pub fn parse_json_fast<'a>(&'a self) -> Result<GValue<'a>> {
        if self.is_json() {
            match std::str::from_utf8(&self.body) {
                Ok(s) => {
                    if gjson::valid(s) {
                        Ok(gjson::parse(s))
                    } else {
                        #[cfg(not(feature = "english"))]
                        http_bail!("请求体不是有效的json字符串");
                        #[cfg(feature = "english")]
                        http_bail!("request body is not json string");
                    }
                }
                Err(_) => {
                    #[cfg(not(feature = "english"))]
                    http_bail!("请求体不是有效的utf8字符串");
                    #[cfg(feature = "english")]
                    http_bail!("request body is not utf8 string");
                }
            }
        } else {
            #[cfg(not(feature = "english"))]
            http_bail!("请求必须是 application/json 格式");
            #[cfg(feature = "english")]
            http_bail!("the request must be in application/json format");
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
    pub fn parse_form(&self) -> Result<FormParamMap> {
        if self.is_form_urlencoded() {
            Ok(Self::parse_form_params_with(&self.body))
        } else {
            #[cfg(not(feature = "english"))]
            http_bail!("请求必须是 application/x-www-form-urlencoded 格式");
            #[cfg(feature = "english")]
            http_bail!("the request must be in application/x-www-form-urlencoded format")
        }
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
        Self::parse_form_params_with(self.req.uri().query().unwrap_or("").as_bytes())
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
        Self::pri_get_path_param(index, self.req.uri().path(), self.path_len, self.id)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param<T: FromStr>(&self, key: &str) -> Result<Option<T>> {
        Self::get_param(self.req.uri().query().unwrap_or("").as_bytes(), key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param_str<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        match self.req.uri().query() {
            Some(query) => Self::get_param_str(query.as_bytes(), key),
            None => None
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded query,
    pub fn get_form_param<T: FromStr>(&self, key: &str) -> Result<Option<T>> {
        Self::get_param(&self.body, key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_form_param_str<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        if !self.body.is_empty() {
            Self::get_param_str(&self.body, key)
        } else {
            None
        }
    }

    /// 从多个地方尝试获取指定参数，优先级为 body > url_query > url_path
    ///
    /// Arguments:
    ///
    /// * `name`: 参数名称
    /// * `idx`: 参数在url_path中的位置, None时忽略从path中读取
    pub fn get_param_from_multi<'a>(&'a self, name: &'a str, idx: Option<usize>) -> Option<Cow<'a, str>> {
        if self.is_json() {
            match std::str::from_utf8(&self.body) {
                Ok(body) => {
                    let val: gjson::Value<'a> = gjson::get(body, name);
                    if val.exists() {
                        return Some(Cow::Owned(val.str().to_owned()));
                    }
                }
                Err(_) => log_warn!(self.id, "request body is not utf8 string")
            }
        }

        if self.is_form_urlencoded() {
            if let Some(val) = Self::get_param_str(&self.body, name) {
                return Some(val);
            }
        }

        if let Some(val) = self.get_url_param_str(name) {
            return Some(val);
        }

        match idx {
            Some(idx) => self.get_path_param(idx),
            None => None,
        }
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        Self::pri_remote_ip(&self.req.headers(), &self.addr)
    }

    /// 获取http头部
    pub fn header<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        Self::pri_header(self.id, &self.req.headers(), key)
    }

    /// 获取自定义参数
    pub fn attr<'a>(&'a self, key: &str) -> Option<&'a Value> {
        match &self.attrs {
            Some(atrr) => atrr.get(key),
            None => None,
        }
    }

    /// 设置自定义参数
    pub fn set_attr<T: Into<Value>>(&mut self, key: String, value: T) {
        if self.attrs.is_none() {
            self.attrs = Some(HashMap::default());
        }
        self.attrs.as_mut().unwrap().insert(key, value.into());
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
        if let Some(s) = self.req.headers().get(CONTENT_TYPE) {
            s.as_bytes().starts_with(content_type.as_bytes())
        } else {
            false
        }
    }

    pub(self) fn parse_form_params_with(data: &[u8]) -> FormParamMap {
        let mut result = FormParamMap::new();
        if !data.is_empty() {
            for (k, v) in form_urlencoded::parse(data) {
                result.insert(k, v);
            }
        }

        result
    }

    pub(self) fn get_param<T: FromStr>(data: &[u8], key: &str) -> Result<Option<T>> {
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

    pub(self) fn get_param_str<'a>(data: &'a [u8], key: &str) -> Option<Cow<'a, str>> {
        for (k, v) in form_urlencoded::parse(data) {
            if &k == key {
                return Some(v);
            }
        }
        None
    }

    pub(self) fn pri_get_path_param<'a>(index: usize, path: &'a str, path_len: u32, id: u32) -> Option<Cow<'a, str>> {
        if path_len > 0 {
            let vars = &path[path_len as usize..];
            if let Some(val_str) = vars.split('/').skip(index).next() {
                match urlencoding::decode(val_str) {
                    Ok(val) => return match val.find('+') {
                        Some(_) => Some(Cow::Owned(val.replace('+', " "))),
                        None => Some(val),
                    },
                    Err(e) => log_error!(id, "url decode value error: {e:?}")
                }
            }
        }

        None
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub(self) fn pri_remote_ip(headers: &HeaderMap<HeaderValue>, addr: &SocketAddr) -> Ipv4Addr {
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
    pub(self) fn pri_header<'a>(id: u32, headers: &'a HeaderMap<HeaderValue>, key: &str) -> Option<Cow<'a, str>> {
        match headers.get(key) {
            Some(s) => match s.to_str() {
                Ok(s) => Some(Cow::Borrowed(s)),
                Err(_) => {
                    #[cfg(not(feature = "english"))]
                    log_warn!(id, "header key:{} is not a ascii string", key);
                    #[cfg(feature = "english")]
                    log_warn!(id, "请求头:{} 的值不是ascii字符串", key);
                    None
                }
            }
            None => None,
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
        HttpContext::parse_form_params_with(self.req.uri.query().unwrap_or("").as_bytes())
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
        HttpContext::pri_get_path_param(index, self.req.uri.path(), self.path_len, self.id)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param<T: FromStr>(&self, key: &str) -> Result<Option<T>> {
        HttpContext::get_param(self.req.uri.query().unwrap_or("").as_bytes(), key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param_str<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        match self.req.uri.query() {
            Some(query) => HttpContext::get_param_str(query.as_bytes(), key),
            None => None
        }
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        HttpContext::pri_remote_ip(&self.req.headers, &self.addr)
    }

    /// 获取http头部
    pub fn header<'a>(&'a self, key: &str) -> Option<Cow<'a, str>> {
        HttpContext::pri_header(self.id, &self.req.headers, key)
    }

}
