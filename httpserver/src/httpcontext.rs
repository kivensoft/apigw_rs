use std::{borrow::Cow, collections::HashMap, net::{Ipv4Addr, SocketAddr}, str::FromStr};

use anyhow::Result;
use compact_str::CompactString;
use fnv::FnvHashMap;
use hyper::{body::Bytes, header::{AsHeaderName, HeaderValue}};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{http_bail, log_error, HttpCtxAttrs, HttpError, Request, CONTENT_TYPE};


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
    pub uid: CompactString,
    /// additional attributes (user-defined)
    pub attrs: HttpCtxAttrs,
}

impl HttpContext {
    /// check request content type is application/json
    pub fn is_json(&self) -> bool {
        if let Some(s) = self.req.headers().get(CONTENT_TYPE) {
            s == "application/json"
        } else {
            false
        }
    }

    /// check request content type is application/x-www-form-urlencoded
    pub fn is_formd_urlencoded(&self) -> bool {
        if let Some(s) = self.req.headers().get(CONTENT_TYPE) {
            s == "application/x-www-form-urlencoded"
        } else {
            false
        }
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
    /// use httpserver::{HttpContext, Response, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_json::<ReqParam>().await?;
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
    /// use httpserver::{HttpContext, Response, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_option_json::<ReqParam>().await?;
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub fn parse_json_opt<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        #[cfg(not(feature = "english"))]
        const MISSING_FIELD: &str = "missing field `";

        let res = if !self.body.is_empty() {
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
                    return HttpError::result_with_source(emsg, e);
                }
                #[cfg(feature = "english")]
                Err(e) => {
                    log_error!(self.id, "deserialize body to json fail: {e:?}");
                    return HttpError::result_with_source(e.to_string(), e);
                }
            }
        } else {
            None
        };

        Ok(res)
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded,
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::HttpContext;
    ///
    /// fn parse(ctx: HttpContext) -> HashMap<String, String> {
    ///     ctx.parse_formdata(String::from)
    /// }
    /// ```
    pub fn parse_formdata(&self) -> FnvHashMap<CompactString, Vec<CompactString>> {
        Self::parse_params(&self.body)
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded,
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::HttpContext;
    ///
    /// fn parse(ctx: HttpContext) -> HashMap<String, String> {
    ///     let map = ctx.parse_query(String::from)
    ///         .map(|(k, v)| (k.to_string(), v.to_string()))
    ///         .collect::HashMap<String, String>()
    /// }
    /// ```
    pub fn parse_query(&self) -> FnvHashMap<CompactString, Vec<CompactString>> {
        Self::parse_params(self.req.uri().query().unwrap_or("").as_bytes())
    }

    /// 获取在url路径中指定位置的参数值（已做urldecode解码）
    ///
    /// * `index`: 参数位置索引，从0开始
    ///
    /// # Examples
    /// ```
    /// use httpserver::HttpContext;
    ///
    /// fn handle(ctx: HttpContext) {
    ///     let id = ctx.get_path_val(0).unwrap();
    /// }
    pub fn get_path_val<'a>(&'a self, index: usize) -> Option<Cow<'a, str>> {
        if self.path_len > 0 {
            let vars = &self.req.uri().path()[self.path_len as usize..];
            if let Some(val_str) = vars.split('/').skip(index).next() {
                match urlencoding::decode(val_str) {
                    Ok(val) => return match val.find('+') {
                        Some(_) => Some(Cow::Owned(val.replace('+', " "))),
                        None => Some(val),
                    },
                    Err(e) => log_error!(self.id, "url decode value error: {e:?}")
                }
            }
        }

        None
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param<K: AsRef<str>, V: FromStr>(&self, key: K) -> Result<Option<V>> {
        Self::get_param(self.req.uri().query().unwrap_or("").as_bytes(), key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_url_param_str<'a, K: AsRef<str>>(&'a self, key: K) -> Option<Cow<'a, str>> {
        match self.req.uri().query() {
            Some(query) => Self::get_param_str(query.as_bytes(), key),
            None => None
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests from x-www-form-urlencoded query,
    pub fn get_formdata_param<K: AsRef<str>, V: FromStr>(&self, key: K) -> Result<Option<V>> {
        Self::get_param(&self.body, key)
    }

    /// Asynchronous parsing of the body content of HTTP requests from url query,
    pub fn get_formdata_param_str<'a, K: AsRef<str>>(&'a self, key: K) -> Option<Cow<'a, str>> {
        if !self.body.is_empty() {
            Self::get_param_str(&self.body, key)
        } else {
            None
        }
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        if let Some(ip) = self.req.headers().get("X-Real-IP") {
            if let Ok(ip) = ip.to_str() {
                if let Ok(ip) = ip.parse() {
                    return ip;
                }
            }
        }

        if let Some(ip) = self.req.headers().get("X-Forwarded-For") {
            if let Ok(ip) = ip.to_str() {
                if let Some(ip) = ip.split(',').next() {
                    if let Ok(ip) = ip.parse() {
                        return ip;
                    }
                }
            }
        }

        match self.addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => std::net::Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    /// 获取http头部
    pub fn header<K: AsHeaderName>(&self, key: K) -> Option<&HeaderValue> {
        self.req.headers().get(key)
    }

    /// 获取自定义参数
    pub fn attr<'a>(&'a self, key: &str) -> Option<&'a Value> {
        match &self.attrs {
            Some(atrr) => atrr.get(key),
            None => None,
        }
    }

    /// 设置自定义参数
    pub fn set_attr<T: Into<Value>>(&mut self, key: CompactString, value: T) {
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

    fn parse_params(data: &[u8]) -> FnvHashMap<CompactString, Vec<CompactString>> {
        let mut result = FnvHashMap::<CompactString, Vec<CompactString>>::default();
        for (k, v) in form_urlencoded::parse(data) {
            let val = result.get_mut(k.as_ref());
            if let Some(val) = val {
                val.push(CompactString::new(&v));
            } else {
                result.insert(CompactString::new(&k), vec![CompactString::new(&v)]);
            }
        }

        result
    }

    fn get_param<K: AsRef<str>, V: FromStr>(data: &[u8], key: K) -> Result<Option<V>> {
        let kref = key.as_ref();
        for (k, v) in form_urlencoded::parse(data) {
            if &k == kref {
                match v.parse() {
                    Ok(v) => return Ok(Some(v)),
                    Err(_) => {
                        #[cfg(not(feature = "english"))]
                        http_bail!("{} 格式错误", kref);
                        #[cfg(feature = "english")]
                        http_bail!("{} format error", kref);
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_param_str<'a, K: AsRef<str>>(data: &'a [u8], key: K) -> Option<Cow<'a, str>> {
        let kref = key.as_ref();
        for (k, v) in form_urlencoded::parse(data) {
            if &k == kref {
                return Some(v);
            }
        }
        None
    }

}
