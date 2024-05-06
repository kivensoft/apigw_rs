use compact_str::CompactString;
use cookie::Cookie;
use httpserver::{log_trace, log_warn, HttpContext, HttpResponse, Next};
use hyper::http::HeaderValue;
use serde_json::Value;
use std::{borrow::Cow, time::Duration};
use triomphe::Arc;

const ACCESS_TOKEN: &str = "access_token";
const COOKIE_NAME: &str = "Cookie";
const TOKEN_VERIFIED: &str = "X-Token-Verified";

type Cache<K, V> = mini_moka::sync::Cache<K, V>;

pub struct Authentication {
    key: CompactString,
    iss: CompactString,
    token_cache: Cache<String, Arc<Value>>,
}

impl Authentication {
    /// create Authentication object
    ///
    /// * `key`: jwt签名密钥
    /// * `issuer` jwt签发者
    /// * `cache_size` 签名校验缓存允许的最大条目
    /// * `cache_ttl` 签名校验缓存项的最大生存时间(单位：秒)
    ///
    pub fn new(key: &str, issuer: &str, cache_size: u64, cache_ttl: u32) -> Self {
        Authentication {
            key: CompactString::new(key),
            iss: CompactString::new(issuer),
            token_cache: mini_moka::sync::Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(Duration::from_secs(cache_ttl as u64))
                .build(),
        }
    }

    /// 校验jwt token
    fn verify_token(&self, token: &str, req_id: u32) -> bool {
        // 获取token的签名值
        let sign = match jwt::get_sign(token) {
            Some(sign) => sign.to_owned(),
            None => {
                log_warn!(req_id, "jwt token format error: can't find sign of {}", token);
                return false;
            }
        };

        // 优先从缓存中读取签名，减少解密次数
        if let Some(claims) = self.token_cache.get(&sign) {
            return match jwt::check_exp(&claims) {
                Ok(_) => {
                    // 需要校验发行者
                    if !self.iss.is_empty() {
                        if let Err(e) = jwt::check_issuer(&claims, &self.iss) {
                            log_warn!(req_id, "jwt check issuer fail: {:?}", e);
                            return false;
                        }
                    }
                    true
                }
                Err(_) => {
                    log_warn!(req_id, "jwt token expired");
                    false
                }
            }
        }

        // 缓存中没有，进行验证步骤，并将解析的claims缓存起来
        match jwt::decode(token, &self.key, &self.iss) {
            Ok(claims) => {
                self.token_cache.insert(sign, Arc::new(claims));
                true
            }
            Err(e) => {
                log_warn!(req_id, "jwt token decode error: {e:?}");
                false
            }
        }
    }

    /// 解析返回jwt token字符串
    fn get_token(ctx: &HttpContext) -> Option<Cow<str>> {
        match ctx.req.headers().get(jwt::AUTHORIZATION) {
            Some(auth) => match auth.to_str() {
                Ok(auth) => {
                    if auth.len() > jwt::BEARER.len() && auth.starts_with(jwt::BEARER) {
                        Some(Cow::Borrowed(&auth[jwt::BEARER.len()..]))
                    } else {
                        log_trace!(ctx.id, "Authorization is not jwt token");
                        None
                    }
                }
                Err(e) => {
                    log_warn!(ctx.id, "Authorization value is invalid: {:?}", e);
                    None
                }
            },
            None => Self::get_access_token(ctx),
        }
    }

    /// 从url参数或cookie中解析access_token
    fn get_access_token(ctx: &HttpContext) -> Option<Cow<str>> {
        // 优先从url中获取access_token参数
        if let Some(query) = ctx.req.uri().query() {
            let mut parse = form_urlencoded::parse(query.as_bytes());
            let token = parse
                .find(|(k, _)| k.as_ref() == ACCESS_TOKEN)
                .map(|(_, v)| v);

            if token.is_some() {
                return token;
            }
        };

        // url中找不到, 尝试从cookie中获取access_token
        if let Some(cookie_str) = ctx.req.headers().get(COOKIE_NAME) {
            let cookie_str = match cookie_str.to_str() {
                Ok(s) => s,
                Err(e) => {
                    log_warn!(ctx.id, "cookie value is not utf8 string: {:?}", e);
                    return None;
                }
            };

            for cookie in Cookie::split_parse_encoded(cookie_str) {
                match cookie {
                    Ok(item) => if item.name() == ACCESS_TOKEN {
                        return Some(Cow::Owned(String::from(item.value())));
                    }
                    Err(e) => {
                        log_warn!(ctx.id, "cookie value [{cookie_str}] parse encode error: {e:?}");
                        return None;
                    }
                }
            }
        }

        None
    }

}

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for Authentication {
    async fn handle<'a>(&'a self, mut ctx: HttpContext, next: Next<'a>,) -> HttpResponse {
        let mut verified = "false";
        // 解析token并进行校验，校验成功返回uid
        if let Some(token) = Self::get_token(&ctx) {
            if self.verify_token(&token, ctx.id) {
                verified = "true";
            }
        }
        // 添加头部标志，指明token校验是否成功
        ctx.req.headers_mut().append(TOKEN_VERIFIED, HeaderValue::from_static(verified));
        next.run(ctx).await
    }
}
