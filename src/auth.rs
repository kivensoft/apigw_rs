use compact_str::CompactString;
use cookie::Cookie;
use httpserver::{
    http_bail, log_error, HttpContext, HttpResponse, HttpResult, Next, ToHttpError
};
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
    fn verify_token(&self, token: &str) -> HttpResult<()> {
        // 获取token的签名值
        let sign = match jwt::get_sign(token) {
            Some(sign) => sign.to_owned(),
            None => http_bail!("jwt token format error: can't find '.'"),
        };

        // 优先从缓存中读取签名，减少解密次数
        if let Some(claims) = self.token_cache.get(&sign) {
            return match jwt::check_exp(&claims) {
                Ok(_) => {
                    if !self.iss.is_empty() {
                        match jwt::check_issuer(&claims, &self.iss) {
                            Ok(_) => Ok(()),
                            Err(_) => http_bail!("jwt token issuer error"),
                        }
                    } else {
                        Ok(())
                    }
                }
                Err(_) => http_bail!("jwt token expired"),
            }
        }

        // 缓存中没有，进行验证步骤，并将解析的claims缓存起来
        let claims = jwt::decode(token, &self.key, &self.iss).to_http_error()?;
        self.token_cache.insert(sign, Arc::new(claims));

        Ok(())
    }

    /// 解析返回jwt token字符串
    fn get_token(ctx: &HttpContext) -> HttpResult<Option<Cow<str>>> {
        match ctx.req.headers().get(jwt::AUTHORIZATION) {
            Some(auth) => match auth.to_str() {
                Ok(auth) => {
                    if auth.len() > jwt::BEARER.len() && auth.starts_with(jwt::BEARER) {
                        return Ok(Some(Cow::Borrowed(&auth[jwt::BEARER.len()..])));
                    } else {
                        http_bail!("Authorization is not jwt token")
                    }
                }
                Err(e) => http_bail!("Authorization value is invalid: {:?}", e),
            },
            None => Self::get_access_token(ctx),
        }
    }

    /// 从url参数或cookie中解析access_token
    fn get_access_token(ctx: &HttpContext) -> HttpResult<Option<Cow<str>>> {
        // 优先从url中获取access_token参数
        if let Some(query) = ctx.req.uri().query() {
            let mut parse = form_urlencoded::parse(query.as_bytes());
            let token = parse.find(|(k, _)| k.as_ref() == ACCESS_TOKEN).map(|(_, v)| v);
            if token.is_some() {
                return Ok(token);
            }
        };

        // url中找不到, 尝试从cookie中获取access_token
        if let Some(cookie_str) = ctx.req.headers().get(COOKIE_NAME) {
            let cookie_str = match cookie_str.to_str() {
                Ok(s) => s,
                Err(e) => http_bail!("cookie value is not utf8 string: {:?}", e)
            };
            for cookie in Cookie::split_parse_encoded(cookie_str) {
                match cookie {
                    Ok(c) => if c.name() == ACCESS_TOKEN {
                        return Ok(Some(Cow::Owned(c.value().to_owned())));
                    }
                    Err(e) => http_bail!("cookie value [{cookie_str}] parse encode error: {:?}", e),
                }
            }
        }

        Ok(None)
    }

}

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for Authentication {
    async fn handle<'a>(&'a self, mut ctx: HttpContext, next: Next<'a>,) -> HttpResponse {
        // 解析token并进行校验，校验成功返回uid
        if let Some(token) = Self::get_token(&ctx)? {
            let verified = match self.verify_token(&token) {
                Ok(_) => "true",
                Err(e) => {
                    log_error!(ctx.id, "AUTH verify token error: {:?}", e);
                    "false"
                },
            };
            // 添加头部标志，指明token校验是否成功
            ctx.req.headers_mut().append(TOKEN_VERIFIED, HeaderValue::from_static(verified));
        }
        next.run(ctx).await
    }
}
