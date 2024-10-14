use cookie::Cookie;
use httpserver::{log_debug, log_trace, log_warn, HttpContext, HttpResponse, Next};
use hyper::http::HeaderValue;
use serde_json::Value;
use tokio::task;
use std::{borrow::Cow, fmt::Write, time::Duration};
use triomphe::Arc;

use crate::{redis, AppConf, AppGlobal};

const ACCESS_TOKEN: &str = "access_token";
const COOKIE_NAME: &str = "Cookie";
const TOKEN_VERIFIED: &str = "X-Token-Verified";
pub const LOGIN_KEY: &str = "login";
pub const LOGOUT_KEY: &str = "logout";

type Cache<K, V> = mini_moka::sync::Cache<K, V>;

pub struct Authentication {
    key: String,
    iss: String,
    token_cache: Cache<String, Arc<Value>>,
}

impl Authentication {
    /// 创建认证对象
    ///
    /// * `key`: jwt签名密钥
    /// * `issuer` jwt签发者
    /// * `cache_size` 签名校验缓存允许的最大条目
    /// * `cache_ttl` 签名校验缓存项的最大生存时间(单位：秒)
    ///
    pub fn new(key: &str, issuer: &str, cache_size: u64, cache_ttl: u32) -> Self {
        Authentication {
            key: String::from(key),
            iss: String::from(issuer),
            token_cache: mini_moka::sync::Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(Duration::from_secs(cache_ttl as u64))
                .build(),
        }
    }

    /// 校验jwt token
    ///
    /// * `token`: jwt令牌
    /// * `req_id` 请求id
    ///
    async fn verify_token(&self, token: &str, req_id: u32) -> bool {
        // 获取token的签名值
        let sign = match jwt::get_sign(token) {
            Some(sign) => sign.to_owned(),
            None => {
                log_warn!(req_id, "jwt token format error: can't find sign of {}", token);
                return false;
            }
        };

        // 判断是否在黑名单中
        if is_blacklist(&sign).await {
            log_debug!(req_id, "jwt token is in blacklist: {}", token);
            return false;
        }

        // 优先从本地缓存及redis缓存中读取签名，减少解密次数
        let claims = match self.token_cache.get(&sign) {
            Some(v) => Some(v),
            None => match load_from_redis(&sign).await {
                Some(v) => {
                    self.token_cache.insert(sign.clone(), v.clone());
                    Some(v)
                }
                None => None,
            }
        };

        // 判断token是否过期
        if let Some(claims) = claims {
            return match jwt::check_exp(&claims) {
                Ok(_) => true,
                Err(_) => {
                    self.token_cache.invalidate(&sign);
                    delete_from_redis(&sign);
                    log_warn!(req_id, "jwt token expired");
                    false
                }
            }
        }

        // 缓存中没有，进行验证步骤，并将解析的claims缓存起来
        match jwt::decode(token, &self.key, &self.iss) {
            Ok(claims) => {
                save_to_redis(&sign, &claims);
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
            if self.verify_token(&token, ctx.id).await {
                verified = "true";
            }
        }
        // 添加头部标志，指明token校验是否成功
        ctx.req.headers_mut().append(TOKEN_VERIFIED, HeaderValue::from_static(verified));
        next.run(ctx).await
    }
}

/// 判断token是否在黑名单中（用户已更新token或者用户已被删除或者已退出登录）
async fn is_blacklist(sign: &str) -> bool {
    let ac = AppConf::get();
    if !ac.redis_host.is_empty() {
        let mut key = String::with_capacity(128);
        write!(key, "{}:{}:{}", ac.redis_prefix, LOGOUT_KEY, sign).unwrap();

        if redis::get(&key).await.unwrap_or(None).is_some() {
            return true;
        }
    }

    false
}

/// 从redis中加载签名对应的信息
async fn load_from_redis(sign: &str) -> Option<Arc<Value>> {
    if AppConf::get().redis_host.is_empty() {
        return None;
    }

    let key = gen_redis_key(sign);

    let value: String = match redis::get(&key).await.unwrap_or(None) {
        Some(v) => v,
        None => return None,
    };

    let claims: Arc<Value> = match serde_json::from_str(&value) {
        Ok(v) => v,
        Err(e) => {
            log::error!("parse token from redis error: {:?}, token = {}", e, value);
            return None;
        }
    };

    Some(claims)
}

/// 保存签名对应的信息到redis(异步方式保存)
fn save_to_redis(sign: &str, claims: &Value) {
    if AppConf::get().redis_host.is_empty() {
        return;
    }

    let key = gen_redis_key(sign);
    match serde_json::to_string(claims) {
        Ok(value) => {
            task::spawn(async move {
                let (k, v) = (key, value);
                let ttl = AppGlobal::get().redis_ttl as u32;
                if let Err(e) = redis::set(&k, &v, ttl).await {
                    log::error!("save_to_redis error: {}", e);
                }
            });
        }
        Err(e) => {
            log::error!("serialize token to json error: {:?}", e);
        }
    };
}

/// 从redis删除签名对应的信息(异步方式删除)
fn delete_from_redis(sign: &str) {
    if AppConf::get().redis_host.is_empty() {
        return;
    }

    let key = gen_redis_key(sign);
    task::spawn(async move {
        let k = key;
        if let Err(e) = redis::del(&k).await {
            log::error!("redis delete key {} error: {:?}", k, e);
        }
    });
}

fn gen_redis_key(sign: &str) -> String {
    let mut key = String::with_capacity(128);
    write!(key, "{}:{}:{}", AppConf::get().redis_prefix, LOGIN_KEY, sign).unwrap();
    key
}
