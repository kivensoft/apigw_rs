use cookie::Cookie;
use httpserver::{HttpContext, HttpResponse, Next};
use hyper::http::HeaderValue;
use serde_json::Value;
use std::{borrow::Cow, sync::Arc, time::Duration};
use tokio::task;

use crate::{AppConf, db, redis};

type Cache<K, V> = mini_moka::sync::Cache<K, V>;

pub struct Authentication {
    key: String,
    iss: String,
    token_cache: Cache<String, Arc<Value>>,
}

const ACCESS_TOKEN: &str = "access_token";
const COOKIE_NAME: &str = "Cookie";
const TOKEN_VERIFIED: &str = "X-Token-Verified";
pub const CK_TOKEN: &str = "token";

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
    async fn verify_token(&self, token: &str) -> bool {
        // 获取token的签名值
        let sign = match jwt::get_sign(token) {
            Some(sign) => sign.to_owned(),
            None => {
                log::warn!("jwt token format error: can't find sign of {}", token);
                return false;
            }
        };

        // 判断是否在黑名单中
        if is_blacklist(&sign).await {
            log::debug!("jwt token is in blacklist: {}", token);
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
            },
        };

        // 判断token是否过期
        if let Some(claims) = claims {
            return match jwt::check_exp(&claims) {
                Ok(_) => true,
                Err(_) => {
                    log::warn!("jwt token expired");
                    false
                }
            };
        }

        // 缓存中没有，进行验证步骤，并将解析的claims缓存起来
        match jwt::decode(token, &self.key, &self.iss) {
            Ok(claims) => {
                save_to_redis(&sign, &claims);
                self.token_cache.insert(sign, Arc::new(claims));
                true
            }
            Err(e) => {
                log::warn!("jwt token decode error: {e:?}");
                false
            }
        }
    }

    /// 从HTTP请求上下文中获取令牌
    ///
    /// 尝试从请求头中获取JWT令牌，如果请求头中没有JWT令牌，
    /// 则尝试从其他地方获取访问令牌
    ///
    /// ### 参数
    ///
    /// * `ctx` - 一个HTTP请求上下文的引用，用于访问请求头和其他信息
    ///
    /// ### 返回值
    ///
    /// 如果找到有效的令牌，则返回Some(Cow<str>)，否则返回None
    fn get_token(ctx: &HttpContext) -> Option<Cow<str>> {
        // 尝试从请求头中获取AUTHORIZATION字段
        match ctx.headers().get(jwt::AUTHORIZATION) {
            // 如果成功获取到AUTHORIZATION字段
            Some(auth) => match auth.to_str() {
                // 将字段值转换为字符串
                Ok(auth) => {
                    // 检查令牌是否以"Bearer "开头，并且长度大于"Bearer "的长度
                    if auth.len() > jwt::BEARER.len() && auth.starts_with(jwt::BEARER) {
                        // 如果是，则返回令牌的剩余部分
                        Some(Cow::Borrowed(&auth[jwt::BEARER.len()..]))
                    } else {
                        // 如果不是，则记录日志并返回None
                        log::trace!("Authorization is not jwt token");
                        None
                    }
                }
                // 如果字段值转换为字符串失败，则记录错误并返回None
                Err(e) => {
                    log::warn!("Authorization value is invalid: {:?}", e);
                    None
                }
            },
            // 如果没有获取到AUTHORIZATION字段，则尝试从其他地方获取访问令牌
            None => Self::get_access_token(ctx),
        }
    }

    /// 从url参数或cookie中解析access_token
    ///
    /// ### 参数
    /// * `ctx`: HttpContext引用，用于访问HTTP请求的上下文信息
    ///
    /// ### 返回值
    /// * `Option<Cow<str>>`: 如果找到有效的access_token，则返回Some(Cow<str>)，否则返回None
    fn get_access_token(ctx: &HttpContext) -> Option<Cow<str>> {
        // 优先从url中获取access_token参数
        if let Some(query) = ctx.uri().query() {
            if let Some(token) = form_urlencoded::parse(query.as_bytes())
                .find(|(k, _)| k.as_ref() == ACCESS_TOKEN)
                .map(|(_, v)| v)
            {
                return Some(token);
            }
        };

        // url中找不到, 尝试从cookie中获取access_token
        if let Some(cookie_str) = ctx.headers().get(COOKIE_NAME) {
            let cookie_str = match cookie_str.to_str() {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("cookie value is not utf8 string: {:?}", e);
                    return None;
                }
            };

            for cookie in Cookie::split_parse_encoded(cookie_str) {
                match cookie {
                    Ok(item) => {
                        if item.name() == ACCESS_TOKEN {
                            return Some(Cow::Owned(String::from(item.value())));
                        }
                    }
                    Err(e) => {
                        log::warn!("cookie value [{cookie_str}] parse encode error: {e:?}");
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
    async fn handle<'a>(&'a self, mut ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        let mut verified = "false";
        // 解析token并进行校验，校验成功返回uid
        if let Some(token) = Self::get_token(&ctx) {
            if self.verify_token(&token).await {
                verified = "true";
            }
        }
        // 添加头部标志，指明token校验是否成功
        ctx.parts
            .headers
            .append(TOKEN_VERIFIED, HeaderValue::from_static(verified));
        next.run(ctx).await
    }
}

/// 判断token是否在黑名单中（用户已更新token或者用户已被删除或者已退出登录）
async fn is_blacklist(sign: &str) -> bool {
    db::exists(sign)
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
                if let Err(e) = redis::set(&k, &v).await {
                    log::error!("save_to_redis error: {}", e);
                }
            });
        }
        Err(e) => log::error!("serialize token to json error: {:?}", e),
    };
}

fn gen_redis_key(sign: &str) -> String {
    format!("{}:{}:{}", AppConf::get().redis_prefix, CK_TOKEN, sign)
}
