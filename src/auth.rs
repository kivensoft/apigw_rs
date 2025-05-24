use compact_str::CompactString;
use cookie::Cookie;
use httpserver::{HttpContext, HttpResponse, Next};
use hyper::http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, sync::Arc, time::Duration};
use tokio::task;

use crate::{appvars, db, redis};

type Cache<K, V> = mini_moka::sync::Cache<K, V>;
type TokenCache = Cache<String, Arc<JwtClaims>>;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtClaims {
    pub iss: Option<CompactString>,
    pub exp: Option<u64>,
    pub uid: Option<CompactString>,
}

pub struct Authentication {
    gw_prefix: CompactString,
    key: CompactString,
    iss: CompactString,
    redis_prefix: String,
    token_cache: TokenCache,
}

const ACCESS_TOKEN: &str = "access_token";
const COOKIE_NAME: &str = "Cookie";
const USER_ID: &str = "X-UserId";
pub const CK_TOKEN: &str = "token";

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for Authentication {
    async fn handle<'a>(&'a self, mut ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        // 非网关接口访问，则进行token校验
        if !ctx.uri().path().starts_with(self.gw_prefix.as_str()) {
            let mut user_id = None;

            // 解析token并进行校验，校验成功返回uid
            if let Some(token) = Self::get_token(&ctx) {
                if let Some(uid) = self.verify_token(&token).await {
                    if let Ok(uid) = HeaderValue::from_str(&uid) {
                        user_id = Some(uid)
                    }
                }
            }

            // 添加头部标志，指明token校验是否成功
            let user_id = user_id.unwrap_or_else(|| HeaderValue::from_static("0"));
            ctx.parts.headers.remove(USER_ID);
            ctx.parts.headers.append(USER_ID, user_id);
        }

        next.run(ctx).await
    }
}

impl Authentication {
    /// 创建认证对象
    ///
    /// * `key`: jwt签名密钥
    /// * `issuer` jwt签发者
    /// * `cache_size` 签名校验缓存允许的最大条目
    /// * `cache_ttl` 签名校验缓存项的最大生存时间(单位：秒)
    ///
    pub fn new(
        gw_prefix: CompactString,
        key: &str,
        issuer: &str,
        redis_prefix: &str,
        cache_size: u64,
        cache_ttl: u32,
    ) -> Self {
        Authentication {
            gw_prefix,
            key: CompactString::new(key),
            iss: CompactString::new(issuer),
            redis_prefix: String::from(redis_prefix),
            token_cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(Duration::from_secs(cache_ttl as u64))
                .build(),
        }
    }

    /// 校验jwt token
    ///
    /// * `token`: jwt令牌
    ///
    /// Returns:
    ///
    ///   `Some(uid)`: 校验成功，返回uid, `None`:校验失败
    ///
    async fn verify_token(&self, token: &str) -> Option<CompactString> {
        // 获取token的签名值
        let sign = match kjwt::get_sign(token) {
            Some(sign) => sign.to_string(),
            None => {
                log::info!("jwt token format error: can't find sign of {}", token);
                return None;
            }
        };

        // 判断是否在黑名单中(用户退出，或者管理员手动添加)
        if is_blacklist(&sign).await {
            log::debug!("jwt token is in blacklist: {}", token);
            return None;
        }

        // 优先从本地缓存中读取签名，减少解密次数
        let claims = match self.token_cache.get(&sign) {
            Some(claims) => Some(claims),
            None => match load_from_redis(&self.redis_prefix, &sign).await {
                Some(claims) => {
                    let claims = Arc::new(claims);
                    self.token_cache.insert(sign.clone(), claims.clone());
                    Some(claims)
                }
                None => None,
            },
        };

        // 如果缓存中有值，判断token的iss和exp的有效性
        if let Some(claims) = claims {
            let iss = claims.iss.as_ref().map(|v| v.as_str());
            match kjwt::check_claims(&self.iss, &iss, &claims.exp) {
                Ok(_) => return claims.uid.clone(),
                Err(e) => log::info!("check_claims error: {e:?}"),
            }
        };

        fn get_iss_exp(claims: &JwtClaims) -> (Option<&str>, Option<u64>) {
            let iss = claims.iss.as_ref().map(|v| v.as_str());
            (iss, claims.exp)
        }

        // 缓存中没有，进行验证步骤，并将解析的claims缓存起来
        match kjwt::decode_custom(token, &self.key, &self.iss, get_iss_exp) {
            Ok(claims) => {
                let uid = claims.uid.clone();
                save_to_redis(&self.redis_prefix, &sign, &claims);
                self.token_cache.insert(sign, Arc::new(claims));
                return uid;
            }
            Err(e) => log::warn!("jwt token decode error: {e:?}"),
        }

        None
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
        match ctx.headers().get(kjwt::AUTHORIZATION) {
            // 如果成功获取到AUTHORIZATION字段
            Some(auth) => match auth.to_str() {
                // 将字段值转换为字符串
                Ok(auth) => {
                    // 检查令牌是否以"Bearer "开头，并且长度大于"Bearer "的长度
                    if auth.len() > kjwt::BEARER.len() && auth.starts_with(kjwt::BEARER) {
                        // 如果是，则返回令牌的剩余部分
                        Some(Cow::Borrowed(&auth[kjwt::BEARER.len()..]))
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

/// 判断token是否在黑名单中（用户已更新token或者用户已被删除或者已退出登录）
async fn is_blacklist(sign: &str) -> bool {
    db::exists(sign)
}

/// 从redis中加载签名对应的信息
async fn load_from_redis(prefix: &str, sign: &str) -> Option<JwtClaims> {
    if !appvars::get().use_redis {
        return None;
    }

    let key = gen_redis_key(prefix, sign);

    let value: String = match redis::get(&key).await.unwrap_or(None) {
        Some(v) => v,
        None => return None,
    };

    let claims = match serde_json::from_str(&value) {
        Ok(v) => v,
        Err(e) => {
            log::error!("parse token from redis error: {:?}, token = {}", e, value);
            return None;
        }
    };

    Some(claims)
}

/// 保存签名对应的信息到redis(异步方式保存)
fn save_to_redis(prefix: &str, sign: &str, claims: &JwtClaims) {
    if !appvars::get().use_redis {
        return;
    }

    let key = gen_redis_key(prefix, sign);
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

fn gen_redis_key(prefix: &str, sign: &str) -> String {
    format!("{}:{}:{}", prefix, CK_TOKEN, sign)
}
