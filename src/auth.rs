use axum::{
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};
use compact_str::CompactString;
use hyper::header;
use kv_axum_util::{bean, if_else, unix_timestamp};
use mini_moka::sync::ConcurrentCacheExt;
use prost::Message;
use rclite::Arc;
use std::time::Duration;
use tokio::task;

use crate::{appvars::{APP_VAR, REDIS_CLIENT}, db};

const AUTH_INFO_ENCODE_SIZE: usize = 64;

#[derive(prost::Message)]
pub struct AuthInfo {
    #[prost(uint64, tag = "1")]
    pub exp: u64,

    #[prost(uint32)]
    pub uid: u32,
}

#[bean(ser, deser)]
pub struct JwtClaims {
    pub iss: Option<CompactString>,
    pub exp: u64,
    pub uid: u32,
}

#[derive(Clone)]
pub struct UserId(pub u32);

impl<S: Send + Sync> FromRequestParts<S> for UserId {
    type Rejection = std::convert::Infallible;

    #[allow(clippy::manual_async_fn)]
    fn from_request_parts(
        parts: &mut Parts, _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let user_id = parts.extensions.get::<UserId>().map_or(0, |v| v.0);
            Ok(UserId(user_id))
        }
    }
}

type CacheKey = [u8; 32];
type Cache<K, V> = mini_moka::sync::Cache<K, V>;
type TokenCache = Cache<CacheKey, Arc<AuthInfo>>;

pub struct AuthState {
    pub key: String,
    pub iss: String,
    pub redis_prefix: String,
    pub token_cache: Arc<TokenCache>,
}

impl AuthState {
    /// 创建认证对象
    ///
    /// * `key`: jwt 签名密钥, 为空表示禁用 jwt 校验
    /// * `iss` jwt 签发者, 为空表示不校验签发者
    /// * `cache_cap` 签名校验缓存允许的最大条目
    /// * `cache_ttl` 签名校验缓存项的最大生存时间(单位：秒), 本地缓存及二级缓存共用
    pub fn new<S: Into<String>>(
        key: S, iss: S, redis_prefix: S, cache_cap: u32, cache_ttl: u32,
    ) -> Self {
        let auth_state = AuthState {
            key: key.into(),
            iss: iss.into(),
            redis_prefix: redis_prefix.into(),
            token_cache: Arc::new(
                Cache::builder()
                    .max_capacity(cache_cap as u64)
                    .time_to_live(Duration::from_secs(cache_ttl as u64))
                    .build(),
            ),
        };

        let cache = auth_state.token_cache.clone();
        // 启动定时清理本地缓存过期数据的任务
        task::spawn(async move {
            use tokio::time::sleep;
            loop {
                sleep(Duration::from_secs(cache_ttl as u64)).await;
                cache.sync();
            }
        });

        auth_state
    }

    /// 从多级缓存中加载数据, 优先从本地缓存中读取, 没有则转到二级缓存中读取
    async fn load_from_multi_cache(&self, sign: &str) -> Option<Arc<AuthInfo>> {
        // 优先从本地缓存中读取
        let mut sign_bs = CacheKey::default();
        let use_local = decode_sign(&mut sign_bs, sign);
        if use_local {
            let auth_info = self.token_cache.get(&sign_bs);
            if auth_info.is_some() {
                return auth_info;
            }
        }

        // 尝试从二级缓存 redis 中读取
        let result = self.load_from_redis(sign).await;
        if let Some(auth_info) = &result {
            self.token_cache.insert(sign_bs, auth_info.clone());
        }
        result
    }

    /// 保存到本地缓存及二级缓存中
    fn save_to_multi_cache(&self, sign: &str, auth_info: Arc<AuthInfo>) {
        // 本地缓存中已存在, 直接返回
        let mut sign_bs = CacheKey::default();
        let use_local = decode_sign(&mut sign_bs, sign);
        if use_local && self.token_cache.contains_key(&sign_bs) {
            return;
        }

        // 保存到二级缓存
        self.save_to_redis(sign, &auth_info);
        // 保存到本地缓存
        if use_local {
            self.token_cache.insert(sign_bs, auth_info);
        }
    }

    // fn remove_from_multi_cache(&self, sign: &str) {
    //     let mut sign_bs = CacheKey::default();
    //     let use_local = decode_sign(&mut sign_bs, sign);
    //     if use_local {
    //         self.token_cache.invalidate(&sign_bs);
    //     }

    //     if !APP_VAR.get().use_redis {
    //         return;
    //     }

    //     let key = self.gen_redis_key(sign);
    //     task::spawn(async move {
    //         if let Err(e) = REDIS_CLIENT.get().del(key).await {
    //             tracing::error!(err = %e, "从 redis 删除 key 失败");
    //         }
    //     });
    // }

    /// 从 redis 中加载签名对应的认证信息
    async fn load_from_redis(&self, sign: &str) -> Option<Arc<AuthInfo>> {
        if !APP_VAR.get().use_redis {
            return None;
        }

        let key = self.gen_redis_key(sign);

        let value: Vec<u8> = match REDIS_CLIENT.get().get(&key).await {
            Ok(v) => match v {
                Some(s) => s,
                None => return None,
            },
            Err(err) => {
                tracing::error!(%err, "访问 redis 出现错误");
                return None;
            },
        };

        let auth_info = match AuthInfo::decode(value.as_ref()) {
            Ok(v) => v,
            Err(err) => {
                tracing::error!(%err, "解码 AuthInfo 结构失败");
                return None;
            },
        };

        Some(Arc::new(auth_info))
    }

    /// 保存签名对应的信息到 redis (异步方式保存)
    fn save_to_redis(&self, sign: &str, auth_info: &AuthInfo) {
        if !APP_VAR.get().use_redis {
            return;
        }

        let key = self.gen_redis_key(sign);
        let mut value = Vec::with_capacity(AUTH_INFO_ENCODE_SIZE);
        if let Err(err) = auth_info.encode(&mut value) {
            tracing::error!(%err, "AuthInfo 序列化成 protobuf 失败");
            return;
        }

        task::spawn(async move {
            if let Err(err) = REDIS_CLIENT.get().set(key, value).await {
                tracing::error!(%err, "保存 AuthInfo 到 redis 失败");
            }
        });
    }

    /// 根据`sign`生成 redis 的 key
    fn gen_redis_key(&self, sign: &str) -> String {
        let mut key = String::with_capacity(128);
        key.push_str(&self.redis_prefix);
        key.push(':');
        key.push_str(CK_JWT);
        key.push(':');
        key.push_str(sign);
        key
    }
}

const CK_JWT: &str = "jwt";
const BEARER: &str = "Bearer ";

pub async fn auth_middleware(
    State(state): State<Arc<AuthState>>, mut req: Request, next: Next,
) -> Response {
    // key 不为空, 表示开启 jwt 验证
    if !state.key.is_empty() {
        // 获取 jwt token
        let jwt_token = match get_auth_header(&req) {
            Some(auth_header) => get_jwt_token(auth_header).to_string(),
            None => String::new(),
        };

        // 从认证令牌解析用户ID, 解析成功是用户id, 解析失败是 0
        let uid = parse_uid(jwt_token, &state).await.unwrap_or(0);

        // 将数据存入请求扩展
        req.extensions_mut().insert(UserId(uid));
    }

    next.run(req).await
}

async fn parse_uid(jwt_token: String, state: &AuthState) -> Option<u32> {
    if jwt_token.is_empty() {
        return None;
    }

    // 获取 token 中的签名
    let sign = match kjwt::get_sign(&jwt_token) {
        Some(sign) => sign,
        None => return None,
    };

    // 如果签名在黑名单中存在(表示 token 无效)
    if is_blacklist(sign) {
        return None;
    }

    let now = unix_timestamp();

    // 从缓存中加载解码信息成功, 直接返回
    if let Some(auth_info) = state.load_from_multi_cache(sign).await {
        // 判断过期时间
        return if_else!(now <= auth_info.exp, Some(auth_info.uid), None);
    }

    // 进行解码操作
    match kjwt::decode_custom(&jwt_token, &state.key, &state.iss, get_iss_exp) {
        Ok(claims) => {
            let uid = claims.uid;
            let auth_info = Arc::new(AuthInfo { exp: claims.exp, uid: claims.uid });
            // 保存到缓存
            state.save_to_multi_cache(sign, auth_info);
            Some(uid)
        },
        Err(err) => {
            tracing::error!(%err, "解码 jwt 失败");
            None
        },
    }
}

fn get_auth_header(req: &Request) -> Option<&str> {
    if let Some(auth_value) = req.headers().get(header::AUTHORIZATION) {
        match auth_value.to_str() {
            Ok(auth_header) => return Some(auth_header),
            Err(_) => {
                tracing::warn!("请求头部 {} 有无效字符", header::AUTHORIZATION);
            },
        }
    }

    None
}

fn get_jwt_token(auth_header: &str) -> &str {
    if auth_header.len() > BEARER.len() {
        let prefix = &auth_header[..BEARER.len()];

        if BEARER.eq_ignore_ascii_case(prefix) {
            return &auth_header[BEARER.len()..];
        }
    }

    auth_header
}

/// 解码 base64 格式的签名
fn decode_sign(out: &mut CacheKey, sign: &str) -> bool {
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

    match URL_SAFE_NO_PAD.decode_slice(sign.as_bytes(), out) {
        Ok(count) => count == out.len(),
        Err(err) => {
            tracing::error!(%err, "解码 jwt 签名(base64)失败");
            false
        },
    }
}

/// 判断token是否在黑名单中（用户已更新token或者用户已被删除或者已退出登录）
fn is_blacklist(sign: &str) -> bool {
    db::exists(sign)
}

fn get_iss_exp(claims: &JwtClaims) -> (Option<&str>, Option<u64>) {
    let iss = claims.iss.as_ref().map(|v| v.as_str());
    (iss, Some(claims.exp))
}
