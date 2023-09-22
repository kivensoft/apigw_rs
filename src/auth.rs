use anyhow::{Result, bail};
use compact_str::{CompactString, ToCompactString};
use cookie::Cookie;
use httpserver::{HttpContext, Next, Response};
use lru::LruCache;
use parking_lot::Mutex;
use serde_json::Value;
use std::{borrow::Cow, num::NonZeroUsize};
use tokio::time;
use triomphe::Arc;

const ACCESS_TOKEN: &str = "access_token";
const COOKIE_NAME: &str = "Cookie";

struct CacheItem {
    data: Value,
    expire: u64,
}

pub struct Authentication {
    key: CompactString,
    iss: CompactString,
    expire: u32,
    token_cache: Mutex<LruCache<String, Arc<CacheItem>>>,
}

impl Authentication {
    /// create Authentication object
    ///
    /// * `key`: jwt签名密钥
    /// * `issuer` jwt签发者
    /// * `cache_size` 签名校验缓存允许的最大条目
    /// * `cache_ttl` 签名校验缓存项的最大生存时间(单位：秒)
    ///
    pub fn new(key: &str, issuer: &str, cache_size: NonZeroUsize, cache_ttl: u32) -> Self {
        Authentication {
            key: key.to_compact_string(),
            iss: issuer.to_compact_string(),
            expire: cache_ttl,
            token_cache: Mutex::new(LruCache::new(cache_size)),
        }
    }

    /// 校验jwt token
    fn verify_token(&self, token: &str) -> Result<()> {
        // 获取token的签名值
        let sign = match jwt::get_sign(token) {
            Some(sign) => sign.to_owned(),
            None => bail!("jwt token format error: can't find '.'"),
        };

        let now = crate::unix_timestamp();

        // 优先从缓存中读取签名，减少解密次数
        let mut tc = self.token_cache.lock();
        if let Some(cache_item) = tc.get(&sign) {
            if cache_item.expire >= now {
                return jwt::check_exp(&cache_item.data)
            }
            // 缓存项过期，执行删除操作
            tc.pop(&sign);
        }
        let claims = jwt::decode(token, &self.key, &self.iss)?;
        tc.put(sign, Arc::new(CacheItem {
            data: claims,
            expire: now + self.expire as u64
        }));

        Ok(())
    }

    /// 解析返回jwt token字符串
    fn get_token(ctx: &HttpContext) -> Result<Option<Cow<str>>> {
        match ctx.req.headers().get(jwt::AUTHORIZATION) {
            Some(auth) => match auth.to_str() {
                Ok(auth) => {
                    if auth.len() > jwt::BEARER.len() && auth.starts_with(jwt::BEARER) {
                        return Ok(Some(Cow::Borrowed(&auth[jwt::BEARER.len()..])));
                    } else {
                        bail!("Authorization is not jwt token")
                    }
                }
                Err(e) => bail!("Authorization value is invalid: {e}"),
            },
            None => Self::get_access_token(ctx),
        }
    }

    /// 从url参数或cookie中解析access_token
    fn get_access_token(ctx: &HttpContext) -> Result<Option<Cow<str>>> {
        // 优先从url中获取access_token参数
        if let Some(query) = ctx.req.uri().query() {
            let url_params = querystring::querify(query);
            if let Some(param) = url_params.iter().find(|v| v.0 == ACCESS_TOKEN) {
                match urlencoding::decode(param.1) {
                    Ok(token) => return Ok(Some(token)),
                    Err(e) => bail!(
                        "request param access_token [{}] is not utf8 string: {:?}",
                        param.1, e),
                }
            };
        };

        // url中找不到, 尝试从cookie中获取access_token
        if let Some(cookie_str) = ctx.req.headers().get(COOKIE_NAME) {
            let cookie_str = match cookie_str.to_str() {
                Ok(s) => s,
                Err(e) => bail!("cookie value is not utf8 string: {e:?}")
            };
            for cookie in Cookie::split_parse_encoded(cookie_str) {
                match cookie {
                    Ok(c) => if c.name() == ACCESS_TOKEN {
                        return Ok(Some(Cow::Owned(c.value().to_owned())));
                    },
                    Err(e) => bail!("cookie value [{cookie_str}] parse encode error: {e:?}"),
                }
            }
        }

        Ok(None)
    }

    // 删除缓存里过期的项，需要用户自行调用，避免占用独立的线程资源
    fn recycle(&self) {
        log::trace!("执行token缓存清理任务...");
        let now = crate::unix_timestamp();
        let mut tc = self.token_cache.lock();

        let ds: Vec<String> = tc.iter()
            .filter(|(_, v)| v.expire < now).map(|(k, _)| k.clone())
            .collect();
        let ds_count = ds.len();

        for k in ds {
            log::trace!("清理过期的token: {k}");
            tc.pop(&k);
        }
        log::trace!("总计清理token过期项: {}", ds_count);
    }

    // 启动基于tokio的异步定时清理任务
    pub fn start_recycle_task(obj: std::sync::Arc<Authentication>, task_interval: u64) {
        let mut interval = time::interval(std::time::Duration::from_secs(task_interval));
        tokio::spawn(async move {
            interval.tick().await;
            loop {
                interval.tick().await;
                obj.recycle();
            }
        });
    }

}

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for Authentication {
    async fn handle<'a>(&'a self, mut ctx: HttpContext, next: Next<'a>,) -> anyhow::Result<Response> {
        // 解析token并进行校验，校验成功返回uid
        if let Some(token) = Self::get_token(&ctx)? {
            if let Err(e) = self.verify_token(&token) {
                log::error!("[{:08x}] AUTH verify token error: {:?}", ctx.id(), e);
                // anyhow::bail!(e)
                ctx.req.headers_mut().remove(jwt::AUTHORIZATION);
            }
        }
        next.run(ctx).await
    }
}
