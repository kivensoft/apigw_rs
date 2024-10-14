use std::time::Duration;

use dashmap::DashMap;
use httpserver::{log_trace, HttpContext, HttpResponse, Next};

type LimiterMap = DashMap<String, RateLimiter>;

pub struct RateLimiter {
    pub limiter: tokio_utils::RateLimiter,
    pub rate: Duration, // 单独记录限流阈值，因为limiter无法获取阈值
}

pub struct RateLimiterMiddleware {
    context_path: String,
    limiter_map: LimiterMap,
}

impl RateLimiterMiddleware {
    pub fn new(context_path: &str) -> Self {
        Self {
            context_path: String::from(context_path),
            limiter_map: LimiterMap::new(),
        }
    }

    pub fn insert(&self, key: String, rate_limit: Duration) {
        self.limiter_map.insert(key, RateLimiter {
            limiter: tokio_utils::RateLimiter::new(rate_limit),
            rate: rate_limit,
        });
    }

    pub fn delete(&self, key: &str) {
        self.limiter_map.remove(key);
    }

    pub fn get(&self) -> &DashMap<String, RateLimiter> {
        &self.limiter_map
    }

}

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for RateLimiterMiddleware {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>,) -> HttpResponse {
        let mut path = ctx.req.uri().path();
        if path.starts_with(self.context_path.as_str()) {
            path = &path[self.context_path.len()..];
            let mut last = false;
            let pbs = path.as_bytes();
            let mut pos = pbs.len();
            if pos > 0 && pbs[pos - 1] == b'/' {
                pos -= 1;
            }

            loop {
                if pos == 0 {
                    if !last {
                        last = true;
                        path = "/";
                    } else {
                        break;
                    }
                } else {
                    path = &path[..pos];
                }

                if let Some(rate_limiter) = self.limiter_map.get(path) {
                    if log::log_enabled!(log::Level::Trace) {
                        log_trace!(ctx.id, "rate limiter find path: {}", path);
                    }
                    return rate_limiter.limiter.throttle(|| next.run(ctx)).await
                }

                // 找到上一级目录
                pos = path.rfind('/').unwrap_or_default();
            }
        }

        next.run(ctx).await
    }
}
