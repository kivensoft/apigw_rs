use std::time::Duration;

use dashmap::DashMap;
use httpserver::{HttpContext, HttpResponse, Next};
use tokio_utils::RateLimiter as TokioRateLimiter;

type LimiterMap = DashMap<String, RateLimiterItem>;

pub struct RateLimiterItem {
    pub limiter: TokioRateLimiter,
    pub rate_limit: Duration, // 单独记录限流阈值，因为limiter无法获取阈值
}

pub struct RateLimiter {
    context_path: String,
    limiter_map: LimiterMap,
}

impl RateLimiter {
    /// 创建限流中间件
    ///
    /// Arguments:
    ///
    /// * `context_path`: 请求上下文，后续添加的限流接口路径都是相对于该上下文路径
    pub fn new(context_path: &str) -> Self {
        Self {
            context_path: String::from(context_path),
            limiter_map: LimiterMap::new(),
        }
    }

    /// 添加接口的限流规则
    ///
    /// Arguments:
    ///
    /// * `path`: 接口相对于context_path的路径
    /// * `rate_limit`: 限流规则，rate_limit单位时间内只允许1个请求通过
    pub fn insert(&self, path: String, rate_limit: Duration) {
        let limiter = TokioRateLimiter::new(rate_limit);
        self.limiter_map.insert(
            path,
            RateLimiterItem {
                limiter,
                rate_limit,
            },
        );
    }

    /// 删除接口的限流规则
    ///
    /// Arguments:
    ///
    /// * `path`: 接口相对于context_path的路径
    pub fn delete(&self, path: &str) {
        self.limiter_map.remove(path);
    }

    /// 获取接口限流规则的map
    pub fn get(&self) -> &DashMap<String, RateLimiterItem> {
        &self.limiter_map
    }
}

#[async_trait::async_trait]
impl httpserver::HttpMiddleware for RateLimiter {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        let mut path = ctx.uri().path();

        if path.starts_with(self.context_path.as_str()) {
            path = &path[self.context_path.len()..];

            let mut last = false;
            let mut pos = path.len();

            loop {
                if pos > 0 {
                    path = &path[..pos];
                } else if !last {
                    last = true;
                    path = "/";
                } else {
                    break;
                }

                if let Some(rate_limiter) = self.limiter_map.get(path) {
                    if log::log_enabled!(log::Level::Trace) {
                        log::trace!("rate limiter find path: {}", path);
                    }
                    return rate_limiter.limiter.throttle(|| next.run(ctx)).await;
                }

                // 找到上一级目录
                pos = path.rfind('/').unwrap_or(0);
            }
        }

        next.run(ctx).await
    }
}
