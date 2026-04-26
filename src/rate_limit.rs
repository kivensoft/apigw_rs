use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use compact_str::CompactString;
use dashmap::DashMap;
use fnv::FnvHashMap;
use governor::{
    Quota, RateLimiter,
    clock::{QuantaClock, QuantaInstant},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
};
use hyper::StatusCode;
use kv_axum_util::{ApiError, bean, if_else};
use rclite::Arc;
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum::{EnumCount, EnumIter, FromRepr};

use crate::auth::UserId;

/// 限速器类型
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Serialize_repr,
    Deserialize_repr,
    FromRepr,
    EnumCount,
    EnumIter,
)]
#[repr(u32)]
pub enum RateLimiterType {
    /// 全局限速
    #[default]
    None,
    /// 根据IP限速
    IP,
    /// 根据用户ID限速
    UserId,
}

#[bean]
#[derive(Clone)]
pub struct RateLimitCfg {
    /// 限速器类型
    pub rtype: RateLimiterType,
    /// 每秒增加的令牌数, > 1 时, seconds 无效
    pub per_second: NonZeroU32,
    /// per_second == 1 时, 表示每 seconds 增加 1 个令牌
    pub seconds: NonZeroU32,
    /// 最大令牌数(突发流量)
    pub allow_burst: NonZeroU32,
}

enum GenericRateLimiter {
    None(RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware<QuantaInstant>>),
    IP(
        RateLimiter<
            CompactString,
            DashMap<CompactString, InMemoryState>,
            QuantaClock,
            NoOpMiddleware<QuantaInstant>,
        >,
    ),
    UserId(
        RateLimiter<u32, DashMap<u32, InMemoryState>, QuantaClock, NoOpMiddleware<QuantaInstant>>,
    ),
}

pub struct RateLimitInfo {
    /// 限速器配置
    config: RateLimitCfg,
    /// 限速器类型
    rate_limiter: GenericRateLimiter,
}

#[derive(Clone)]
pub struct RateLimiterState(pub Arc<DashMap<CompactString, RateLimitInfo>>);

impl RateLimiterState {
    pub fn new() -> Self {
        Self(Arc::new(DashMap::new()))
    }

    /// 删除限速器
    ///
    /// ### Arguments
    /// * `path` - api 接口路径
    pub fn remove(&self, path: &str) {
        self.0.remove(path);
    }

    /// 清理过期的条目, 减少内存占用
    pub fn recycle(&self) {
        for entry in self.0.iter() {
            match &entry.rate_limiter {
                GenericRateLimiter::IP(limiter) => {
                    limiter.retain_recent();
                    limiter.shrink_to_fit();
                },
                GenericRateLimiter::UserId(limiter) => {
                    limiter.retain_recent();
                    limiter.shrink_to_fit();
                },
                _ => {},
            }
        }
    }

    /// 查询, 当 path.is_empty() 时，返回所有限速器, 当 path 以 "/" 结尾时, 按前缀查找
    pub fn query(&self, path: &str) -> FnvHashMap<CompactString, RateLimitCfg> {
        let get_all = path.is_empty();
        let get_prefix = path.ends_with('/');
        let eq_str = if_else!(get_prefix, &path[..path.len() - 1], path);
        let mut ret = FnvHashMap::default();

        for entry in self.0.iter() {
            let mut inserted = false;
            let key = entry.key();

            if get_all {
                inserted = true;
            } else if get_prefix {
                if key.starts_with(path) || key == eq_str {
                    inserted = true;
                }
            } else if key == path {
                inserted = true;
            }

            if inserted {
                ret.insert(key.clone(), entry.value().config.clone());
            }
        }

        ret
    }

    /// 添加一个快速限速器(每秒生成N个令牌)
    ///
    /// ### Arguments
    /// * `path` - api 接口路径
    /// * `rtype` - 限速器类型
    /// * `per_second` - 每秒生成令牌数(seconds == 1 时)
    /// * `allow_burst` - 允许的突发流量
    #[allow(dead_code)]
    pub fn add_quick<T: Into<CompactString>>(
        &self, path: T, rtype: RateLimiterType, per_second: NonZeroU32, allow_burst: NonZeroU32,
    ) {
        self.add(path, rtype, per_second, NonZeroU32::new(1).unwrap(), allow_burst);
    }

    /// 添加一个慢速限速器(N秒生成1个令牌)
    ///
    /// ### Arguments
    /// * `path` - api 接口路径
    /// * `rtype` - 限速器类型
    /// * `seconds` - 每生成1个令牌需要的秒数(per_second == 1 时)
    /// * `allow_burst` - 允许的突发流量
    #[allow(dead_code)]
    pub fn add_slow<T: Into<CompactString>>(
        &self, path: T, rtype: RateLimiterType, seconds: NonZeroU32, allow_burst: NonZeroU32,
    ) {
        self.add(path, rtype, NonZeroU32::new(1).unwrap(), seconds, allow_burst);
    }

    /// 添加一个限速器
    ///
    /// ### Arguments
    /// * `path` - api 接口路径
    /// * `rtype` - 限速器类型
    /// * `per_second` - 每秒生成令牌数(seconds == 1 时)
    /// * `seconds` - 每生成1个令牌需要的秒数(per_second == 1 时)
    /// * `allow_burst` - 允许的突发流量
    pub fn add<T: Into<CompactString>>(
        &self, path: T, rtype: RateLimiterType, per_second: NonZeroU32, seconds: NonZeroU32,
        allow_burst: NonZeroU32,
    ) {
        let rate_limiter = Self::new_rate_limiter(rtype, per_second, seconds, allow_burst);
        let config = RateLimitCfg { rtype, per_second, seconds, allow_burst };
        let info = RateLimitInfo { config, rate_limiter };
        let path = path.into();

        self.0.insert(path.clone(), info);

        tracing::info!(%path, rtype = %rtype as u32, %per_second, %seconds, %allow_burst, "创建限速器");
    }

    /// 创建新的限速器
    fn new_rate_limiter(
        type_: RateLimiterType, per_second: NonZeroU32, seconds: NonZeroU32,
        allow_burst: NonZeroU32,
    ) -> GenericRateLimiter {
        let quota = if per_second.get() > 1 {
            Quota::per_second(per_second).allow_burst(allow_burst)
        } else {
            Quota::with_period(Duration::from_secs(seconds.get() as u64))
                .unwrap()
                .allow_burst(allow_burst)
        };

        match type_ {
            RateLimiterType::None => GenericRateLimiter::None(RateLimiter::direct(quota)),
            RateLimiterType::IP => GenericRateLimiter::IP(RateLimiter::keyed(quota)),
            RateLimiterType::UserId => GenericRateLimiter::UserId(RateLimiter::keyed(quota)),
        }
    }
}

pub async fn rate_limit_middleware(
    State(state): State<RateLimiterState>, req: Request, next: Next,
) -> Response {
    let mut limited = false;
    let path = req.uri().path();
    if let Some(config) = state.0.get(path) {
        // 获取当前请求对应的限流器实例（需结合IP或Key）
        match &config.rate_limiter {
            GenericRateLimiter::None(limiter) => {
                limited = limiter.check().is_err();
            },
            GenericRateLimiter::IP(limiter) => {
                let real_ip = get_ip(&req);
                limited = limiter.check_key(&real_ip).is_err();
            },
            GenericRateLimiter::UserId(limiter) => {
                let uid = req.extensions().get::<UserId>().map_or(0, |uid| uid.0);
                limited = limiter.check_key(&uid).is_err();
            },
        }
        // 执行限流检查，若超限则返回 429
    }

    // 如果被限流, 返回 429, 否则正常执行
    if limited {
        ApiError::error_with_status(StatusCode::TOO_MANY_REQUESTS, "请求过于频繁, 请稍后再试")
            .into_response()
    } else {
        next.run(req).await
    }
}

fn get_ip(req: &Request) -> CompactString {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| CompactString::new(s.trim()))
        .or_else(|| {
            req.headers()
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| CompactString::new(s))
        })
        .unwrap_or_else(|| {
            req.extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ipv4_to_compact_string(ci.0.ip()))
                .unwrap_or_else(|| CompactString::new("unknown"))
        })
}

fn ipv4_to_compact_string(ip: IpAddr) -> CompactString {
    let ipv4 = match ip {
        IpAddr::V4(ip) => ip,
        _ => return CompactString::new("ipv6"),
    };

    let octets = ipv4.octets();
    let mut buffer = [0u8; 15]; // "255.255.255.255" 需要 15 字节

    let mut pos = 0;
    for (i, &octet) in octets.iter().enumerate() {
        if i > 0 {
            buffer[pos] = b'.';
            pos += 1;
        }
        pos += write_uint(&mut buffer[pos..], octet as u32);
    }

    // 不安全但安全，因为我们保证 buffer 有效且 pos <= 15
    unsafe { CompactString::from_utf8_unchecked(&buffer[..pos]) }
}

fn write_uint(buffer: &mut [u8], mut n: u32) -> usize {
    let mut temp = [0u8; 3];
    let mut index = 0;

    if n == 0 {
        buffer[0] = b'0';
        return 1;
    }

    while n > 0 {
        temp[index] = b'0' + (n % 10) as u8;
        n /= 10;
        index += 1;
    }

    for j in 0..index {
        buffer[j] = temp[index - 1 - j];
    }

    index
}
