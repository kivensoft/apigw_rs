use std::num::NonZeroU32;

use anyhow::Context;
use compact_str::{CompactString, ToCompactString};
use fnv::{FnvBuildHasher, FnvHashMap};
use indexmap::IndexMap;
use kv_axum_util::{ApiResult, JsonString, api_err, api_json, api_ok, bean, if_else, now_str_into};
use localtime::LocalDateTime;
use smallvec::SmallVec;

use crate::{
    APP_NAME, APP_VER,
    appconf::AppConf,
    appvars::{APP_VAR, RATE_LIMITER_STATE},
    auth::JwtClaims,
    db, dict, efmt, err, proxy,
    rate_limit::{RateLimitCfg, RateLimiterType},
    utils,
};

#[bean(deser)]
pub struct SimpleQueryReq {
    pub q: Option<String>,
}

#[bean(deser)]
pub struct PingReq {
    pub reply: Option<String>,
}

/// ping
pub fn ping(reply: &str, ip: &str) -> JsonString {
    let mut dt = SmallVec::<[u8; 32]>::new();
    now_str_into(&mut dt);
    let dt_str = unsafe { std::str::from_utf8_unchecked(&dt) };

    api_json!(
        256,
        r#"{{"server":"{}/{}","reply":"{}","ip":"{}","now":"{}"}}"#,
        APP_NAME,
        APP_VER,
        reply,
        ip,
        dt_str
    )
}

#[bean(ser)]
pub struct StatusRes {
    /// 应用启动时间
    startup: LocalDateTime,
    /// 服务过期时间（单位：秒）
    service_ttl: u64,
    /// 有效服务列表
    services: proxy::EndPointDisplayMap,
}

/// 服务状态
pub fn status() -> ApiResult<StatusRes> {
    let av = APP_VAR.get();

    api_ok!(StatusRes {
        startup: LocalDateTime::from_unix_timestamp(av.startup_time as i64),
        service_ttl: av.heartbeat_interval as u64,
        services: proxy::service_list(),
    })
}

#[bean(ser)]
pub struct TokenRes {
    pub token: String,
}

/// 生成token，生成jwt格式token
pub fn token(uid: u32) -> ApiResult<TokenRes> {
    let ac = AppConf::get();
    if ac.jwt_key.is_empty() {
        api_err!("jwt token generation is not supported");
    }

    let iss = &ac.jwt_iss;
    let iss = if_else!(iss.is_empty(), None, Some(CompactString::new(iss)));
    let exp = kjwt::unix_timestamp_after(APP_VAR.get().jwt_ttl as u64)
        .map_err(|e| err!("无法生成unix timestamp: {:?}", e))?;
    let claims = JwtClaims { iss, exp, uid };

    let mut buf = SmallVec::<[u8; 256]>::new();
    serde_json::to_writer(&mut buf, &claims).with_context(|| efmt!("json序列化失败"))?;
    let claims_json = unsafe { std::str::from_utf8_unchecked(&buf) };
    let token =
        kjwt::encode_raw(claims_json, &ac.jwt_key).map_err(|e| err!("编码jwt失败: {:?}", e))?;

    api_ok!(TokenRes { token })
}

#[bean(deser)]
pub struct BlacklistReq {
    pub token: String,
}

/// 将token加入黑名单
pub fn blacklist(token: &str) -> ApiResult<()> {
    let ac = AppConf::get();
    if ac.jwt_key.is_empty() {
        api_err!("jwt token generation is not supported");
    }

    if let Some((sign, exp)) = utils::parse_token_sign_exp(token) {
        db::put(sign, exp)?;
    }

    api_ok!()
}

#[bean(deser)]
pub struct QueryReq {
    /// 逗号分隔的路径列表
    pub paths: String,
}

/// 注册服务查询
pub fn query(paths: &str) -> ApiResult<proxy::EndPointDisplayMap> {
    // 没有path参数，则使用paths参数
    let mut map = FnvHashMap::with_capacity_and_hasher(0, Default::default());
    for path in paths.split(',') {
        if let Some(services) = proxy::service_query(path) {
            map.insert(path.to_compact_string(), services);
        }
    }

    api_ok!(map)
}

#[bean(deser)]
pub struct RegReq {
    endpoint: CompactString,
    ttl: Option<u32>,
    paths: String,
}

/// 注册服务(同时也作为心跳服务使用)
pub fn reg(param: RegReq) -> ApiResult<()> {
    let ttl = param.ttl.unwrap_or(0);
    let endpoint = param.endpoint;
    // path参数为空时使用paths参数进行注册
    for path in param.paths.split(',') {
        if proxy::register_service(path, &endpoint, ttl) {
            tracing::debug!(%endpoint, %path, "服务注册成功");
        }
    }

    api_ok!()
}

#[bean(deser)]
pub struct UnregReq {
    pub endpoint: CompactString,
}

/// 取消服务注册
pub fn unreg(endpoint: &str) -> ApiResult<()> {
    proxy::unregister_service(endpoint);
    api_ok!()
}

#[bean(deser)]
pub struct CfgReq {
    /// 逗号分隔的路径列表
    pub keys: String,
}

#[bean(ser)]
pub struct CfgRes {
    pub cfgs: FnvHashMap<String, CompactString>,
}

/// 获取配置信息
pub async fn cfg(keys: &str) -> ApiResult<CfgRes> {
    let mut map = FnvHashMap::with_capacity_and_hasher(64, Default::default());

    for key in keys.split(',') {
        let list = dict::query(key).await;
        if !list.is_empty() {
            for (k, v) in list {
                map.insert(k, v);
            }
        }
    }

    api_ok!(CfgRes { cfgs: map })
}

/// 重新加载配置信息
pub async fn recfg() -> ApiResult<()> {
    let dict_file = &AppConf::get().dict_file;
    if !dict_file.is_empty() {
        match dict::load(dict_file).await {
            Ok(_) => {
                tracing::info!(%dict_file, "加载公共配置完成");
                api_ok!()
            },
            Err(err) => {
                tracing::error!(%dict_file, %err, "重新加载公共配置失败");
                api_err!()
            },
        }
    } else {
        tracing::error!("重新加载公共配置失败, 未配置公共配置的文件名");
        api_err!("api被禁用")
    }
}

#[bean(deser)]
pub struct RateReq {
    /// api接口路径
    pub path: CompactString,
    /// 限速器类型, 0: 全局, 1: IP限速, 2: 用户Id限速
    pub rtype: u32,
    /// 每秒增加的令牌数, > 1 时, seconds 无效
    pub per_second: NonZeroU32,
    /// per_second == 1 时, 表示每 seconds 增加 1 个令牌
    pub seconds: NonZeroU32,
    /// 允许突发流量的令牌数
    pub allow_burst: NonZeroU32,
}

/// 设置接口限流
///
/// ### Arguments:
/// * `rate_req`: 限流参数
pub fn rate(rate_req: RateReq) -> ApiResult<()> {
    if rate_req.rtype > 2 {
        api_err!(format!("限速器类型必须是 0, 1 或者 2"));
    }

    if rate_req.allow_burst.get() == 0 {
        RATE_LIMITER_STATE.remove(&rate_req.path);
    } else {
        let ty = RateLimiterType::from_repr(rate_req.rtype).unwrap_or_default();
        RATE_LIMITER_STATE.add(
            rate_req.path,
            ty,
            rate_req.per_second,
            rate_req.seconds,
            rate_req.allow_burst,
        );
    }

    api_ok!()
}

#[bean(ser)]
pub struct RatesRes {
    pub rates: IndexMap<CompactString, RateLimitCfg, FnvBuildHasher>,
}

/// 查询所有限流器
pub fn rates(q: &str) -> ApiResult<RatesRes> {
    let list = RATE_LIMITER_STATE.query(q);
    api_ok!(RatesRes { rates: list })
}

#[bean(deser)]
pub struct RateDelReq {
    /// api接口路径
    pub path: CompactString,
}

/// 删除接口限流
///
/// ### Arguments:
/// * `path`: 接口地址
pub fn rate_del(path: &str) -> ApiResult<()> {
    RATE_LIMITER_STATE.remove(path);
    api_ok!()
}
