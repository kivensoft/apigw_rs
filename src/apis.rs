//! 网关应用提供的服务接口
use std::{sync::Arc, time::Duration};

use crate::{
    auth, dict, proxy::{self, ServiceGroup}, ratelimit::RateLimiterMiddleware,
    redis, staticmut::StaticMut, AppConf, AppGlobal
};
use httpserver::{http_bail, http_error, log_error, log_info, HttpContext, HttpResponse, Resp};
use localtime::LocalTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub static mut RATE_LIMITER: StaticMut<Arc<RateLimiterMiddleware>> = StaticMut::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegRequest {
    endpoint: String,
    path: Option<String>,
    paths: Option<Vec<String>>,
}

/// 服务测试，测试服务是否存活
pub async fn ping(ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        reply: String,
        now: LocalTime,
        server: String,
        ip: String,
    }

    let ip = format!("{}", ctx.addr);
    log_info!(ctx.id, "ping from: {}", ip);

    let reply = ctx.get_param_from_multi("reply", Some(0))
        .map(String::from)
        .unwrap_or(String::from("pong"));

    Resp::ok(&Res {
        reply,
        now: LocalTime::now(),
        server: format!("{}/{}", crate::APP_NAME, crate::APP_VER),
        ip,
    })
}

/// 生成token，生成jwt格式token
pub async fn token(ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        ttl:    u32,        // token存活时间(分钟为单位)
        claims: Value,      // 附加要加入jwt的字段及内容
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        token: String,
    }

    let ac = AppConf::get();
    if ac.jwt_key.is_empty() {
        return Resp::fail("jwt token generation is not supported");
    }

    let param: Req = ctx.parse_json()?;
    if !param.claims.is_object() {
        return Resp::fail("jwt token claims must be object");
    }

    log_info!(ctx.id, "create jwt token from {}", param.claims);
    let exp = (param.ttl * 60) as u64;
    let token = jwt::encode(param.claims, &ac.jwt_key, &ac.jwt_issuer, exp)?;

    Resp::ok(&Res { token })
}

/// 将token加入黑名单
pub async fn blacklist(ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        token: String,
    }

    let ac = AppConf::get();
    if ac.redis_host.is_empty() || ac.jwt_key.is_empty() {
        http_bail!("Not Support Jwt Token");
    }

    let param: Req = ctx.parse_json()?;
    log_info!(ctx.id, "set token {} to blacklist", param.token);

    if let Err(e) = jwt::decode(&param.token, &ac.jwt_key, &ac.jwt_issuer) {
        log_error!(ctx.id, "decode token fail: {e:?}");
        http_bail!("Invalid Token");
    };

    let now = localtime::LocalTime::now();
    let sign = jwt::get_sign(&param.token).ok_or_else(|| http_error!("Invalid Token"))?;
    let key = format!("{}:{}:{}", ac.redis_prefix, auth::LOGOUT_KEY, sign);
    let ttl = AppGlobal::get().redis_ttl as u32;

    redis::set(&key, &now.to_string(), ttl).await?;

    Resp::ok_with_empty()
}

/// 服务状态
pub async fn status(_ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        startup: LocalTime,          // 应用启动时间
        service_ttl: u64,            // 服务过期时间（单位：秒）
        services: Vec<ServiceGroup>, // 有效服务列表
    }

    let app_global = AppGlobal::get();

    Resp::ok(&Res {
        startup: LocalTime::from_unix_timestamp(app_global.startup_time as i64),
        service_ttl: app_global.heart_break_live_time as u64,
        services: proxy::service_status(),
    })
}

/// 注册服务查询
pub async fn query(ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        path: Option<String>,
        paths: Option<Vec<String>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SvrInfoItem {
        path: String,
        services: Vec<proxy::ServiceItem>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        services: Option<Vec<proxy::ServiceItem>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        list: Option<Vec<SvrInfoItem>>,
    }

    let mut param = ctx.parse_json_opt::<Req>()?.unwrap_or(Req::default());

    // body中没有，尝试从路径中读取
    if param.path.is_none() {
        if let Some(s) = ctx.get_path_param(0) {
            param.path = Some(String::from(s));
        }
    }

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    // 优先使用path参数
    if let Some(path) = &param.path {
        log_info!(ctx.id, "查找 {path} 对应的服务");
        let services = proxy::service_query(path);
        return Resp::ok(&Res {
            path: param.path.clone(),
            services,
            list: None,
        });
    }

    // 没有path参数，则使用paths参数
    if let Some(paths) = param.paths {
        let mut list = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(services) = proxy::service_query(&path) {
                list.push(SvrInfoItem { path, services });
            }
        }
        return Resp::ok(&Res {
            path: None,
            services: None,
            list: Some(list),
        });
    }

    Resp::ok_with_empty()
}

/// 注册服务(同时也作为心跳服务使用)
pub async fn reg(ctx: HttpContext) -> HttpResponse {
    type Req = RegRequest;

    let param = ctx.parse_json::<Req>()?;
    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    // 优先使用path参数进行注册
    if let Some(path) = &param.path {
        if proxy::register_service(path, &param.endpoint) {
            log_info!(
                ctx.id,
                "service[{} => {}] registration successful",
                param.endpoint,
                path,
            );
        }
    }

    // path参数为空时使用paths参数进行注册
    if let Some(paths) = &param.paths {
        for path in paths {
            if proxy::register_service(path, &param.endpoint) {
                log_info!(
                    ctx.id,
                    "service[{} => {}] registration successful",
                    param.endpoint,
                    path,
                );
            }
        }
    }

    Resp::ok_with_empty()
}

/// 取消服务注册
pub async fn unreg(ctx: HttpContext) -> HttpResponse {
    type Req = RegRequest;

    let param = ctx.parse_json::<Req>()?;

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    let endpoint = &param.endpoint;

    if let Some(path) = &param.path {
        proxy::unregister_service(path, endpoint);
        log_info!(ctx.id, "unregister service[{}: {}]", path, endpoint);
    }

    if let Some(paths) = &param.paths {
        for path in paths {
            proxy::unregister_service(path, endpoint);
            log_info!(ctx.id, "unregister server[{}: {}]", path, endpoint);
        }
    }

    Resp::ok_with_empty()
}

/// 获取配置信息
pub async fn cfg(ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        key: Option<String>,
        keys: Option<Vec<String>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<dict::DictItems>,
    }

    let mut param = match ctx.parse_json_opt::<Req>()? {
        Some(v) => v,
        None => Req { key: None, keys: None },
    };

    if param.key.is_none() {
        if let Some(key) = ctx.get_path_param(0) {
            param.key = Some(String::from(key));
        }
    }

    if param.key.is_none() && param.keys.is_none() {
        return Resp::fail("param group or groups not find");
    }

    let config = if let Some(key) = param.key {
        dict::query(&key)
    } else {
        let mut cfgs = Vec::new();
        for k in param.keys.unwrap() {
            if let Some(items) = dict::query(&k) {
                cfgs.push(items);
            }
        }
        Some(cfgs.concat())
    };

    Resp::ok(&Res { config })
}

/// 重新加载配置信息
pub async fn recfg(ctx: HttpContext) -> HttpResponse {
    let ac = AppConf::get();
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
        log_info!(ctx.id, "dict-file reload completed");
        Resp::ok_with_empty()
    } else {
        log_error!(ctx.id, "reload dict-file error: arg dict-file is no specified");
        Resp::fail("arg dict-file no specified")
    }
}

/// 设置接口限流，rate为毫秒为单位的令牌产生速率，例如1000表示每秒产生1个令牌
/// rate为0时，表示删除该限流器
pub async fn rate(ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        path: String,
        rate: u64,
    }

    let param = ctx.parse_json::<Req>()?;

    let rate_limiter = unsafe { RATE_LIMITER.get() };
    if param.rate == 0 {
        rate_limiter.delete(&param.path);
    } else {
        rate_limiter.insert(param.path, Duration::from_millis(param.rate));
    }

    Resp::ok_with_empty()
}

/// 查询所有限流器
pub async fn rates(_ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ResItem {
        path: String,
        rate: u64,
    }
    type Res = Vec<ResItem>;

    let map = unsafe { RATE_LIMITER.get().get() };
    let res: Res = map.iter()
        .map(|item| ResItem {
            path: item.key().clone(),
            rate: item.value().rate.as_millis() as u64,
        })
        .collect();

    Resp::ok(&res)
}
