//! 网关应用提供的服务接口
use std::{sync::Arc, time::Duration};

use crate::{
    appvars,
    auth::JwtClaims,
    db, dict,
    proxy::{self, ServiceGroup},
    ratelimit::RateLimiter,
    statics::StaticVal,
};
use base64::{Engine, engine::general_purpose};
use compact_str::{CompactString, format_compact};
use httpserver::{HttpContext, HttpResponse, HttpServer, Resp, http_bail};
use localtime::LocalDateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub static RATE_LIMITER: StaticVal<Arc<RateLimiter>> = StaticVal::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegRequest {
    endpoint: CompactString,
    ttl: Option<u32>,
    path: Option<CompactString>,
    paths: Option<Vec<CompactString>>,
}

pub fn register_apis(srv: &mut HttpServer, gw_path: &str) {
    httpserver::register_apis!(srv, gw_path,
        "ping": ping,
        "ping/*": ping,
        "token": token,
        "blacklist": blacklist,
        "status": status,
        "query": query,
        "query/*": query,
        "reg": reg,
        "unreg": unreg,
        "cfg": cfg,
        "cfg/*": cfg,
        "recfg": recfg,
        "rate": rate,
        "rates": rates,
    );
}

/// 服务测试，测试服务是否存活
pub async fn ping(mut ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        reply: CompactString,
        now: LocalDateTime,
        server: CompactString,
        ip: CompactString,
    }

    let ip = format_compact!("{}", ctx.addr);
    log::info!("ping from: {}", ip);

    let reply = match ctx.get_param_from_multi("reply", Some(0)).await {
        Ok(Some(v)) => v,
        _ => CompactString::new("pong"),
    };

    Resp::ok(&Res {
        reply,
        now: LocalDateTime::now(),
        server: format_compact!("{}/{}", crate::APP_NAME, crate::APP_VER),
        ip,
    })
}

/// 生成token，生成jwt格式token
pub async fn token(mut ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        uid: u32,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        token: String,
    }

    let av = appvars::get();
    if av.jwt_key.is_empty() {
        return Resp::fail("jwt token generation is not supported");
    }

    let param: Req = ctx.parse_json().await?;

    let mut buf = itoa::Buffer::new();
    let uid = Some(CompactString::new(buf.format(param.uid)));
    let iss = Some(av.jwt_issuer.clone());
    let exp = Some(kjwt::unix_timestamp_after(av.jwt_ttl as u64)?);
    let claims = JwtClaims { iss, exp, uid };
    let claims_json = serde_json::to_string(&claims)?;
    let token = kjwt::encode_raw(&claims_json, &av.jwt_key)?;

    Resp::ok(&Res { token })
}

/// 将token加入黑名单
pub async fn blacklist(mut ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        token: String,
    }

    let av = appvars::get();
    if av.jwt_key.is_empty() {
        http_bail!("Not Support Jwt Token");
    }
    if !db::is_valid() {
        http_bail!("Not support check invalid token");
    }

    let param: Req = ctx.parse_json().await?;
    log::info!("set token {} to blacklist", param.token);

    if let Some((sign, exp)) = parse_token_sign_exp(&param.token) {
        db::put(sign, exp)?;
    }

    Resp::ok_empty()
}

/// 服务状态
pub async fn status(_ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        startup: LocalDateTime,      // 应用启动时间
        service_ttl: u64,            // 服务过期时间（单位：秒）
        services: Vec<ServiceGroup>, // 有效服务列表
    }

    let app_global = appvars::get();

    Resp::ok(&Res {
        startup: LocalDateTime::from_unix_timestamp(app_global.startup_time as i64),
        service_ttl: app_global.heart_break_live_time as u64,
        services: proxy::service_status(),
    })
}

/// 注册服务查询
pub async fn query(mut ctx: HttpContext) -> HttpResponse {
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
        services: Vec<proxy::GroupItem>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        services: Option<Vec<proxy::GroupItem>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        list: Option<Vec<SvrInfoItem>>,
    }

    let mut param = ctx.parse_json_opt::<Req>().await?.unwrap_or_default();

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
        log::info!("查找 {path} 对应的服务");
        let services = proxy::service_query(path);
        return Resp::ok(&Res {
            path: param.path,
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

    Resp::ok_empty()
}

/// 注册服务(同时也作为心跳服务使用)
pub async fn reg(mut ctx: HttpContext) -> HttpResponse {
    type Req = RegRequest;

    let param = ctx.parse_json::<Req>().await?;
    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    let ttl = param.ttl.unwrap_or_else(|| appvars::get().heart_break_live_time);

    // 优先使用path参数进行注册
    if let Some(path) = &param.path {
        if proxy::register_service(path, &param.endpoint, ttl) {
            log::info!("service[{} => {}] registration successful", param.endpoint, path,);
        }
    }

    // path参数为空时使用paths参数进行注册
    if let Some(paths) = &param.paths {
        for path in paths {
            if proxy::register_service(path, &param.endpoint, ttl) {
                log::info!("service[{} => {}] registration successful", param.endpoint, path);
            }
        }
    }

    Resp::ok_empty()
}

/// 取消服务注册
pub async fn unreg(mut ctx: HttpContext) -> HttpResponse {
    type Req = RegRequest;

    let param = ctx.parse_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    let endpoint = &param.endpoint;

    if let Some(path) = &param.path {
        proxy::unregister_service(path, endpoint);
        log::info!("unregister service[{}: {}]", path, endpoint);
    }

    if let Some(paths) = &param.paths {
        for path in paths {
            proxy::unregister_service(path, endpoint);
            log::info!("unregister server[{}: {}]", path, endpoint);
        }
    }

    Resp::ok_empty()
}

/// 获取配置信息
pub async fn cfg(mut ctx: HttpContext) -> HttpResponse {
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

    let mut param = match ctx.parse_json_opt::<Req>().await? {
        Some(v) => v,
        None => Req {
            key: None,
            keys: None,
        },
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
pub async fn recfg(_ctx: HttpContext) -> HttpResponse {
    let av = appvars::get();
    if !av.dict_file.is_empty() {
        dict::load(&av.dict_file).unwrap();
        log::info!("dict-file reload completed");
        Resp::ok_empty()
    } else {
        log::error!("reload dict-file error: arg dict-file is no specified");
        Resp::fail("arg dict-file no specified")
    }
}

/// 设置接口限流，rate为毫秒为单位的令牌产生速率，例如1000表示每秒产生1个令牌
/// rate为0时，表示删除该限流器
pub async fn rate(mut ctx: HttpContext) -> HttpResponse {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        path: String,
        rate: u64,
    }

    let param = ctx.parse_json::<Req>().await?;

    let rate_limiter = RATE_LIMITER.get();
    if param.rate == 0 {
        rate_limiter.delete(&param.path);
    } else {
        rate_limiter.insert(param.path, Duration::from_millis(param.rate));
    }

    Resp::ok_empty()
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

    let map = RATE_LIMITER.get().get();
    let res: Res = map
        .iter()
        .map(|item| ResItem {
            path: item.key().clone(),
            rate: item.value().rate_limit.as_millis() as u64,
        })
        .collect();

    Resp::ok(&res)
}

fn parse_token_sign_exp(token: &str) -> Option<(&str, u64)> {
    fn parse_exp(b64: &str) -> Option<u64> {
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(b64.as_bytes());
        if let Ok(bytes) = bytes {
            if let Ok(claims) = serde_json::from_slice::<Value>(&bytes) {
                if let Some(exp) = claims.get("exp") {
                    if let Some(exp) = exp.as_u64() {
                        return Some(exp);
                    }
                }
            }
        }
        None
    }

    let mut iter = token.split('.');
    // 跳过头部
    if iter.next().is_some() {
        // 读取claims部分
        if let Some(claims_b64) = iter.next() {
            if let Some(exp) = parse_exp(claims_b64) {
                // 读取签名部分
                if let Some(sign) = iter.next() {
                    return Some((sign, exp));
                }
            }
        }
    }
    None
}
