//! 网关应用提供的服务接口

use crate::{
    dict,
    proxy::{self, ServiceGroup},
    AppConf, AppGlobal,
};
use compact_str::{format_compact, CompactString, ToCompactString};
use httpserver::{HttpContext, Resp, HttpResult};
use localtime::LocalTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
struct RegRequest {
    endpoint: CompactString,
    path: Option<CompactString>,
    paths: Option<Vec<CompactString>>,
}

/// 服务测试，测试服务是否存活
pub async fn ping(ctx: HttpContext) -> HttpResult {
    #[derive(Deserialize)]
    struct Req {
        reply: Option<CompactString>,
    }

    #[derive(Serialize)]
    // #[serde(rename_all = "camelCase")]
    struct Res {
        reply: CompactString,
        now: LocalTime,
        server: CompactString,
    }

    let reply = match ctx.into_opt_json::<Req>()
        .await? {
            Some(ping_params) => ping_params.reply,
            None => None,
        }
        .unwrap_or("pong".to_compact_string());

    Resp::ok(&Res {
        reply,
        now: LocalTime::now(),
        server: format_compact!("{}/{}", crate::APP_NAME, crate::APP_VER),
    })
}

/// 生成token，生成jwt格式token
pub async fn token(ctx: HttpContext) -> HttpResult {
    #[derive(Deserialize)]
    // #[serde(rename_all = "camelCase")]
    struct Req {
        ttl  : u32,   // token存活时间(分钟为单位)
        claim: Value, // 附加要加入jwt的字段及内容
    }

    #[derive(Serialize)]
    // #[serde(rename_all = "camelCase")]
    struct Res {
        token: String,
    }

    let ac = AppConf::get();
    let param: Req = ctx.into_json().await?;

    if !param.claim.is_object() {
        return Resp::fail("request param format error");
    }

    let exp = (param.ttl * 60) as u64;
    let token = jwt::encode(&param.claim, &ac.token_key, &ac.token_issuer, exp)?;

    Resp::ok(&Res { token })
}

/// 服务状态
pub async fn status(_ctx: HttpContext) -> HttpResult {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        startup    : LocalTime,         // 应用启动时间
        service_ttl: u64,               // 服务过期时间（单位：秒）
        services   : Vec<ServiceGroup>, // 有效服务列表
    }

    let app_global = AppGlobal::get();

    Resp::ok(&Res {
        startup: LocalTime::from_unix_timestamp(app_global.startup_time as i64 ),
        service_ttl: app_global.heart_break_live_time as u64,
        services: proxy::service_status(),
    })
}

/// 退出登录接口
pub async fn query(ctx: HttpContext) -> HttpResult {
    #[derive(Deserialize)]
    struct Req {
        path: Option<CompactString>,
        paths: Option<Vec<CompactString>>,
    }

    #[derive(Serialize)]
    struct Item {
        path: CompactString,
        services: Vec<proxy::ServiceItem>,
    }

    #[derive(Serialize)]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        services: Option<Vec<proxy::ServiceItem>>,
        list: Option<Vec<Item>>,
    }

    let param = ctx.into_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    if let Some(path) = &param.path {
        let services = proxy::service_query(path);
        return Resp::ok(&Res { services, list: None, })
    }

    if let Some(paths) = param.paths {
        let mut list = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(services) = proxy::service_query(&path) {
                list.push(Item {
                    path,
                    services,
                });
            }
        }
        return Resp::ok(&Res { services: None, list: Some(list) })
    }

    Resp::ok_with_empty()
}

/// 注册服务(同时也作为心跳服务使用)
pub async fn reg(ctx: HttpContext) -> HttpResult {
    type Req = RegRequest;

    #[derive(Serialize)]
    struct Res {
        endpoint: CompactString,
    }

    let param = ctx.into_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    if let Some(path) = &param.path {
        proxy::register_service(path, &param.endpoint);
    }

    if let Some(paths) = &param.paths {
        for path in paths {
            proxy::register_service(path, &param.endpoint);
        }
    }

    Resp::ok_with_empty()
}

/// 取消服务注册
pub async fn unreg(ctx: HttpContext) -> HttpResult {
    type Req = RegRequest;

    let param = ctx.into_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    let endpoint = &param.endpoint;

    if let Some(path) = &param.path {
        proxy::unregister_service(path, endpoint);
    }

    if let Some(paths) = &param.paths {
        for path in paths {
            proxy::unregister_service(path, endpoint);
        }
    }

    Resp::ok_with_empty()
}

/// 获取配置信息
pub async fn cfg(ctx: HttpContext) -> HttpResult {
    #[derive(Deserialize)]
    struct Req {
        group: CompactString,
    }

    #[derive(Serialize)]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<dict::DictItems>,
    }

    let param = ctx.into_json::<Req>().await?;

    Resp::ok(&Res { config: dict::query(&param.group) })
}

/// 获取配置信息
pub async fn reload_cfg(_ctx: HttpContext) -> HttpResult {
    let ac = AppConf::get();
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
        Resp::ok_with_empty()
    } else {
        Resp::fail("arg dict-file no specified")
    }
}
