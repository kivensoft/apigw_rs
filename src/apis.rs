//! 网关应用提供的服务接口

use crate::{
    dict,
    proxy::{self, ServiceGroup},
    AppConf, AppGlobal, unix_crypt,
};
use anyhow::Result;
use compact_str::{format_compact, CompactString, ToCompactString};
use httpserver::{fail_if, HttpContext, ResBuiler, Response};
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
pub async fn ping(ctx: HttpContext) -> Result<Response> {
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

    let reply = match ctx.into_option_json::<Req>().await? {
        Some(ping_params) => ping_params.reply,
        None => None,
    }
    .unwrap_or("pong".to_compact_string());

    ResBuiler::ok(&Res {
        reply,
        now: LocalTime::now(),
        server: format_compact!("{}/{}", crate::APP_NAME, crate::APP_VER),
    })
}

/// 生成token，生成jwt格式token
pub async fn token(ctx: HttpContext) -> Result<Response> {
    #[derive(Serialize)]
    struct Res {
        token: String,
    }

    let ac = AppConf::get();
    let exp = AppGlobal::get().token_expire as u64;
    let param = ctx.into_json::<Value>().await?;
    fail_if!(!param.is_object(), "request param format error");

    let token = jwt::encode(&param, &ac.token_key, &ac.token_issuer, exp)?;

    ResBuiler::ok(&Res { token })
}

/// 生成口令
pub async fn gen_pw(ctx: HttpContext) -> Result<Response> {
    #[derive(Deserialize, Serialize)]
    struct Req {
        password: String,
    }

    type Res = Req;

    let param: Req = ctx.into_json().await?;
    let password = unix_crypt::encrypt(&param.password)?;

    ResBuiler::ok(&Res { password })
}

/// 校验口令
pub async fn chk_pw(ctx: HttpContext) -> Result<Response> {
    #[derive(Deserialize, Serialize)]
    struct Req {
        password: CompactString,
        digest: String,
    }

    let param: Req = ctx.into_json().await?;
    if unix_crypt::verify(&param.password, &param.digest)? {
        ResBuiler::ok_with_empty()
    } else {
        ResBuiler::fail("口令错误")
    }
}

/// 服务状态
pub async fn status(_ctx: HttpContext) -> Result<Response> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        startup: LocalTime,             // 应用启动时间
        service_ttl: u64,         // 服务过期时间（单位：秒）
        services: Vec<ServiceGroup>,    // 有效服务列表
    }

    let app_global = AppGlobal::get();

    ResBuiler::ok(&Res {
        startup: LocalTime::from_unix_timestamp(app_global.startup_time as i64 ),
        service_ttl: app_global.heart_break_live_time as u64,
        services: proxy::service_status(),
    })
}

/// 退出登录接口
pub async fn query(ctx: HttpContext) -> Result<Response> {
    #[derive(Deserialize)]
    struct Req {
        path: CompactString,
    }

    #[derive(Serialize)]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        services: Option<Vec<proxy::ServiceItem>>,
    }

    let param = ctx.into_json::<Req>().await?;
    let services = proxy::service_query(&param.path);

    ResBuiler::ok(&Res { services })
}

/// 注册服务(同时也作为心跳服务使用)
pub async fn reg(ctx: HttpContext) -> Result<Response> {
    type Req = RegRequest;

    #[derive(Serialize)]
    struct Res {
        endpoint: CompactString,
    }

    let param = ctx.into_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return ResBuiler::fail("param path and paths not find");
    }

    if let Some(path) = &param.path {
        proxy::register_service(path, &param.endpoint);
    }

    if let Some(paths) = &param.paths {
        for path in paths {
            proxy::register_service(path, &param.endpoint);
        }
    }

    ResBuiler::ok_with_empty()
}

/// 取消服务注册
pub async fn unreg(ctx: HttpContext) -> Result<Response> {
    type Req = RegRequest;

    let param = ctx.into_json::<Req>().await?;

    if param.path.is_none() && param.paths.is_none() {
        return ResBuiler::fail("param path and paths not find");
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

    ResBuiler::ok_with_empty()
}

/// 获取配置信息
pub async fn cfg(ctx: HttpContext) -> Result<Response> {
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

    ResBuiler::ok(&Res { config: dict::query(&param.group) })
}

/// 获取配置信息
pub async fn reload_cfg(_ctx: HttpContext) -> Result<Response> {
    let ac = AppConf::get();
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
        ResBuiler::ok_with_empty()
    } else {
        ResBuiler::fail("arg dict-file no specified")
    }
}
