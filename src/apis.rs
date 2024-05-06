//! 网关应用提供的服务接口
use crate::{
    dict,
    proxy::{self, ServiceGroup},
    AppConf, AppGlobal,
};
use compact_str::{format_compact, CompactString};
use httpserver::{log_debug, log_error, log_info, HttpContext, HttpResponse, Resp};
use localtime::LocalTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use triomphe::Arc;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PingRequest {
    reply: Option<CompactString>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegRequest {
    endpoint: CompactString,
    path: Option<CompactString>,
    paths: Option<Vec<CompactString>>,
}

/// 服务测试，测试服务是否存活
pub async fn ping(ctx: HttpContext) -> HttpResponse {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        reply: CompactString,
        now: LocalTime,
        server: CompactString,
        client: CompactString,
    }

    let client: CompactString = format_compact!("{}", ctx.addr);

    log_debug!(ctx.id, "ping from: {}", client);

    let reply = get_reply_param(&ctx).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    Resp::ok(&Res {
        reply,
        now: LocalTime::now(),
        server: format_compact!("{}/{}", crate::APP_NAME, crate::APP_VER),
        client,
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
    let param: Req = ctx.parse_json()?;

    if !param.claims.is_object() {
        return Resp::fail("request param format error");
    }

    let exp = (param.ttl * 60) as u64;
    let token = jwt::encode(param.claims, &ac.token_key, &ac.token_issuer, exp)?;

    Resp::ok(&Res { token })
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
        path: Option<CompactString>,
        paths: Option<Vec<CompactString>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SvrInfoItem {
        path: CompactString,
        services: Vec<proxy::ServiceItem>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<CompactString>,
        #[serde(skip_serializing_if = "Option::is_none")]
        services: Option<Vec<proxy::ServiceItem>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        list: Option<Vec<SvrInfoItem>>,
    }

    let mut param = ctx.parse_json_opt::<Req>()?.unwrap_or(Req::default());

    // body中没有，尝试从路径中读取
    if param.path.is_none() {
        if let Some(s) = ctx.get_path_val(0) {
            param.path = Some(CompactString::new(s));
        }
    }

    if param.path.is_none() && param.paths.is_none() {
        return Resp::fail("param path and paths not find");
    }

    // 优先使用path参数
    if let Some(path) = &param.path {
        log_debug!(ctx.id, "查找 {path} 对应的服务");
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

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        endpoint: CompactString,
    }

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
        group: Option<CompactString>,
        groups: Option<Vec<CompactString>>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Res {
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<dict::DictItems>,
    }

    let mut param = ctx.parse_json_opt::<Req>()?.unwrap_or(Req {
        group: None,
        groups: None,
    });

    if param.group.is_none() {
        if let Some(group) = ctx.get_path_val(0) {
            param.group = Some(CompactString::new(group));
        }
    }

    if param.group.is_none() && param.groups.is_none() {
        return Resp::fail("param group or groups not find");
    }

    let config = if let Some(group) = param.group {
        dict::query(&group)
    } else {
        let mut tmp_config = Vec::new();
        for g in param.groups.unwrap() {
            if let Some(items) = dict::query(&g) {
                tmp_config.extend_from_slice(items.as_slice());
            }
        }
        Some(Arc::new(tmp_config))
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

/// 获取请求中reply参数, 获取优先级: post_data > query_string > url_path > default
async fn get_reply_param(ctx: &HttpContext) -> CompactString {
    const REPLY: &str = "reply";
    const REPLY_DEFAULT: CompactString = CompactString::new_inline("pong");

    // 优先从post的数据中提取
    if !ctx.body.is_empty() {
        if ctx.is_json() {
            if let Ok(Some(param)) = ctx.parse_json_opt::<PingRequest>() {
                log_info!(ctx.id, "param: {param:?}");
                if let Some(reply) = param.reply {
                    if !reply.is_empty() {
                        return reply;
                    }
                }
            }
        } else if ctx.is_formd_urlencoded() {
            if let Some(reply) = ctx.get_formdata_param_str(REPLY) {
                return CompactString::new(reply);
            }
        }
    }

    // 次优先从url参数中获取
    if let Some(reply) =  ctx.get_url_param_str(REPLY) {
        return CompactString::new(reply);
    }

    // 最低优先级从路径中获取
    if let Some(reply) = ctx.get_path_val(0) {
        return CompactString::new(reply);
    }

    // 如果都没有找到，返回缺省值
    REPLY_DEFAULT
}
