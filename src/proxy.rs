use anyhow::{Context, Result, anyhow};
use compact_str::CompactString;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use httpserver::{BodyData, Bytes, HttpContext, HttpResponse, Resp, Response, if_else};
use hyper::{Request, StatusCode, Uri};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use localtime::{LocalDateTime, unix_timestamp};
use serde::Serialize;
use smallstr::SmallString;

use std::{
    collections::VecDeque,
    sync::{LazyLock, OnceLock},
    time::Duration,
};

use crate::{AppConf, appvars, efmt};

type ServiceList = VecDeque<ServiceInfo>;
type ServiceMap = DashMap<String, ServiceList>;
type ProxyClient = Client<HttpConnector, BoxBody<Bytes, anyhow::Error>>;
type ProxyRequest = Request<BoxBody<Bytes, anyhow::Error>>;

#[derive(Serialize)]
pub struct GroupItem {
    endpoint: CompactString,
    #[serde(skip_serializing_if = "Option::is_none")]
    expire: Option<LocalDateTime>,
}

#[derive(Serialize)]
pub struct ServiceGroup {
    path: String,
    services: Vec<GroupItem>,
}

struct ServiceInfo {
    endpoint: CompactString,
    expire: u64,
}


/// 已注册的服务列表
static SERVICES: LazyLock<ServiceMap> = LazyLock::new(DashMap::new);
/// http request 请求的客户端，内部使用缓存池
static CLIENT: OnceLock<ProxyClient> = OnceLock::new();


impl ServiceInfo {
    pub fn new(endpoint: &str, expire: u64) -> Self {
        Self {
            endpoint: CompactString::new(endpoint),
            expire,
        }
    }
}

/// 注册服务, 返回true代表新注册服务, false代表服务续租
pub fn register_service(path: &str, endpoint: &str) -> bool {
    let hb_time = appvars::get().heart_break_live_time as u64;
    // 注册服务的过期时间
    let expire = if_else!(hb_time != 0, unix_timestamp() + hb_time, 0);
    let services = get_services();

    // 路径有注册的服务
    if let Some(mut svr_list) = services.get_mut(path) {
        // 对应端点的服务找到，更新过期时间, 返回false，表示续租
        if let Some(svr) = svr_list.iter_mut().find(|v| v.endpoint == endpoint) {
            svr.expire = expire;
            log::debug!("update service `{endpoint}:{path}` expire time");
            return false;
        }

        // 找不到，创建服务并添加到链表末尾
        svr_list.push_back(ServiceInfo::new(endpoint, expire));
    } else {
        // 路径对应没有服务，创建服务及链表
        let mut svr_list = ServiceList::new();
        svr_list.push_back(ServiceInfo::new(endpoint, expire));
        services.insert(String::from(path), svr_list);
    }

    log::debug!("register service `{endpoint}:{path}`");
    true
}

/// 取消注册服务
pub fn unregister_service(path: &str, endpoint: &str) {
    let services = get_services();
    if let Some(mut svr_list) = services.get_mut(path) {
        let old_svr_len = svr_list.len();
        svr_list.retain(|v| v.endpoint.as_str() != endpoint);
        if old_svr_len > svr_list.len() {
            log::debug!("remove service `{endpoint}:{path}`");
        }
        if svr_list.is_empty() {
            services.remove(path);
        }
    };
}

/// 列出当前注册的所有服务信息
pub fn service_status() -> Vec<ServiceGroup> {
    let now = unix_timestamp();
    let mut del_keys = Vec::new();
    let services = get_services();

    let result = services
        .iter()
        .filter_map(|item| {
            let services: Vec<GroupItem> = item
                .iter()
                .filter(|v| v.expire == 0 || v.expire >= now)
                .map(|v| GroupItem {
                    endpoint: v.endpoint.clone(),
                    expire: set_expire(v.expire),
                })
                .collect();

            if !services.is_empty() {
                Some(ServiceGroup {
                    path: String::from(item.key()),
                    services,
                })
            } else {
                del_keys.push(String::from(item.key()));
                None
            }
        })
        .collect();

    if !del_keys.is_empty() {
        for key in del_keys {
            services.remove(&key);
        }
    }

    result
}

// 查询指定路径的可用服务信息，路径可以是子路径，系统会自动进行递归查找，直到找到最匹配的服务
pub fn service_query(mut path: &str) -> Option<Vec<GroupItem>> {
    let now = unix_timestamp();
    let services = get_services();

    while !path.is_empty() {
        if let Some(svr_list) = services.get(path) {
            let items: Vec<GroupItem> = svr_list
                .iter()
                .filter(|s| s.expire > now || s.expire == 0)
                .map(|s| GroupItem {
                    endpoint: s.endpoint.clone(),
                    expire: set_expire(s.expire),
                })
                .collect();

            if items.is_empty() {
                services.remove(path);
                return None;
            } else {
                return Some(items);
            }
        }

        path = &path[..path.rfind('/').unwrap_or(0)];
    }

    None
}

/// 反向代理函数
///
/// 处理来自客户端的请求，并将其转发到对应的服务端点
/// 如果服务端点不存在或转发失败，将返回相应的错误信息
pub async fn proxy_handler(ctx: HttpContext) -> HttpResponse {
    let path = ctx.uri().path().to_owned();
    let full_path = ctx
        .uri()
        .path_and_query()
        .map_or("", |v| v.as_str())
        .to_owned();
    let mut finded = false;

    // 获取path对应的endpoint，找不到直接返回service not found错误
    if let Some(endpoint) = get_service_endpoint(&path) {
        finded = true;
        // 生成反向代理的请求地址
        let uri = create_uri(&endpoint, &full_path).with_context(|| efmt!("create uri fail"))?;
        log::info!("[FORWARD] {path} => {endpoint}");
        // 根据请求对象及反向代理地址，生成新的反向代理的请求对象
        let req = create_req(ctx, uri);

        match get_client().request(req).await {
            // 成功后直接向客户端返回后台服务返回的数据
            Ok(res) => {
                let (parts, body) = res.into_parts();
                let body = body.map_err(|e| anyhow!(e)).boxed();
                return Ok(Response::from_parts(parts, body));
            }
            Err(e) => {
                unregister_service_by_endpoint(&endpoint);
                log::error!("[FORWARD] {endpoint}{path} error: {e:?}");
            }
        }
    }

    if finded {
        log::info!("[FORWARD] {path} service shutdown");
        Resp::fail_with_status(StatusCode::GONE, 419, "Goned")
    } else {
        log::info!("[FORWARD] {path} service not found");
        Resp::fail_with_status(StatusCode::NOT_FOUND, 404, "Not Found")
    }
}

fn get_service_endpoint(mut path: &str) -> Option<CompactString> {
    let services = get_services();
    let mut finish = false;

    while !path.is_empty() {
        if let Some(mut svr_list) = services.get_mut(path) {
            let now = unix_timestamp();
            // 找到第一个未过期的接口服务
            while let Some(svr) = svr_list.pop_front() {
                // 服务未过期，返回其端点地址并将其重新放到服务链表尾部
                if svr.expire >= now || svr.expire == 0 {
                    let res = svr.endpoint.clone();
                    svr_list.push_back(svr);
                    return Some(res);
                }
            }

            if svr_list.is_empty() {
                services.remove(path);
            }
        }

        path = match path.rfind('/') {
            Some(pos) if pos > 0 => &path[..pos],
            _ => {
                if !finish {
                    finish = true;
                    "/"
                } else {
                    ""
                }
            }
        };
    }

    None
}

fn create_uri(endpoint: &str, path_and_query: &str) -> Result<Uri> {
    let mut buf = SmallString::<[u8; 256]>::new();
    buf.push_str("http://");
    buf.push_str(endpoint);
    if !path_and_query.is_empty() {
        buf.push('?');
        buf.push_str(path_and_query);
    }
    buf.parse().with_context(|| "parse forward uri fail")
}

fn create_req(ctx: HttpContext, uri: Uri) -> ProxyRequest {
    let mut parts = ctx.parts.clone();
    parts.uri = uri;

    let body = match ctx.body {
        BodyData::Bytes(bytes) => Full::from(bytes).map_err(|_| anyhow!("")).boxed(),
        BodyData::Incoming(incoming) => incoming.map_err(|e| anyhow!(e)).boxed(),
    };

    Request::from_parts(parts, body)
}

/// 基于子路径的递归查找取消注册服务功能
fn unregister_service_by_endpoint(endpoint: &str) {
    get_services().retain(|_, slist| {
        slist.retain(|s| s.endpoint.as_str() != endpoint);
        !slist.is_empty()
    });
}

fn set_expire(expire: u64) -> Option<LocalDateTime> {
    if expire != 0 {
        Some(LocalDateTime::from_unix_timestamp(expire as i64))
    } else {
        None
    }
}

fn get_client() -> &'static ProxyClient {
    CLIENT.get_or_init(|| {
        let timeout: u64 = AppConf::get().conn_timeout.parse().unwrap_or(2);
        let mut http_conn = HttpConnector::new();

        http_conn.set_connect_timeout(Some(Duration::from_secs(timeout)));

        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_timer(TokioTimer::new())
            .build(http_conn)
    })
}

fn get_services() -> &'static ServiceMap {
    &SERVICES
}
