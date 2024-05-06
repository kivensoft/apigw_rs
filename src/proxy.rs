use anyhow_ext::{Context, Result};
use compact_str::CompactString;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use httpserver::{
    if_else, log_error, log_info, Bytes, HttpContext, HttpResponse,
    Resp, Response,
};
use hyper::{StatusCode, Uri};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioTimer},
};
use localtime::LocalTime;
use serde::Serialize;
use smallstr::SmallString;

use std::{collections::VecDeque, fmt::Write, sync::OnceLock, time::Duration};

use crate::{AppConf, AppGlobal};

type ServiceInfoList = VecDeque<ServiceInfo>;
type ServicesType = DashMap<CompactString, ServiceInfoList>;

/// 已注册的服务列表
static SERVICES: OnceLock<ServicesType> = OnceLock::new();
/// http request 请求的客户端，内部使用缓存池
static CLIENT: OnceLock<Client<HttpConnector, Full<Bytes>>> = OnceLock::new();

struct ServiceInfo {
    endpoint: CompactString,
    expire: i64,
}

#[derive(Serialize)]
pub struct ServiceItem {
    endpoint: CompactString,
    #[serde(skip_serializing_if = "Option::is_none")]
    expire: Option<LocalTime>,
}

#[derive(Serialize)]
pub struct ServiceGroup {
    path: CompactString,
    services: Vec<ServiceItem>,
}

/// 注册服务, 返回true代表新注册服务, false代表服务续租
pub fn register_service(path: &str, endpoint: &str) -> bool {
    let hblt = AppGlobal::get().heart_break_live_time as i64;
    // 注册服务的过期时间
    let expire = if hblt != 0 {
        LocalTime::now().timestamp() + hblt
    } else {
        0
    };

    match get_services().get_mut(path) {
        // 路径有注册的服务
        Some(mut svr_list) => match svr_list
            .iter_mut()
            .find(|v| v.endpoint.as_str() == endpoint)
        {
            // 对应端点的服务找到，更新过期时间
            Some(svr) => {
                svr.expire = expire;
                log::trace!("注册服务: 更新服务{}:{}的过期时间", endpoint, path);
                return false;
            }
            // 找不到，创建服务并添加到链表末尾
            None => svr_list.push_back(ServiceInfo {
                endpoint: CompactString::new(endpoint),
                expire,
            }),
        },
        // 路径对应没有服务，创建服务及链表
        None => {
            let mut svr_list = ServiceInfoList::new();
            svr_list.push_back(ServiceInfo {
                endpoint: CompactString::new(endpoint),
                expire,
            });
            get_services().insert(CompactString::new(path), svr_list);
        }
    };

    true
}

/// 取消注册服务
pub fn unregister_service(path: &str, endpoint: &str) {
    if let Some(mut svr_list) = get_services().get_mut(path) {
        let old_len = svr_list.len();
        svr_list.retain(|v| v.endpoint.as_str() != endpoint);
        if old_len > svr_list.len() {
            log::trace!("删除服务：{}:{}", endpoint, path);
        }
        if svr_list.is_empty() {
            get_services().remove(path);
        }
    };
}

/// 列出当前注册的所有服务信息
pub fn service_status() -> Vec<ServiceGroup> {
    let now = LocalTime::now().timestamp();
    let mut del_keys = Vec::new();
    let services = get_services();


    let result = services
        .iter()
        .filter_map(|item| {
            let services: Vec<ServiceItem> = item
                .value()
                .iter()
                .filter(|v| v.expire == 0 || v.expire >= now)
                .map(|v| ServiceItem {
                    endpoint: v.endpoint.clone(),
                    expire: if_else!(
                        v.expire != 0,
                        Some(LocalTime::from_unix_timestamp(v.expire)),
                        None
                    ),
                })
                .collect();

            if !services.is_empty() {
                Some(ServiceGroup {
                    path: CompactString::new(item.key()),
                    services,
                })
            } else {
                del_keys.push(CompactString::new(item.key()));
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
pub fn service_query(mut path: &str) -> Option<Vec<ServiceItem>> {
    let now = LocalTime::now().timestamp();
    let services = get_services();

    while !path.is_empty() {
        if let Some(svr_list) = services.get(path) {
            let items: Vec<ServiceItem> = svr_list
                .iter()
                .filter(|s| s.expire > now || s.expire == 0)
                .map(|s| ServiceItem {
                    endpoint: s.endpoint.clone(),
                    expire: if s.expire != 0 {
                        Some(LocalTime::from_unix_timestamp(s.expire))
                    } else {
                        None
                    },
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
pub async fn proxy_handler(ctx: HttpContext) -> HttpResponse {
    let path = CompactString::new(ctx.req.uri().path());
    let path_and_query = ctx.req.uri().path_and_query().unwrap().as_str();
    let mut finded = false;

    // 获取path对应的endpoint，找不到直接返回service not found错误
    while let Some(endpoint) = get_service_endpoint(&path) {
        finded = true;
        let uri = create_uri(&endpoint, path_and_query)?;
        log_info!(ctx.id, "[FORWARD] {path} => {endpoint}");

        // 复制ctx中的req作为转发参数使用
        let mut req_mut = ctx.req.clone();
        *req_mut.uri_mut() = uri;

        match get_client().request(req_mut).await {
            // 成功后直接向客户端返回后台服务返回的数据
            Ok(res) => {
                let (parts, body) = res.into_parts();
                let body = body.collect().await?.to_bytes();
                return Ok(Response::from_parts(parts, Full::new(body)));
            }
            Err(e) => {
                unregister_service_by_endpoint(&endpoint);
                log_error!(ctx.id, "[FORWARD] {endpoint}{path} error: {e:?}");
            }
        }
    }

    if finded {
        log_info!(ctx.id, "[FORWARD] {path} service shutdown");
        Resp::fail_with_status(StatusCode::GONE, 419, "Goned")
    } else {
        log_info!(ctx.id, "[FORWARD] {path} service not found");
        Resp::fail_with_status(StatusCode::NOT_FOUND, 404, "Not Found")
    }
}

fn get_service_endpoint(mut path: &str) -> Option<CompactString> {
    let services = get_services();

    while !path.is_empty() {
        if let Some(mut svr_list) = services.get_mut(path) {
            let now = LocalTime::now().timestamp();
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

        path = &path[..path.rfind('/').unwrap_or(0)];
    }

    None
}

#[inline(never)]
fn create_uri(endpoint: &str, path_and_query: &str) -> Result<Uri> {
    let mut buf = SmallString::<[u8; 512]>::new();
    write!(buf, "http://{endpoint}{path_and_query}")?;

    buf.as_str().parse().context("parse forward uri fail")
}

/// 基于子路径的递归查找取消注册服务功能
fn unregister_service_by_endpoint(endpoint: &str) {
    get_services().retain(|_, slist| {
        slist.retain(|s| s.endpoint.as_str() != endpoint);
        !slist.is_empty()
    });
}

fn get_client() -> &'static Client<HttpConnector, Full<Bytes>> {
    CLIENT.get_or_init(|| {
        let ct: u64 = AppConf::get().conn_timeout.parse().unwrap_or(3);
        let mut hc = HttpConnector::new();
        hc.set_connect_timeout(Some(Duration::from_secs(ct)));

        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_timer(TokioTimer::new())
            .build(hc)
    })
}

fn get_services() -> &'static ServicesType {
    SERVICES.get_or_init(ServicesType::new)
}
