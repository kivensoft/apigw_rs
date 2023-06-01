use std::{
    collections::{HashMap, VecDeque},
    fmt::Write,
    time::Duration,
};
use anyhow::{Context, Result};
use compact_str::{CompactString, ToCompactString};
use httpserver::{HttpContext, ResBuiler, Response};
use hyper::{
    client::{Client, HttpConnector},
    Uri,
};
use localtime::LocalTime;
use parking_lot::Mutex;
use serde::Serialize;
use smallstr::SmallString;

use crate::AppGlobal;

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

type ServiceInfoList = VecDeque<Box<ServiceInfo>>;

lazy_static::lazy_static! {
    static ref SERVICES: Mutex<HashMap<CompactString, ServiceInfoList>> = Mutex::new(HashMap::new());
}

/// 注册服务
pub fn register_service(path: &str, endpoint: &str) {
    let hblt = AppGlobal::get().heart_break_live_time as i64;
    // 注册服务的过期时间
    let expire = if hblt != 0 {
        LocalTime::now().timestamp() + hblt
    } else {
        0
    };

    let mut services = SERVICES.lock();

    match services.get_mut(path) {
        // 路径有注册的服务
        Some(svr_list) => match svr_list.iter_mut().find(|v| v.endpoint == endpoint) {
            // 对应端点的服务找到，更新过期时间
            Some(svr) => {
                svr.expire = expire;
            }
            // 找不到，创建服务并添加到链表末尾
            None => svr_list.push_back(Box::new(ServiceInfo {
                endpoint: endpoint.to_compact_string(),
                expire,
            })),
        },
        // 路径对应没有服务，创建服务及链表
        None => {
            let mut slist = ServiceInfoList::new();
            slist.push_back(Box::new(ServiceInfo {
                endpoint: endpoint.to_compact_string(),
                expire,
            }));
            services.insert(path.to_compact_string(), slist);
        }
    };
}

/// 取消注册服务
pub fn unregister_service(path: &str, endpoint: &str) {
    let mut services = SERVICES.lock();
    let svr_list = services.get_mut(path);
    if let Some(svr_list) = svr_list {
        svr_list.retain(|v| v.endpoint != endpoint);
        if svr_list.is_empty() {
            services.remove(path);
        }
    };
}

/// 基于子路径的递归查找取消注册服务功能
fn unregister_service_by_endpoint(endpoint: &str) {
    SERVICES.lock().retain(|_, v| {
        v.retain(|s| s.endpoint.as_str() != endpoint);
        !v.is_empty()
    });
}

/// 列出当前注册的所有服务信息
pub fn service_status() -> Vec<ServiceGroup> {
    let now = LocalTime::now().timestamp();

    SERVICES
        .lock()
        .iter()
        .filter_map(|(k, v)| {
            let services: Vec<ServiceItem> = v
                .iter()
                .filter_map(|s| {
                    if s.expire > now || s.expire == 0 {
                        Some(ServiceItem {
                            endpoint: s.endpoint.clone(),
                            expire: if s.expire != 0 {
                                Some(LocalTime::from_unix_timestamp(s.expire))
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    }
                })
                .collect();

            if !services.is_empty() {
                Some(ServiceGroup {
                    path: k.to_compact_string(),
                    services,
                })
            } else {
                None
            }
        })
        .collect()
}

// 查询指定路径的可用服务信息，路径可以是子路径，系统会自动进行递归查找，直到找到最匹配的服务
pub fn service_query(path: &str) -> Option<Vec<ServiceItem>> {
    let services = SERVICES.lock();
    let mut pos = Some(path.len());

    while let Some(pos2) = pos {
        let path = &path[0..pos2];

        if let Some(svr_list) = services.get(path) {
            let now = LocalTime::now().timestamp();

            let items = svr_list
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
                .collect::<Vec<ServiceItem>>();

            return if !items.is_empty() {
                Some(items)
            } else {
                None
            };
        }

        pos = path.rfind('/');
    }

    None
}

fn get_service_endpoint(path: &str) -> Option<CompactString> {
    let mut services = SERVICES.lock();
    let mut pos = Some(path.len());

    while let Some(pos2) = pos {
        let path = &path[0..pos2];

        if let Some(svr_list) = services.get_mut(path) {
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
        }

        pos = path.rfind('/');
    }

    None
}

#[inline(never)]
fn gen_uri(endpoint: &str, path_and_query: &str) -> Result<Uri> {
    let mut buf = SmallString::<[u8; 512]>::new();
    write!(buf, "http://{endpoint}{path_and_query}")?;
    let s = buf.as_str();
    s.parse().with_context(|| format!("create forward uri error: `{s}`"))
}

pub async fn proxy_handler(mut ctx: HttpContext) -> Result<Response> {
    let path = ctx.req.uri().path().to_compact_string();
    // 获取path对应的endpoint，找不到直接返回service not found错误
    let endpoint = match get_service_endpoint(&path) {
        Some(v) => v,
        None => return Ok(ResBuiler::fail("service not found")?),
    };
    let path_and_query = ctx.req.uri().path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/");
    let uri = gen_uri(&endpoint, path_and_query)?;

    // 将ctx中的req作为转发参数使用
    *ctx.req.uri_mut() = uri;

    let mut hc = HttpConnector::new();
    hc.set_connect_timeout(Some(Duration::from_secs(
        AppGlobal::get().connect_timeout as u64,
    )));
    let client = Client::builder().build(hc);
    log::debug!("[{:08x}] FORWARD {} => {}", ctx.id(), path, endpoint);

    let req_id = ctx.id();
    match client.request(ctx.req).await {
        Ok(r) => Ok(r),
        Err(e) => {
            unregister_service_by_endpoint(&endpoint);
            log::error!("[{req_id:08x}] FORWARD {path} error: {e:?}");
            ResBuiler::internal_server_error()
        }
    }
}
