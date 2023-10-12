use anyhow::{Context, Result};
use compact_str::{CompactString, ToCompactString};
use httpserver::{HttpContext, Resp, Response};
use hyper::{
    client::{Client, HttpConnector},
    StatusCode, Uri, body::to_bytes, Body,
};
use localtime::LocalTime;
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::Mutex;
use serde::Serialize;
use smallstr::SmallString;
use std::{
    collections::{VecDeque, HashMap},
    fmt::Write,
    time::Duration,
};

use crate::AppGlobal;

type ServiceInfoList = VecDeque<Box<ServiceInfo>>;
type ServicesType = Mutex<HashMap<CompactString, ServiceInfoList>>;

static SERVICES: Lazy<ServicesType> = Lazy::new(|| Mutex::new(HashMap::default()));
static CLIENT: OnceCell<Client<HttpConnector>> = OnceCell::new();

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

/// 初始化客户端对象, 参数为连接超时设置
pub fn init_client(val: Option<Duration>) {
    let mut hc = HttpConnector::new();
    hc.set_connect_timeout(val);
    CLIENT.set(Client::builder().build(hc)).expect("init http client error");
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

    let mut ret = true;
    let mut services = SERVICES.lock();

    match services.get_mut(path) {
        // 路径有注册的服务
        Some(svr_list) => match svr_list.iter_mut().find(|v| v.endpoint == endpoint) {
            // 对应端点的服务找到，更新过期时间
            Some(svr) => {
                svr.expire = expire;
                ret = false;
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

    ret
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

/// 列出当前注册的所有服务信息
pub fn service_status() -> Vec<ServiceGroup> {
    let now = LocalTime::now().timestamp();

    SERVICES.lock().iter()
        .filter_map(|(k, v)| {
            let services: Vec<ServiceItem> = v.iter()
                .filter_map(|s| {
                    if s.expire < now && s.expire != 0 {
                        return None;
                    }

                    Some(ServiceItem {
                        endpoint: s.endpoint.clone(),
                        expire: if s.expire != 0 {
                            Some(LocalTime::from_unix_timestamp(s.expire))
                        } else {
                            None
                        },
                    })
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

            let items = svr_list.iter()
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

            return if !items.is_empty() { Some(items) } else { None };
        }

        pos = path.rfind('/');
    }

    None
}

pub async fn proxy_handler(mut ctx: HttpContext) -> Result<Response> {
    if log::log_enabled!(log::Level::Trace) {
        ctx = log_request(ctx).await;
    }

    let path = ctx.req.uri().path().to_compact_string();
    // 获取path对应的endpoint，找不到直接返回service not found错误
    let endpoint = match get_service_endpoint(&path) {
        Some(v) => v,
        None => return Resp::fail_with_status(StatusCode::NOT_FOUND, 404, "Not Found"),
    };

    let path_and_query = ctx.req.uri().path_and_query().map(|v| v.as_str())
        .unwrap_or("/");
    let uri = gen_uri(&endpoint, path_and_query)?;

    // 将ctx中的req作为转发参数使用
    *ctx.req.uri_mut() = uri;
    log::debug!("[{:08x}] FORWARD {} => {}", ctx.id, path, endpoint);

    let client = CLIENT.get().expect("uninit http client");
    let req_id = ctx.id;

    match client.request(ctx.req).await {
        Ok(r) => Ok(
            if log::log_enabled!(log::Level::Trace) {
                log_response(req_id, r).await
            } else {
                r
            }
        ),
        Err(e) => {
            unregister_service_by_endpoint(&endpoint);
            log::error!("[{req_id:08x}] FORWARD {path} error: {e:?}");
            Resp::internal_server_error()
        }
    }
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
    s.parse()
        .with_context(|| format!("create forward uri error: `{s}`"))
}

/// 基于子路径的递归查找取消注册服务功能
fn unregister_service_by_endpoint(endpoint: &str) {
    SERVICES.lock().retain(|_, v| {
        v.retain(|s| s.endpoint.as_str() != endpoint);
        !v.is_empty()
    });
}

async fn log_request(mut ctx: HttpContext) -> HttpContext {
    let req = &ctx.req;
    let mut text = String::new();

    // 输出header
    write!(text, "{}http request[{}] >>>{}\n",
        ansicolor::G,
        ctx.id,
        ansicolor::Z,
    ).unwrap();
    write!(text, "{} {} {:?}\n",
        req.method(),
        req.uri().path_and_query().unwrap(),
        req.version()
    ).unwrap();

    for (k, v) in req.headers() {
        write!(text, "{}: {}\n", k.as_str(), v.to_str().unwrap()).unwrap();
    }

    text.push('\n');

    // 输出body
    let (parts, body) = ctx.req.into_parts();
    let body = to_bytes(body).await.unwrap();

    match String::from_utf8(body.to_vec()) {
        Ok(s) => text.push_str(&s),
        Err(_) => text.push_str("<binary>"),
    }

    log::trace!("{}", text);

    let body = Body::from(body);
    ctx.req = hyper::Request::from_parts(parts, body);
    ctx
}

async fn log_response(req_id: u32, res: Response) -> Response {
    let mut text = String::new();

    // 输出header
    write!(text, "{}http response[{}] >>>{}\n",
        ansicolor::B,
        req_id,
        ansicolor::Z,
    ).unwrap();
    write!(text, "{:?} {}\n",
        res.version(),
        res.status().to_string(),
    ).unwrap();

    for (k, v) in res.headers() {
        write!(text, "{}: {}\n", k.as_str(), v.to_str().unwrap()).unwrap();
    }

    text.push('\n');

    // 输出body
    let (parts, body) = res.into_parts();
    let body = to_bytes(body).await.unwrap();

    match String::from_utf8(body.to_vec()) {
        Ok(s) => text.push_str(&s),
        Err(_) => text.push_str("<binary>"),
    }

    log::trace!("{}", text);

    Response::from_parts(parts, Body::from(body))
}
