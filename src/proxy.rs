use std::{
    collections::VecDeque,
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use compact_str::CompactString;
use dashmap::DashMap;
use fnv::FnvHashMap;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use kv_axum_util::{ApiError, ReqId, bean, if_else, unix_timestamp};
use localtime::LocalDateTime;
use parking_lot::Mutex;
use smallstr::SmallString;
use smallvec::SmallVec;

use crate::{appvars::APP_VAR, auth::UserId, efmt, path_iter::PathIter};

type ProxyClient = Client<HttpConnector, Body>;

#[bean(ser)]
pub struct EndpointDisplay {
    pub endpoint: CompactString,
    pub expire_at: Option<LocalDateTime>,
}

pub type EndPointDisplayMap = FnvHashMap<CompactString, Vec<EndpointDisplay>>;

#[derive(Clone)]
struct EndpointConfig {
    // 端点信息, 例如 127.0.0.1:8080
    endpoint: CompactString,
    // 基于 unix timestamp 的过期时间
    expire_at: u64,
}

/// 端点列表类型, 使用双端队列是因为每次做反向代理操作时需要把第一项移动到末尾, 实现轮询机制
type EndpointConfigVec = VecDeque<EndpointConfig>;
/// 服务字典类型, 端点列表使用 Mutex 而不是 RwLock 是因为大部分访问都需要修改端点列表
type ServiceMap = DashMap<CompactString, Mutex<EndpointConfigVec>>;

/// 已注册的服务列表
static SERVICE_MAP: LazyLock<ServiceMap> = LazyLock::new(DashMap::new);
/// http request 请求的客户端，内部使用缓存池
static CLIENT: OnceLock<ProxyClient> = OnceLock::new();

/// 注册服务, 返回true代表新注册服务, false代表服务续租
///
/// ### 参数
/// * `path` - 服务路径, 例如: "/api/sys"
/// * `endpoint` - 服务端点, 例如: "127.0.0.1:8080"
/// * `ttl` - 服务有效期(单位: 秒)
pub fn register_service(path: &str, endpoint: &str, ttl: u32) -> bool {
    // 注册服务的过期时间
    let expire_at = if_else!(ttl == 0, 0, unix_timestamp() + (ttl as u64));

    // 路径有注册的服务
    if let Some(mutex_val) = SERVICE_MAP.get(path) {
        let mut endpoints = mutex_val.lock();
        // 对应端点的服务找到，更新过期时间, 返回false，表示续租
        if let Some(srv) = endpoints.iter_mut().find(|v| v.endpoint.as_str() == endpoint) {
            srv.expire_at = expire_at;
            tracing::debug!(path = %path, endpoint = %endpoint, ttl = %ttl, "代理服务心跳更新成功");
            return false;
        }

        // 找不到，创建服务并添加到链表末尾
        endpoints.push_back(EndpointConfig { endpoint: endpoint.into(), expire_at });
    } else {
        // 路径对应没有服务，创建服务及链表
        let mut endpoints = EndpointConfigVec::new();
        endpoints.push_back(EndpointConfig { endpoint: endpoint.into(), expire_at });
        SERVICE_MAP.insert(path.into(), Mutex::new(endpoints));
    }

    tracing::debug!(path = %path, endpoint = %endpoint, ttl = %ttl, "代理服务新注册成功");
    true
}

/// 取消注册服务
///
/// ### 参数
/// * `endpoint` - 服务端点, 例如: "127.0.0.1:8080"
pub fn unregister_service(endpoint: &str) {
    let mut wait_del_keys = SmallVec::<[CompactString; 32]>::new();
    let mut remove_from_keys = SmallVec::<[CompactString; 32]>::new();

    for entry in SERVICE_MAP.iter() {
        let mut endpoints = entry.value().lock();
        let old_len = endpoints.len();

        endpoints.retain(|v| v.endpoint.as_str() != endpoint);

        if old_len > endpoints.len() {
            remove_from_keys.push(entry.key().clone());
        }

        // 如果服务列表为空, 记录需要删除的键, 后续进行删除
        if endpoints.is_empty() {
            wait_del_keys.push(entry.key().clone());
        }
    }

    // 删除 endpoints 为空的项
    for key in &wait_del_keys {
        SERVICE_MAP.remove_if(key, |_, v| v.lock().is_empty());
    }

    // 记录日志
    for path in remove_from_keys {
        tracing::debug!(%path, %endpoint, "删除被代理服务成功");
    }
    for path in wait_del_keys {
        tracing::debug!(%path, %endpoint, "删除被代理服务列表为空的项成功")
    }
}

/// 列出当前注册的所有服务信息
pub fn service_list() -> EndPointDisplayMap {
    let now = Now::new();
    let mut result = {
        let cap = (SERVICE_MAP.len() as f64 / 0.75).ceil() as usize;
        EndPointDisplayMap::with_capacity_and_hasher(cap, Default::default())
    };

    for entry in SERVICE_MAP.iter() {
        let endpoints = entry.lock();

        // 如果端点列表为空, 则直接进行下一次循环
        let len = endpoints.len();
        if len == 0 {
            continue;
        }

        let mut new_endpoints = Vec::with_capacity(len);

        // 复制尚未过期的所有端点到新的端点列表
        for endpoint in endpoints.iter() {
            // 只复制尚未过期的服务
            if now.before(endpoint.expire_at) {
                new_endpoints.push(EndpointDisplay {
                    endpoint: endpoint.endpoint.clone(),
                    expire_at: make_expire_at(endpoint.expire_at),
                });
            }
        }

        // 释放锁
        drop(endpoints);

        if !new_endpoints.is_empty() {
            result.insert(entry.key().clone(), new_endpoints);
        }
    }

    result
}

// 查询指定路径的可用服务信息，路径可以是子路径，系统会自动进行递归查找，直到找到最匹配的服务
pub fn service_query(path: &str) -> Option<Vec<EndpointDisplay>> {
    let now = Now::new();

    for p in PathIter::new(path) {
        if let Some(mutex_val) = SERVICE_MAP.get(p) {
            let endpoints = mutex_val.lock();
            let mut new_endpoints = Vec::with_capacity(endpoints.len());

            for endpoint in endpoints.iter() {
                if now.before(endpoint.expire_at) {
                    new_endpoints.push(EndpointDisplay {
                        endpoint: endpoint.endpoint.clone(),
                        expire_at: make_expire_at(endpoint.expire_at),
                    });
                }
            }

            if !new_endpoints.is_empty() {
                return Some(new_endpoints);
            }
        }
    }

    None
}

/// 清理反向代理列表中的过期项
pub fn services_clean() {
    static RUNNING: AtomicBool = AtomicBool::new(false);

    let result = RUNNING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
    if result.is_err() {
        return;
    }

    let mut del_keys = SmallVec::<[CompactString; 32]>::new();
    let now = Now::new();

    SERVICE_MAP.retain(|k, v| {
        let mut endpoints = v.lock();
        // 清理过期服务
        endpoints.retain(|v| now.before(v.expire_at));
        // 如果清理后服务列表为空, 则记录将被删除的路径, 后续日志输出需要
        let ret = !endpoints.is_empty();
        if !ret {
            del_keys.push(k.clone());
        }
        ret
    });

    if !del_keys.is_empty() {
        for k in del_keys {
            tracing::debug!(path = %k, "清理反向代理服务");
        }
    }
}

/// 反向代理函数
///
/// 处理来自客户端的请求，并将其转发到对应的服务端点
/// 如果服务端点不存在或转发失败，将返回相应的错误信息
pub async fn proxy_handler(req: Request, rid: ReqId, uid: UserId) -> Response {
    let uri = req.uri();
    let path = uri.path();

    // 查询已注册的反向代理服务, 按最长路径匹配优先, 得到本次反向代理的服务器信息
    let endpoint = match poll_endpoint(path) {
        Some(s) => s,
        None => {
            // 匹配失败, 直接返回 404
            tracing::debug!(path = %path, "未配置反向代理服务");
            return ApiError::not_found().into_response();
        },
    };
    tracing::info!(path = %path, endpoint = %endpoint, "转发反向代理请求");

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // 构建目标 URI
    let target_uri = match build_target_uri(&endpoint, path_and_query) {
        Ok(uri) => uri,
        Err(e) => {
            tracing::warn!(err = %e, "构建代理请求URI失败");
            return ApiError::error("构建代理请求URI失败").into_response();
        },
    };

    // 创建新的请求
    let (mut parts, body) = req.into_parts();
    // 替换uri
    parts.uri = target_uri;
    // 请求头添加 x-req-id, x-uid 两个字段
    parts.headers.append("x-req-id", rid.0.into());
    parts.headers.append("x-uid", uid.0.into());
    let new_req = Request::from_parts(parts, body);

    // 发送请求到上游
    match get_client().request(new_req).await {
        Ok(res) => {
            res.into_response()
        },
        Err(e) => {
            tracing::warn!(err = %e, "上游请求失败");
            ApiError::error_with_status(StatusCode::BAD_GATEWAY, "上游服务不可用")
                .into_response()
        },
    }
}

struct Now(u64);

impl Now {
    fn new() -> Self {
        Self(unix_timestamp())
    }

    fn before(&self, expire: u64) -> bool {
        expire == 0 || self.0 <= expire
    }
}

/// 生成unix timestamp过期时间的本地时间格式
fn make_expire_at(expire: u64) -> Option<LocalDateTime> {
    if expire == 0 {
        return None;
    }
    Some(LocalDateTime::from_unix_timestamp(expire as i64))
}

/// 轮询指定服务的端点
fn poll_endpoint(path: &str) -> Option<CompactString> {
    let mut del_keys = SmallVec::<[CompactString; 32]>::new();

    for p in PathIter::new(path) {
        if let Some(mutex_val) = SERVICE_MAP.get(p) {
            let mut endpoints = mutex_val.lock();
            let now = unix_timestamp();
            while let Some(endpoint) = endpoints.pop_front() {
                if endpoint.expire_at == 0 || endpoint.expire_at >= now {
                    let res = endpoint.endpoint.clone();
                    endpoints.push_back(endpoint);
                    return Some(res);
                }
            }

            if endpoints.is_empty() {
                del_keys.push(p.into());
            }
        }
    }

    if !del_keys.is_empty() {
        for key in del_keys {
            SERVICE_MAP.remove(&key);
            tracing::debug!(path = %key, "移除反向代理列表为空的项");
        }
    }

    None
}

/// 构建目标 URI
fn build_target_uri(endpoint: &str, path_and_query: &str) -> Result<Uri> {
    let mut buf = SmallString::<[u8; 256]>::new();
    buf.push_str("http://");
    buf.push_str(endpoint);
    buf.push_str(path_and_query);
    buf.parse().with_context(|| efmt!("构建 URI 失败"))
}

fn get_client() -> &'static ProxyClient {
    CLIENT.get_or_init(|| {
        let timeout: u64 = APP_VAR.get().srv_conn_timeout as u64;
        let mut connector = HttpConnector::new();

        // 设置连接超时时间
        connector.set_connect_timeout(Some(Duration::from_secs(timeout)));

        Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(32)
            .pool_timer(TokioTimer::new())
            .build(connector)
    })
}
