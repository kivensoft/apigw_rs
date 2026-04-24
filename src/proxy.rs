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
use fast_radix_trie::RadixMap;
use fnv::FnvHashMap;
use http_body_util::BodyExt;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use kv_axum_util::{ApiError, ReqId, bean, if_else, unix_timestamp};
use localtime::LocalDateTime;
use parking_lot::{Mutex, RwLock};
use rclite::Arc;
use smallstr::SmallString;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

use crate::{appvars::APP_VAR, auth::UserId, efmt};

/// 用于对外显示的代理配置信息
pub type EndPointDisplayVec = Vec<EndpointDisplay>;
pub type EndPointDisplayMap = FnvHashMap<String, Vec<EndpointDisplay>>;
/// 端点列表类型, 使用双端队列是因为每次做反向代理操作时需要把第一项移动到末尾, 实现轮询机制
type EndpointConfigVec = Arc<Mutex<VecDeque<EndpointConfig>>>;
/// 服务字典类型, 端点列表使用 Mutex 而不是 RwLock 是因为大部分访问都需要修改端点列表
type ServiceMap = RwLock<RadixMap<EndpointConfigVec>>;
/// 代理客户端类型
type ProxyClient = Client<HttpConnector, Body>;

/// 代理配置信息项
#[bean(ser)]
pub struct EndpointDisplay {
    pub endpoint: CompactString,
    pub expire_at: Option<LocalDateTime>,
}

#[derive(Clone)]
struct EndpointConfig {
    // 端点信息, 例如 127.0.0.1:8080
    endpoint: CompactString,
    // 基于 unix timestamp 的过期时间
    expire_at: u64,
}

/// 已注册的服务列表
static SERVICES: LazyLock<ServiceMap> = LazyLock::new(|| RwLock::new(RadixMap::new()));
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
    let expire_at = Now::new().expire_at(ttl as u64);
    let path = normalize_for_map(path);

    // 获取路径对应的端点列表, 不存在则新建
    let endpoint_cfg_vec = SERVICES
        .write()
        .entry(&path)
        .or_insert_with(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone();

    let mut endpoint_cfg_vec_guard = endpoint_cfg_vec.lock();

    for endpoint_cfg in endpoint_cfg_vec_guard.iter_mut() {
        if endpoint == endpoint_cfg.endpoint {
            endpoint_cfg.expire_at = expire_at;
            debug!(%path, %endpoint, %ttl, "代理服务心跳更新成功");
            // 返回 false, 表示是更新反向代理服务信息而不是新建
            return false;
        }
    }

    let endpoint_cfg = EndpointConfig { endpoint: endpoint.into(), expire_at };
    endpoint_cfg_vec_guard.push_back(endpoint_cfg);
    debug!(%path, %endpoint, %ttl, "代理服务新注册成功");
    true
}

/// 取消注册服务
///
/// ### 参数
/// * `endpoint` - 服务端点, 例如: "127.0.0.1:8080"
pub fn unregister_service(endpoint: &str) {
    let mut wait_del_paths = SmallVec::<[String; 32]>::new();

    // 遍历所有代理, 找到匹配的 endpoint, 将对应的路径加入待删除路径列表
    for (path, cfg_vec) in SERVICES.read().iter() {
        let mut guard = cfg_vec.lock();
        let old_len = guard.len();
        guard.retain(|cfg| cfg.endpoint != endpoint);
        if old_len != guard.len() {
            wait_del_paths.push(unsafe { String::from_utf8_unchecked(path) });
        }
    }

    // 输出被移除的代理服务信息到日志中
    let mut remove_endpoint_paths = SmallString::<[u8; 512]>::new();
    for path in &wait_del_paths {
        remove_endpoint_paths.push_str(normalize_for_display(path));
    }

    // 删除所有匹配的 endpoint 对应的 path (当代理列表为空时)
    let mut remove_paths = SmallString::<[u8; 512]>::new();
    let mut srv_guard = SERVICES.write();
    for path in wait_del_paths {
        if let Some(cfg_vec) = srv_guard.get(&path)
            && cfg_vec.lock().is_empty()
        {
            remove_paths.push_str(normalize_for_display(&path));
            srv_guard.remove(&path);
        }
    }
    drop(srv_guard);

    // 输出已删除的路径列表
    debug!(%remove_endpoint_paths, %endpoint, "移除代理服务信息");
    debug!(%remove_endpoint_paths, "删除代理列表为空的路径");
}

/// 列出当前注册的所有服务信息
pub fn service_list() -> EndPointDisplayMap {
    let now = Now::new();
    let srv_guard = SERVICES.read();

    let mut valid_endpoint_map = {
        let cap = (srv_guard.len() as f64 / 0.75).ceil() as usize;
        EndPointDisplayMap::with_capacity_and_hasher(cap, Default::default())
    };

    for (key, value) in srv_guard.iter() {
        if let Some(valid_endpoints) = copy_valid_endpionts(value, &now) {
            let mut path = unsafe { String::from_utf8_unchecked(key) };
            normalize_for_display2(&mut path);
            valid_endpoint_map.insert(path, valid_endpoints);
        }
    }

    valid_endpoint_map
}

// 查询指定路径的可用服务信息，路径可以是子路径，系统会自动进行递归查找，直到找到最匹配的服务
pub fn service_query(path: &str) -> Option<Vec<EndpointDisplay>> {
    let endpoints = match SERVICES.read().get_longest_common_prefix(path) {
        Some((_, value)) => value.clone(),
        None => return None,
    };

    let now = Now::new();
    let mut valid_endpoints = Vec::with_capacity(32);

    for endpoint in endpoints.lock().iter() {
        if now.before(endpoint.expire_at) {
            valid_endpoints.push(EndpointDisplay {
                endpoint: endpoint.endpoint.clone(),
                expire_at: expire_at_to_datetime(endpoint.expire_at),
            });
        }
    }

    Some(valid_endpoints)
}

/// 清理反向代理列表中的过期项
pub fn services_clean() {
    // 函数运行标志, 为 true 时, 表示程序正在运行
    static RUNNING: AtomicBool = AtomicBool::new(false);

    let result = RUNNING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
    if result.is_err() {
        return;
    }

    let mut del_keys = SmallVec::<[String; 32]>::new();
    let mut del_endpoints = SmallVec::<[CompactString; 32]>::new();
    let now = Now::new();

    for (key, value) in SERVICES.read().iter() {
        let mut endpoints = value.lock();

        // 清理过期服务
        endpoints.retain(|cfg| {
            if now.before(cfg.expire_at) {
                true
            } else {
                del_endpoints.push(cfg.endpoint.clone());
                false
            }
        });

        // 如果清理后服务列表为空, 则记录将被删除的路径, 后续日志输出需要
        if endpoints.is_empty() {
            let mut path = unsafe { String::from_utf8_unchecked(key) };
            normalize_for_display2(&mut path);
            del_keys.push(path);
        }
    }

    if !del_keys.is_empty() {
        for path in del_keys {
            debug!(%path, "清理反向代理服务");
        }
    }

    // 恢复运行标志为 false
    RUNNING.store(false, Ordering::Release);
}

/// 反向代理函数
///
/// 处理来自客户端的请求，并将其转发到对应的服务端点
/// 如果服务端点不存在或转发失败，将返回相应的错误信息
pub async fn proxy_handler(req: Request, rid: ReqId, uid: UserId) -> Response {
    let uri = req.uri();
    let path = uri.path();

    // 查询已注册的反向代理服务, 按最长路径匹配优先, 得到本次反向代理的服务器信息
    let endpoint = match find_endpoint(path) {
        Some(s) => s,
        None => {
            // 匹配失败, 直接返回 404
            debug!(%path, "未配置反向代理服务");
            return ApiError::not_found().into_response();
        },
    };
    info!(%path, %endpoint, "⚡转发反向代理请求");

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // 构建目标 URI
    let target_uri = match build_target_uri(&endpoint, path_and_query) {
        Ok(uri) => uri,
        Err(err) => {
            warn!(%err, "构建代理请求URI失败");
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

    // 发送请求到上游, 发送出现错误则说明服务失效, 删除该服务
    // 之所以不重试, 是考虑到 clone request 需要时间与内存, 简单处理了事
    match get_client().request(new_req).await {
        Ok(res) => {
            // 不要通过 body.collect() 方法返回, 那样会占用大量内存
            // 应使用 stream 流方式返回, 避免大量内存占用
            let (parts, body) = res.into_parts();
            let stream_body = Body::from_stream(body.into_data_stream());
            Response::from_parts(parts, stream_body)
        },
        Err(err) => {
            // 删除端点的注册信息: 当服务不存在(未启动)或者连接超时或者其它网络错误
            unregister_service(&endpoint);

            warn!(%err, "反向代理请求失败");
            ApiError::error_with_status(StatusCode::BAD_GATEWAY, "上游服务不可用").into_response()
        },
    }
}

struct Now(u64);

impl Now {
    fn new() -> Self {
        Self(unix_timestamp())
    }

    // 判断给定的过期时间戳是否依旧有效(尚未过期)
    fn before(&self, expire_at: u64) -> bool {
        expire_at == 0 || self.0 <= expire_at
    }

    fn expire_at(&self, expire_secs: u64) -> u64 {
        if expire_secs > 0 {
            self.0 + expire_secs
        } else {
            0
        }
    }
}

/// 生成unix timestamp过期时间的本地时间格式
fn expire_at_to_datetime(expire: u64) -> Option<LocalDateTime> {
    if expire == 0 {
        None
    } else {
        Some(LocalDateTime::from_unix_timestamp(expire as i64))
    }
}

/// 根据api路径查找对应的服务端点, 如果同一个路径有多个服务端点, 则采用轮询方式
fn find_endpoint(path: &str) -> Option<CompactString> {
    let now = Now::new();
    let path = normalize_for_map(path);

    let endpoints = match SERVICES.read().get_longest_common_prefix(&path) {
        Some((_, value)) => value.clone(),
        None => return None,
    };

    let mut endpoints_guard = endpoints.lock();

    while let Some(endpoint) = endpoints_guard.pop_front() {
        // 检查服务是否过期, 只返回尚未过期的反向代理服务端点
        if now.before(endpoint.expire_at) {
            let endpoint_clone = endpoint.endpoint.clone();
            endpoints_guard.push_back(endpoint);
            return Some(endpoint_clone);
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

fn copy_valid_endpionts(endpoints: &EndpointConfigVec, now: &Now) -> Option<EndPointDisplayVec> {
    let guard = endpoints.lock();

    if guard.is_empty() {
        return None;
    }

    let mut result = Vec::with_capacity(guard.len());

    for endpoint in guard.iter() {
        // 只复制尚未过期的服务
        if now.before(endpoint.expire_at) {
            result.push(EndpointDisplay {
                endpoint: endpoint.endpoint.clone(),
                expire_at: expire_at_to_datetime(endpoint.expire_at),
            });
        }
    }

    if_else!(!result.is_empty(), Some(result), None)
}

/// 规范化路径, '/' 开头, '/' 结尾
fn normalize_for_map(path: &str) -> CompactString {

    let mut result = CompactString::default();
    if !path.is_empty() {
        if path.as_bytes()[0] != b'/' {
            result.push('/');
        }

        result.push_str(path);

        if result.as_bytes()[result.len() - 1] != b'/' {
            result.push('/');
        }
    }

    result
}

/// 删除末尾的 '/', 返回用户友好的可显示的路径表达
fn normalize_for_display(path: &str) -> &str {
    if !path.is_empty() && path.as_bytes()[path.len() - 1] == b'/' {
        &path[..path.len() - 1]
    } else {
        path
    }
}

/// 删除末尾的 '/', 返回用户友好的可显示的路径表达
fn normalize_for_display2(path: &mut String) {
    if !path.is_empty() && path.as_bytes()[path.len() - 1] == b'/' {
        path.truncate(path.len() - 1);
    }
}

fn get_client() -> &'static ProxyClient {
    CLIENT.get_or_init(|| {
        let timeout: u64 = APP_VAR.get().srv_conn_timeout as u64;
        let mut connector = HttpConnector::new();

        // 设置连接超时时间
        connector.set_connect_timeout(Some(Duration::from_secs(timeout)));

        Client::builder(TokioExecutor::new())
            // 配置连接池：空闲连接存活时间
            .pool_idle_timeout(Duration::from_secs(60))
            // 配置连接池：每个主机最大空闲连接数
            .pool_max_idle_per_host(16)
            // 配置 pool_timer：用于清理空闲连接（关键配置）
            .pool_timer(TokioTimer::new())
            // 构建连接器
            .build(connector)
    })
}
