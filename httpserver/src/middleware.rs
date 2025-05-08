use std::{
    io::Write,
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use compact_str::CompactString;
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, header::HeaderValue};
use parking_lot::RwLock;

use crate::{
    if_else, is_form_or_json, map_infallible, resp::bytes_to_body, BodyData, HttpContext,
    HttpResponse, Next, Response, APPLICATION_JSON_PREFIX, CONTENT_TYPE,
};

/// middleware interface
#[async_trait::async_trait]
pub trait HttpMiddleware: Send + Sync + 'static {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse;
}

struct LogData {
    id: u32,
    start_time: Instant,
    method: Method,
    path: CompactString,
    ip: Ipv4Addr,
}

/// Log middleware，访问日志中间件
pub struct AccessLog {
    ignore_flag: AtomicBool,
    ignore_paths: RwLock<Vec<String>>,
}

impl AccessLog {
    pub fn new() -> Self {
        Self {
            ignore_flag: AtomicBool::new(false),
            ignore_paths: RwLock::new(Vec::new()),
        }
    }

    /// 添加忽略日志的路径
    pub fn add_ignore(&self, path: &str) {
        self.ignore_paths.write().push(String::from(path));
    }

    /// 删除忽略日志的路径
    pub fn remove_ignore(&mut self, path: &str) {
        self.ignore_paths.write().retain(|x| x != path);
    }

    /// 设置全局忽略日志标记(true: 忽略, false: 不忽略)
    pub fn set_ignore_flag(&self, flag: bool) {
        self.ignore_flag.store(flag, Ordering::Release);
    }

    fn log_request(&self, ctx: &HttpContext) {
        let id = ctx.id;
        let is_debug = log::log_enabled!(log::Level::Debug);

        log::debug!(
            "[REQ-{}] {} \x1b[33m{}\x1b[0m",
            id,
            ctx.parts.method,
            Self::get_real_path(ctx)
        );

        // 记录请求参数日志
        if is_debug {
            if let Some(query) = ctx.parts.uri.query() {
                if !query.is_empty() {
                    log::debug!("[REQ-{id}] [QUERY] \x1b[35m{query}\x1b[0m");
                }
            }
        }

        // 记录请求头
        if log::log_enabled!(log::Level::Trace) {
            Self::log_headers(id, &ctx.parts.headers, true);
        }

        // 记录body
        if is_debug && is_form_or_json(&ctx.parts.headers) {
            if let BodyData::Bytes(bytes) = &ctx.body {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    log::debug!("[REQ-{id}] [BODY] \x1b[35m{text}\x1b[0m");
                } else {
                    log::warn!("reponse body is not utf8");
                }
            }
        }
    }

    async fn log_response(res: HttpResponse, log_data: &LogData) -> HttpResponse {
        let id = log_data.id;
        // 接口调用耗时
        let ms = log_data.start_time.elapsed().as_millis();

        // 记录接口调用结果及耗时
        match &res {
            Ok(res) => {
                let status_code = res.status().as_u16();
                let c = if_else!(res.status() == hyper::StatusCode::OK, 2, 1);
                log::info!(
                    "[REQ-{}] {} \x1b[34m{} \x1b[3{}m{}\x1b[0m {}ms, client: {}",
                    id,
                    log_data.method,
                    log_data.path,
                    c,
                    status_code,
                    ms,
                    log_data.ip
                );
            }
            Err(e) => log::error!(
                "[REQ-{}] {} \x1b[34m{}\x1b[0m \x1b[31m500\x1b[0m {}ms, error: {:?}",
                id,
                log_data.method,
                log_data.path,
                ms,
                e
            ),
        };

        // 记录回复结果日志
        if log::log_enabled!(log::Level::Debug) {
            match res {
                Ok(res) => {
                    // 记录回复的头部
                    if log::log_enabled!(log::Level::Trace) {
                        Self::log_headers(id, res.headers(), false);
                    }

                    // 记录回复内容
                    if let Some(ct) = res.headers().get(CONTENT_TYPE) {
                        let cts = ct.as_bytes();
                        if cts.starts_with(APPLICATION_JSON_PREFIX.as_bytes()) {
                            let res = Self::log_resp_body(res, id).await;
                            return Ok(res);
                        }
                    }
                    return Ok(res);
                }
                Err(e) => return Err(e),
            }
        }

        res
    }

    fn log_headers(id: u32, headers: &HeaderMap<HeaderValue>, is_req: bool) {
        let mut buf = Vec::with_capacity(512);
        for (name, value) in headers {
            let name = name.as_str();
            if let Ok(value) = std::str::from_utf8(value.as_bytes()) {
                let _ = write!(&mut buf, "\n\t{name}: {value}");
            } else {
                let req_type = if_else!(is_req, "request", "response");
                log::warn!("{req_type} header {name} is not utf8");
            }
        }
        let header_name = if_else!(is_req, "HEADER", "RESP-HEADER");
        let text = unsafe { String::from_utf8_unchecked(buf) };
        log::trace!("[REQ-{id}] [{header_name}] ->{text}");
    }

    async fn log_resp_body(resp: Response, id: u32) -> Response {
        let (parts, body) = resp.into_parts();
        let bytes = match body.collect().await {
            Ok(body) => {
                let bytes = body.to_bytes();
                match std::str::from_utf8(&bytes) {
                    Ok(s) => log::debug!("[REQ-{id}] [RESP] \x1b[35m{s}\x1b[0m"),
                    Err(_) => {
                        #[cfg(not(feature = "english"))]
                        log::warn!("http回复消息是无效utf8字符串");
                        #[cfg(feature = "english")]
                        log::warn!("http reply message is an invalid utf8 string");
                    }
                }
                bytes
            }
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log::error!("读取http回复消息失败: {e:?}");
                #[cfg(feature = "english")]
                log::error!("Failed to read the http reply message: {e:?}");
                Bytes::new()
            }
        };

        Response::from_parts(parts, bytes_to_body(bytes))
    }

    fn is_ignore(&self, ctx: &HttpContext) -> bool {
        if self.ignore_flag.load(Ordering::Acquire) {
            return true;
        }

        let path = Self::get_real_path(ctx);
        let ignore_paths = self.ignore_paths.read();
        for ignore_path in ignore_paths.iter() {
            if path.starts_with(ignore_path) {
                let plen = path.len();
                let ilen = ignore_path.len();
                if plen == ilen || ignore_path.as_bytes()[ilen - 1] == b'/' {
                    return true;
                }
            }
        }

        false
    }

    fn get_real_path(ctx: &HttpContext) -> &str {
        let path = ctx.parts.uri.path();
        let clen = ctx.context_path_len;
        if_else!(clen > 0, &path[(clen - 1) as usize..], path)
    }
}

#[async_trait::async_trait]
impl HttpMiddleware for AccessLog {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        if self.is_ignore(&ctx) {
            next.run(ctx).await
        } else {
            let log_data = LogData {
                id: ctx.id,
                start_time: std::time::Instant::now(),
                method: ctx.parts.method.clone(),
                path: CompactString::new(Self::get_real_path(&ctx)),
                ip: ctx.remote_ip(),
            };

            self.log_request(&ctx);
            let res = next.run(ctx).await;
            Self::log_response(res, &log_data).await
        }
    }
}

/// Cors middleware，跨域访问中间件
pub struct CorsMiddleware;

#[async_trait::async_trait]
impl HttpMiddleware for CorsMiddleware {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        use hyper::header::{
            ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_ORIGIN, ALLOW,
        };

        let is_options = ctx.parts.method == hyper::Method::OPTIONS;
        let allow_host = HeaderValue::from_str("*").unwrap();
        // options请求，无需处理，直接返回
        if is_options {
            Ok(hyper::Response::builder()
                .header(ACCESS_CONTROL_ALLOW_HEADERS, allow_host.clone())
                .header(ACCESS_CONTROL_ALLOW_METHODS, allow_host.clone())
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, allow_host.clone())
                .header(ALLOW, HeaderValue::from_str("GET,HEAD,OPTIONS").unwrap())
                .body(Empty::new().map_err(map_infallible).boxed())?)
        } else {
            let mut res = next.run(ctx).await?;
            let headers = res.headers_mut();
            headers.append(ACCESS_CONTROL_ALLOW_HEADERS, allow_host.clone());
            headers.append(ACCESS_CONTROL_ALLOW_METHODS, allow_host.clone());
            headers.append(ACCESS_CONTROL_ALLOW_ORIGIN, allow_host.clone());
            Ok(res)
        }
    }
}
