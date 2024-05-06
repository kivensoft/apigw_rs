//! http server
mod cancel;
mod httpcontext;
mod httperror;
mod macros;
mod middleware;
mod resp;

use anyhow::{Error, Result};
use compact_str::CompactString;
use fnv::FnvHashMap;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    sync::{atomic::AtomicU32, Arc},
};
use tokio::net::{TcpListener, TcpStream};

pub use cancel::{CancelManager, CancelSender, new_cancel};
pub use compact_str;
pub use hyper::body::Bytes;
pub use middleware::{AccessLog, CorsMiddleware, HttpMiddleware};
pub use resp::{ApiResult, Resp};
pub use httpcontext::HttpContext;
pub use httperror::HttpError;

/// http header "Content-Type"
pub const CONTENT_TYPE: &str = "Content-Type";
/// http header "applicatoin/json; charset=UTF-8"
pub const APPLICATION_JSON: &'static str = "applicatoin/json; charset=UTF-8";

// Simplified declaration
pub type Request = hyper::Request<Full<Bytes>>;
pub type Response = hyper::Response<Full<Bytes>>;
pub type HttpResponse = Result<Response>;
pub type BoxHttpHandler = Box<dyn HttpHandler>;

type HttpCtxAttrs = Option<HashMap<CompactString, Value>>;
type Router = FnvHashMap<CompactString, BoxHttpHandler>;

// use for HttpServer.run_with_callback
#[async_trait::async_trait]
pub trait RunCallback {
    async fn handle(self) -> Result<()>;
}

/// api function interface
#[async_trait::async_trait]
pub trait HttpHandler: Send + Sync + 'static {
    async fn handle(&self, ctx: HttpContext) -> HttpResponse;
}

/// http request process object
pub struct Next<'a> {
    pub endpoint: &'a dyn HttpHandler,
    pub next_middleware: &'a [Box<dyn HttpMiddleware>],
}

/// 路由匹配模式
pub enum FuzzyFind {
    /// 精确匹配
    None,
    /// 模糊匹配，支持1级子路径
    One,
    /// 模糊匹配，支持多级子路径
    Many,
}

/// http server
pub struct HttpServer {
    id:                 AtomicU32,                      // 自增的请求id
    count:              AtomicU32,                      // 当前连接总数
    content_path:       CompactString,                  // 上下文路径
    router:             Router,                         // 路由表
    middlewares:        Vec<Box<dyn HttpMiddleware>>,   // 中间件
    default_handler:    BoxHttpHandler,                 // 缺省处理函数
    error_handler:      fn(u32, Error) -> Response,     // 错误处理函数
    fuzzy_find:         FuzzyFind,                      // 路径匹配模式
    cancel_manager:     Option<CancelManager>,          // 进程退出标志
}

#[async_trait::async_trait]
impl<F: Send + Sync + 'static, Fut> RunCallback for F
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    async fn handle(self) -> Result<()> {
        self().await
    }
}

/// Definition of callback functions for API interface functions
#[async_trait::async_trait]
impl<F: Send + Sync + 'static, Fut> HttpHandler for F
where
    F: Fn(HttpContext) -> Fut,
    Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
{
    async fn handle(&self, ctx: HttpContext) -> HttpResponse {
        self(ctx).await
    }
}

impl<'a> Next<'a> {
    pub async fn run(mut self, ctx: HttpContext) -> HttpResponse {
        if let Some((current, next)) = self.next_middleware.split_first() {
            self.next_middleware = next;
            current.handle(ctx, self).await
        } else {
            (self.endpoint).handle(ctx).await
        }
    }
}

impl HttpServer {
    /// Create a new HttpServer
    pub fn new() -> Self {
        HttpServer {
            id:                 AtomicU32::new(1),
            count:              AtomicU32::new(0),
            content_path:       CompactString::with_capacity(0),
            router:             FnvHashMap::default(),
            middlewares:        Vec::<Box<dyn HttpMiddleware>>::new(),
            default_handler:    Box::new(Self::handle_not_found),
            error_handler:      Self::handle_error,
            fuzzy_find:         FuzzyFind::None,
            cancel_manager:             None,
        }
    }

    /// set api content path
    ///
    /// Arguments:
    ///
    /// * `prefix`: api path prefix
    ///
    pub fn set_content_path(&mut self, prefix: &str) {
        if prefix.is_empty() {
            return;
        }

        let pbs = prefix.as_bytes();
        let mut p = CompactString::with_capacity(0);
        if !pbs.is_empty() && pbs[0] != b'/' {
            p.push('/');
        }
        p.push_str(prefix);
        if !pbs.is_empty() && pbs[pbs.len() - 1] != b'/' {
            p.push('/');
        }

        self.content_path = p;
    }

    /// setting fuzzy find mode
    ///
    /// * `FuzzyFind::None`: no fuzzy find
    /// * `FuzzyFind::Parent`: fuzzy find only parent
    /// * `FuzzyFind::MultiParent`: fuzzy find multi parent
    ///
    /// Arguments:
    ///
    /// * `fuzzy_find`: fuzzy find mode
    ///
    pub fn set_fuzzy_find(&mut self, fuzzy_find: FuzzyFind) {
        self.fuzzy_find = fuzzy_find;
    }

    /// set default function when no matching api function is found
    ///
    /// Arguments:
    ///
    /// * `handler`: The default function when no matching interface function is found
    ///
    pub fn set_default_handler(&mut self, handler: impl HttpHandler) {
        self.default_handler = Box::new(handler);
    }

    /// setup error handler for http server
    ///
    /// Arguments
    ///
    /// * `handler`: Exception event handling function
    pub fn set_error_handler(&mut self, handler: fn(id: u32, err: Error) -> Response) {
        self.error_handler = handler;
    }

    /// register api function for path
    ///
    /// Arguments:
    ///
    /// * `path`: api path
    /// * `handler`: handle of api function
    #[inline]
    pub fn register(&mut self, mut path: &str, handler: impl HttpHandler) {
        debug_assert!(!path.is_empty());
        let pbs = path.as_bytes();
        let mut real_path = CompactString::with_capacity(0);

        if pbs[0] != b'/' {
            real_path.push('/');
        }

        let pl = pbs.len();
        if pl > 2 && pbs[pl - 1] == b'*' && pbs[pl - 2] == b'/' {
            path = &path[..pl - 1];
        }

        real_path.push_str(path);

        self.router.insert(real_path, Box::new(handler));
    }

    /// register middleware
    pub fn set_middleware<T: HttpMiddleware>(&mut self, middleware: T) {
        self.middlewares.push(Box::new(middleware));
    }

    /// set process exit cancel token
    pub fn set_cancel_manager(&mut self, cancel: CancelManager) {
        self.cancel_manager = Some(cancel);
    }

    /// run http service and enter message loop mode
    ///
    /// Arguments:
    ///
    /// * `addr`: listen addr
    pub async fn run(self, addr: std::net::SocketAddr) -> Result<()> {
        self.run_with(addr, || async { Ok(()) }).await
    }

    /// run http service and enter message loop mode
    ///
    /// Arguments:
    ///
    /// * `addr`: listen addr
    /// * `f`: Fn() -> anyhow::Result<()>
    pub async fn run_with<F: RunCallback>(
        self,
        addr: std::net::SocketAddr,
        f: F,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        f.handle().await?;
        self.log_api_info(addr);

        let srv = Arc::new(self);

        loop {
            let (tcp, addr) = listener.accept().await?;
            let io = TokioIo::new(tcp);
            tokio::spawn(Self::on_accept(srv.clone(), addr, io));
        }
    }

    pub async fn listen(&self, addr: std::net::SocketAddr) -> Result<TcpListener> {
        let listener = TcpListener::bind(addr).await?;
        self.log_api_info(addr);
        Ok(listener)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let srv = Arc::new(self);

        if let Some(cancel) = &srv.cancel_manager {
            let mut cancel = cancel.new_task_cancel();
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        let (tcp, addr) = res?;
                        let io = TokioIo::new(tcp);
                        tokio::spawn(Self::on_accept(srv.clone(), addr, io));
                    }
                    _ = cancel.cancelled() => {
                        cancel.finish();
                        #[cfg(not(feature = "english"))]
                        log::trace!("结束监听任务, 等待取消任务数: {}", cancel.count());
                        #[cfg(feature = "english")]
                        log::trace!("end listening task, wait for the number of cancelled tasks: {}", cancel.count());
                        break Ok(());
                    }
                }
            }
        } else {
            loop {
                let (tcp, addr) = listener.accept().await?;
                let io = TokioIo::new(tcp);
                tokio::spawn(Self::on_accept(srv.clone(), addr, io));
            }
        }
    }

    async fn on_accept(srv: Arc<HttpServer>, addr: SocketAddr, io: TokioIo<TcpStream>) {
        srv.count.fetch_add(1, std::sync::atomic::Ordering::Release);
        let id = Self::step_id(&srv.id);

        let srv_fn = |req: hyper::Request<Incoming>| {
            let srv = srv.clone();
            async move {
                let path = req.uri().path();
                let (endpoint, path_len) = srv.find_http_handler(path);
                let endpoint = match endpoint {
                    Some(v) => v,
                    None => srv.default_handler.as_ref(),
                };
                let next = Next {
                    endpoint,
                    next_middleware: &srv.middlewares,
                };

                let (parts, body) = req.into_parts();
                let body = match body.collect().await {
                    Ok(v) => v.to_bytes(),
                    Err(e) => {
                        #[cfg(not(feature = "english"))]
                        let e = Error::new(e).context("读取请求体失败");
                        #[cfg(feature = "english")]
                        let e = Error::new(e).context("read from request body fail");
                        let resp = (srv.error_handler)(id, e);
                        return Ok::<_, Infallible>(resp);
                    }
                };
                let req = Request::from_parts(parts, Full::new(body.clone()));

                let ctx = HttpContext {
                    req,
                    body,
                    path_len,
                    addr,
                    id,
                    uid: CompactString::with_capacity(0),
                    attrs: None,
                };

                let resp = match next.run(ctx).await {
                    Ok(resp) => resp,
                    Err(e) => (srv.error_handler)(id, e),
                };

                Ok::<_, Infallible>(resp)
            }
        };

        let conn = http1::Builder::new()
            .serve_connection(io, service::service_fn(srv_fn));
        tokio::pin!(conn);

        if let Some(cancel) = &srv.cancel_manager {
            let mut cancel = cancel.new_task_cancel();
            loop {
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(e) = res {
                            #[cfg(not(feature = "english"))]
                            log_error!(id, "请求处理失败: {e:?}");
                            #[cfg(feature = "english")]
                            log_error!(id, "request processing failed: {e:?}");
                        }
                        cancel.finish();
                        #[cfg(not(feature = "english"))]
                        log_trace!(id, "结束连接任务, 剩余待取消任务: {}", cancel.count());
                        #[cfg(feature = "english")]
                        log_trace!(id, "end connection task, remaining tasks to be cancelled: {}", cancel.count());
                        break;
                    }
                    _ = cancel.cancelled() => {
                        #[cfg(not(feature = "english"))]
                        log_trace!(id, "进程关闭通知，正在结束连接...");
                        #[cfg(feature = "english")]
                        log_trace!(id, "Process shutdown notification, ending connection...");
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        } else {
            if let Err(e) = conn.await {
                #[cfg(not(feature = "english"))]
                log_error!(id, "请求处理失败: {e:?}");
                #[cfg(feature = "english")]
                log_error!(id, "request processing failed: {e:?}");
            }
        }

        let count = srv.count.fetch_sub(1, std::sync::atomic::Ordering::Acquire);
        #[cfg(not(feature = "english"))]
        log::trace!("关闭连接, 剩余连接数: {}", count - 1);
        #[cfg(feature = "english")]
        log::trace!("close connection, remaining connections: {}", count - 1);
    }

    fn step_id(id: &AtomicU32) -> u32 {
        let curr_id = id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if curr_id == 0 {
            id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        } else {
            curr_id
        }
    }

    /// 路由查找，返回路由处理函数及路径匹配的长度
    fn find_http_handler<'a>(&'a self, path: &str) -> (Option<&'a dyn HttpHandler>, u32) {
        let prefix = self.content_path.as_str();

        let pl = if !prefix.is_empty() {
            // 前缀不匹配
            if !path.starts_with(prefix) {
                return (None, 0);
            }
            prefix.len() - 1
        } else {
            0
        };

        let mut path = &path[pl..];
        if path.len() > 1 && path.ends_with('/') {
            path = &path[0..path.len() - 1];
        }

        // 找到直接匹配的路径
        if let Some(handler) = self.router.get(path) {
            return (Some(handler.as_ref()), 0);
        }

        match self.fuzzy_find {
            FuzzyFind::None => {}
            FuzzyFind::One => {
                // 查找上级路径带路径参数的接口
                if let Some(pos) = path.rfind('/') {
                    if let Some(handler) = self.router.get(&path[..pos + 1]) {
                        return (Some(handler.as_ref()), (pl + pos + 1) as u32);
                    }
                }
            }
            FuzzyFind::Many => {
                // 尝试递归上级路径查找带路径参数的接口
                while let Some(pos) = path.rfind('/') {
                    if let Some(handler) = self.router.get(&path[..pos + 1]) {
                        return (Some(handler.as_ref()), (pl + pos + 1) as u32);
                    }
                    path = &path[..pos];
                }
            }
        }

        (None, 0)
    }

    fn handle_error(id: u32, err: Error) -> Response {
        let (code, msg) = match err.downcast::<HttpError>() {
            Ok(e) => {
                if e.source.is_some() {
                    log_error!(id, "{e:?}");
                }
                (e.code, e.message)
            },
            #[cfg(not(feature = "english"))]
            Err(e) => {
                log_error!(id, "内部错误, {e:?}");
                (500, format!("内部错误: {}", id))
            }
            #[cfg(feature = "english")]
            Err(e) => {
                log_error!(id, "internal server error, {e:?}");
                (500, format!("internal server error: {}", id))
            }
        };

        match Resp::fail_with_code(code, &msg) {
            Ok(val) => val,
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log_error!(id, "错误处理函数异常: {e:?}");
                #[cfg(feature = "english")]
                log_error!(id, "handle_error except: {e:?}");
                let body = Full::from("internal server error");
                let mut res = hyper::Response::new(body);
                *res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                res
            }
        }
    }

    async fn handle_not_found(_: HttpContext) -> HttpResponse {
        Ok(Resp::fail_with_status(
            hyper::StatusCode::NOT_FOUND,
            404,
            "Not Found",
        )?)
    }

    fn log_api_info(&self, addr: SocketAddr) {
        if log::log_enabled!(log::Level::Trace) {
            let mut buf = String::with_capacity(1024);
            if self.router.is_empty() {
                #[cfg(not(feature = "english"))]
                buf.push_str("已注册接口: <无>");
                #[cfg(feature = "english")]
                buf.push_str("Registered interface: <Empty>");
            } else {
                if !self.content_path.is_empty() {
                    #[cfg(not(feature = "english"))]
                    buf.push_str("已注册接口: prefix = ");
                    #[cfg(feature = "english")]
                    buf.push_str("Registered interface: prefix = ");
                    buf.push_str(&self.content_path[..self.content_path.len() - 1]);
                } else {
                    #[cfg(not(feature = "english"))]
                    buf.push_str("已注册接口:");
                    #[cfg(feature = "english")]
                    buf.push_str("Registered interface:");
                }
            }
            let buf = self.router.iter().fold(buf, |mut buf, v| {
                buf.push('\n');
                buf.push('\t');
                buf.push_str(v.0.as_str());
                if v.0.ends_with('/') {
                    buf.push('*');
                }
                buf
            });
            log::trace!("{}", buf);
        }

        #[cfg(not(feature = "english"))]
        log::info!("启动http服务: \x1b[34m{addr}\x1b[0m");
        #[cfg(feature = "english")]
        log::info!("Startup http server on \x1b[34m{addr}\x1b[0m");
    }

}
