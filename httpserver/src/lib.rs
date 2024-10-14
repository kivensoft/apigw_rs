//! 简单的http server库，适用于RESTFul的api服务
//!
//! 特性：
//!   1. 只支持http/1.1
//!   2. 不支持websocket
//!   3. 不支持文件上传
//!   4. 支持中间件
mod cancel;
mod httpcontext;
mod httperror;
mod macros;
mod middleware;
mod resp;

use anyhow::{Error, Result};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    sync::{atomic::{AtomicU32, Ordering}, Arc},
};
use tokio::net::{TcpListener, TcpStream};

pub use cancel::{CancelManager, CancelSender, new_cancel};
pub use hyper::body::Bytes;
pub use middleware::{AccessLog, CorsMiddleware, HttpMiddleware};
pub use resp::{ApiResult, Resp};
pub use httpcontext::{HttpContext, GKind, GValue};
pub use httperror::HttpError;

#[cfg(feature = "websocket")]
pub use httpcontext::WsContext;

/// http header "Content-Type"
pub const CONTENT_TYPE: &str = "Content-Type";
/// http header "applicatoin/json; charset=UTF-8"
pub const APPLICATION_JSON: &'static str = "applicatoin/json;charset=UTF-8";

// Simplified declaration
pub type Request = hyper::Request<Full<Bytes>>;
pub type Response = hyper::Response<Full<Bytes>>;
pub type HttpResponse = Result<Response>;
pub type BoxHttpHandler = Box<dyn HttpHandler>;
#[cfg(feature = "websocket")]
pub type WsMessage = hyper_tungstenite::tungstenite::Message;

#[cfg(feature = "websocket")]
pub type WsRequest = http::request::Parts;

type Router = HashMap<String, BoxHttpHandler>;
#[cfg(feature = "websocket")]
type WsRouter = HashMap<String, Arc<dyn WsHandler>>;

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

/// websocket function interface
#[cfg(feature = "websocket")]
#[async_trait::async_trait]
pub trait WsHandler: Send + Sync + 'static {
    async fn handle(&self, ctx: WsContext) -> Result<()>;
}

/// http request process object
pub struct Next<'a> {
    pub endpoint: &'a dyn HttpHandler,
    pub next_middleware: &'a [Arc<dyn HttpMiddleware>],
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
    context_path:       String,                         // 上下文路径
    router:             Router,                         // 路由表
    middlewares:        Vec<Arc<dyn HttpMiddleware>>,   // 中间件
    default_handler:    BoxHttpHandler,                 // 缺省处理函数
    error_handler:      fn(u32, Error) -> Response,     // 错误处理函数
    fuzzy_find:         FuzzyFind,                      // 路径匹配模式
    cancel_manager:     Option<CancelManager>,          // 进程退出标志
    #[cfg(feature = "websocket")]
    ws_router:          WsRouter,
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

#[cfg(feature = "websocket")]
/// Definition of callback functions for Websocket interface functions
#[async_trait::async_trait]
impl<F: Send + Sync + 'static, Fut> WsHandler for F
where
    F: Fn(WsContext) -> Fut,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    async fn handle(&self, ctx: WsContext) -> Result<()> {
        self(ctx).await
    }
}

impl<'a> Next<'a> {
    pub async fn run(mut self, ctx: HttpContext) -> HttpResponse {
        match self.next_middleware.split_first() {
            Some((current, next)) => {
                self.next_middleware = next;
                current.handle(ctx, self).await
            }
            None => (self.endpoint).handle(ctx).await,
        }
    }
}

impl HttpServer {
    /// Create a new HttpServer
    pub fn new() -> Self {
        HttpServer {
            id:                 AtomicU32::new(1),
            count:              AtomicU32::new(0),
            context_path:       String::new(),
            router:             HashMap::new(),
            middlewares:        Vec::<Arc<dyn HttpMiddleware>>::new(),
            default_handler:    Box::new(&Self::handle_not_found),
            error_handler:      Self::handle_error,
            fuzzy_find:         FuzzyFind::None,
            cancel_manager:     None,
            #[cfg(feature = "websocket")]
            ws_router:          HashMap::new(),
        }
    }

    /// get request count
    pub fn request_count(&self) -> u32 {
        self.id.load(Ordering::Relaxed)
    }

    /// get active connections count
    pub fn active_connections(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// set api content path
    ///
    /// Arguments:
    ///
    /// * `prefix`: api path prefix
    ///
    pub fn set_context_path(&mut self, prefix: &str) {
        if prefix.is_empty() {
            return;
        }

        let pbs = prefix.as_bytes();
        let mut p = String::new();
        if !pbs.is_empty() && pbs[0] != b'/' {
            p.push('/');
        }
        p.push_str(prefix);
        if !pbs.is_empty() && pbs[pbs.len() - 1] != b'/' {
            p.push('/');
        }

        self.context_path = p;
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
    pub fn register(&mut self, path: &str, handler: impl HttpHandler) {
        let real_path = Self::fix_path_of_reg(path);
        self.router.insert(real_path, Box::new(handler));
    }

    /// register middleware
    pub fn set_middleware<T: HttpMiddleware>(&mut self, middleware: T) -> Arc<T> {
        let middleware = Arc::new(middleware);
        self.middlewares.push(middleware.clone());
        middleware
    }

    /// set process exit cancel token
    pub fn set_cancel_manager(&mut self, cancel: CancelManager) {
        self.cancel_manager = Some(cancel);
    }

    /// register websocket handle
    #[cfg(feature = "websocket")]
    pub fn reg_websocket(&mut self, path: &str, handler: impl WsHandler) {
        let real_path = Self::fix_path_of_reg(path);
        self.ws_router.insert(real_path, Arc::new(handler));
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

    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    pub async fn serve(self: Arc<HttpServer>, listener: TcpListener) -> Result<()> {
        if let Some(cancel) = &self.cancel_manager {
            let mut cancel = cancel.new_task_cancel();
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        let (tcp, addr) = res?;
                        let io = TokioIo::new(tcp);
                        tokio::spawn(Self::on_accept(self.clone(), addr, io));
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
                tokio::spawn(self.clone().on_accept(addr, io));
            }
        }
    }

    async fn on_accept(self: Arc<HttpServer>, addr: SocketAddr, io: TokioIo<TcpStream>) {
        self.count.fetch_add(1, std::sync::atomic::Ordering::Release);
        let id = Self::step_id(&self.id);

        let srv_fn = |req: hyper::Request<Incoming>| {
            let srv = self.clone();
            async move {
                // 判断是否websocket协议，是的话直接跳转处理
                #[cfg(feature = "websocket")]
                if hyper_tungstenite::is_upgrade_request(&req) {
                    return Ok(srv.on_websocket(id, req, addr));
                }

                let path = req.uri().path();
                // 查找路由
                let (endpoint, path_len) = srv.find_http_handler(path);

                // 找不到对应的路由，使用默认处理函数
                let endpoint = match endpoint {
                    Some(v) => v,
                    None => srv.default_handler.as_ref(),
                };

                // 初始化调用链
                let next = Next {
                    endpoint,
                    next_middleware: &srv.middlewares,
                };

                // 读取请求体(body)
                let (req, body) = match Self::rebuild_req(req, id).await {
                    Ok(v) => v,
                    Err(e) => return Ok::<_, Infallible>((srv.error_handler)(id, e)),
                };

                let (uid, attrs) = (String::new(), None);
                let ctx = HttpContext { req, body, path_len, addr, id, uid, attrs };

                let resp = match next.run(ctx).await {
                    Ok(resp) => resp,
                    Err(e) => (srv.error_handler)(id, e),
                };

                Ok::<_, Infallible>(resp)
            }
        };

        let conn = http1::Builder::new().serve_connection(io, service::service_fn(srv_fn));
        #[cfg(feature = "websocket")]
        let conn = conn.with_upgrades();
        tokio::pin!(conn);

        if let Some(cancel_manager) = &self.cancel_manager {
            let mut canceler = cancel_manager.new_task_cancel();
            loop {
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(e) = res {
                            #[cfg(not(feature = "english"))]
                            log_error!(id, "请求处理失败: {e:?}");
                            #[cfg(feature = "english")]
                            log_error!(id, "request processing failed: {e:?}");
                        }
                        canceler.finish();
                        if canceler.is_cancel() {
                            #[cfg(not(feature = "english"))]
                            log_trace!(id, "取消http请求任务, 剩余待取消任务: {}", canceler.count());
                            #[cfg(feature = "english")]
                            log_trace!(id, "cancel http request task, remaining http request task: {}", canceler.count());
                        }
                        break;
                    }
                    _ = canceler.cancelled() => {
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

        let count = self.count.fetch_sub(1, std::sync::atomic::Ordering::Acquire);
        #[cfg(not(feature = "english"))]
        log::trace!("关闭http连接, 剩余连接数: {}", count - 1);
        #[cfg(feature = "english")]
        log::trace!("close http connection, remaining connections: {}", count - 1);
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
        let (handle, len) = Self::find_handler(&self.router, &self.context_path, &self.fuzzy_find, path);
        match handle {
            Some(h) => (Some(h.as_ref()), len),
            None => (None, len)
        }
    }

    /// websocket路由查找，返回路由处理函数及路径匹配的长度
    #[cfg(feature = "websocket")]
    fn find_ws_handler(&self, path: &str) -> (Option<Arc<dyn WsHandler>>, u32) {
        let (handle, len) = Self::find_handler(&self.ws_router, "", &self.fuzzy_find, path);
        match handle {
            Some(h) => (Some(h.clone()), len),
            None => (None, len)
        }
    }

    /// 路由查找，返回路由处理函数及路径匹配的长度
    fn find_handler<'a, T>(router: &'a HashMap<String, T>, context_path: &str,
            fuzzy_find: &FuzzyFind, mut path: &str) -> (Option<&'a T>, u32) {

        let prefix_len = if !context_path.is_empty() {
            // 前缀不匹配
            if !path.starts_with(context_path) {
                return (None, 0);
            }
            context_path.len() - 1
        } else {
            0
        };

        if prefix_len > 0 {
            path = &path[prefix_len..];
        }
        if path.len() > 1 && path.ends_with('/') {
            path = &path[0..path.len() - 1];
        }

        // 找到直接匹配的路径
        if let Some(handler) = router.get(path) {
            return (Some(handler), 0);
        }

        match fuzzy_find {
            FuzzyFind::None => {}
            FuzzyFind::One => {
                // 查找上级路径带路径参数的接口
                if let Some(pos) = path.rfind('/') {
                    if let Some(handler) = router.get(&path[..pos + 1]) {
                        return (Some(handler), (prefix_len + pos + 1) as u32);
                    }
                }
            }
            FuzzyFind::Many => {
                // 尝试递归上级路径查找带路径参数的接口
                while let Some(pos) = path.rfind('/') {
                    if let Some(handler) = router.get(&path[..pos + 1]) {
                        return (Some(handler), (prefix_len + pos + 1) as u32);
                    }
                    path = &path[..pos];
                }
            }
        }

        (None, 0)
    }

    async fn rebuild_req(req: hyper::Request<Incoming>, id: u32) -> Result<(Request, Bytes)> {
        let (parts, body) = req.into_parts();
        let body = match body.collect().await {
            Ok(v) => v.to_bytes(),
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log_error!(id, "读取请求体失败: {e:?}");
                #[cfg(not(feature = "english"))]
                http_bail!("网络错误");
                #[cfg(feature = "english")]
                log_error!(id, "Failed to read the request body: {e:?}");
                #[cfg(feature = "english")]
                http_bail!("network error");
            }
        };
        Ok((Request::from_parts(parts, Full::new(body.clone())), body))
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
        Resp::fail_with_status(hyper::StatusCode::NOT_FOUND, 404, "Not Found")
    }

    #[cfg(feature = "websocket")]
    fn on_websocket(&self, id: u32, mut req: hyper::Request<Incoming>, addr: SocketAddr) -> hyper::Response<Full<Bytes>> {
        let path = req.uri().path();
        let (endpoint, path_len) = self.find_ws_handler(path);

        // 找不到对应的路由，使用默认处理函数
        let endpoint = match endpoint {
            Some(v) => v,
            None => {
                #[cfg(not(feature = "english"))]
                log_error!(id, "websocket找不到请求路径对应的处理函数: {path}");
                #[cfg(feature = "english")]
                log_error!(id, "websocket request handler not found: {path}");
                return Resp::internal_server_error().unwrap();
            }
        };

        let (response, websocket) = match hyper_tungstenite::upgrade(&mut req, None) {
            Ok(v) => v,
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log_error!(id, "websocket协议错误: {e:?}");
                #[cfg(feature = "english")]
                log_error!(id, "websocket protocol error: {e:?}");
                return Resp::internal_server_error().unwrap();
            }
        };

        let (req, _) = req.into_parts();
        let ctx = WsContext {req, id, path_len, addr, websocket};

        // Spawn a task to handle the websocket connection.
        tokio::spawn(async move {
            if let Err(e) = endpoint.handle(ctx).await {
                #[cfg(not(feature = "english"))]
                log_error!(id, "websocket接口发生错误: {e:?}");
                #[cfg(feature = "english")]
                log_error!(id, "Error in websocket: {e:?}");
            }
        });

        // Return the response so the spawned future can continue.
        response
    }

    fn fix_path_of_reg(mut path: &str) -> String {
        debug_assert!(!path.is_empty());
        let pbs = path.as_bytes();
        let mut real_path = String::new();

        if pbs[0] != b'/' {
            real_path.push('/');
        }

        let pl = pbs.len();
        if pl > 2 && pbs[pl - 1] == b'*' && pbs[pl - 2] == b'/' {
            path = &path[..pl - 1];
        }

        real_path.push_str(path);
        real_path
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
                if !self.context_path.is_empty() {
                    #[cfg(not(feature = "english"))]
                    buf.push_str("已注册接口: prefix = ");
                    #[cfg(feature = "english")]
                    buf.push_str("Registered interface: prefix = ");
                    buf.push_str(&self.context_path[..self.context_path.len() - 1]);
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
