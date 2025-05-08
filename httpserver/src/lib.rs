//! 简单的http server库，适用于RESTFul的api服务
//!
//! 特性：
//!   1. 支持http/1.1
//!   2. 支持websocket
//!   3. 支持中间件

mod cancel;
mod httpcontext;
mod httperror;
mod macros;
mod middleware;
mod resp;

use anyhow::{Error, Result};
use compact_str::CompactString;
use http::{request::Parts, HeaderMap};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use tokio::net::{TcpListener, TcpStream};

pub use cancel::{new_cancel, CancelManager, CancelSender};
pub use httpcontext::{BodyData, GKind, GValue, HttpContext};
pub use httperror::HttpError;
pub use hyper::body::Bytes;
pub use middleware::{AccessLog, CorsMiddleware, HttpMiddleware};
pub use resp::{ApiResult, Resp};

#[cfg(feature = "websocket")]
pub use httpcontext::WsContext;

/// http header "Content-Type"
pub const CONTENT_TYPE: &str = "Content-Type";
/// http header "applicatoin/json; charset=UTF-8"
pub const APPLICATION_JSON: &str = "application/json;charset=UTF-8";
pub const APPLICATION_JSON_PREFIX: &str = "application/json";
pub const APPLICATION_FORM_SUFFIX: &str = "application/x-www-form-urlencoded";

// Simplified declaration
pub type Request = hyper::Request<Incoming>;
pub type RespBody = BoxBody<Bytes, Error>;
pub type Response = hyper::Response<RespBody>;
pub type HttpResponse = Result<Response>;
pub type BoxHttpHandler = Box<dyn HttpHandler>;
#[cfg(feature = "websocket")]
pub type WsMessage = hyper_tungstenite::tungstenite::Message;

#[cfg(feature = "websocket")]
pub type WsRequest = http::request::Parts;

type Router = HashMap<String, BoxHttpHandler>;
#[cfg(feature = "websocket")]
type WsRouter = HashMap<String, Arc<dyn WsHandler>>;

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
    id: AtomicU32,                             // 自增的请求id
    count: AtomicU32,                          // 当前连接总数
    context_path: CompactString,               // 上下文路径
    router: Router,                            // 路由表
    middlewares: Vec<Arc<dyn HttpMiddleware>>, // 中间件
    default_handler: BoxHttpHandler,           // 缺省处理函数
    error_handler: fn(Error) -> Response,      // 错误处理函数
    fuzzy_find: FuzzyFind,                     // 路径匹配模式
    cancel_manager: Option<CancelManager>,     // 进程退出标志
    #[cfg(feature = "websocket")]
    ws_router: WsRouter,
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
            // 还有中间件，执行下一个中间件处理程序
            Some((current, next)) => {
                self.next_middleware = next;
                current.handle(ctx, self).await
            }
            // 没有中间件，执行最终的接口处理程序
            None => (self.endpoint).handle(ctx).await,
        }
    }
}

impl HttpServer {
    /// Create a new HttpServer
    pub fn new() -> Self {
        HttpServer {
            id: AtomicU32::new(0),
            count: AtomicU32::new(0),
            context_path: CompactString::new("/"),
            router: HashMap::new(),
            middlewares: Vec::<Arc<dyn HttpMiddleware>>::new(),
            default_handler: Box::new(&Self::handle_not_found),
            error_handler: Self::handle_error,
            fuzzy_find: FuzzyFind::None,
            cancel_manager: None,
            #[cfg(feature = "websocket")]
            ws_router: HashMap::new(),
        }
    }

    /// get total request count
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
    pub fn context_path(&mut self, prefix: impl AsRef<str>) -> &mut Self {
        let prefix = prefix.as_ref();
        let pbs = prefix.as_bytes();
        let mut ctx_path = CompactString::with_capacity(0);
        if pbs.is_empty() || pbs[0] != b'/' {
            ctx_path.push('/');
        }
        ctx_path.push_str(prefix);
        if !pbs.is_empty() && pbs[pbs.len() - 1] != b'/' {
            ctx_path.push('/');
        }

        self.context_path = ctx_path;
        self
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
    pub fn fuzzy_find(&mut self, fuzzy_find: FuzzyFind) -> &mut Self {
        self.fuzzy_find = fuzzy_find;
        self
    }

    /// set default function when no matching api function is found
    ///
    /// Arguments:
    ///
    /// * `handler`: The default function when no matching interface function is found
    ///
    pub fn default_handler(&mut self, handler: impl HttpHandler) -> &mut Self {
        self.default_handler = Box::new(handler);
        self
    }

    /// setup error handler for http server
    ///
    /// Arguments
    ///
    /// * `handler`: Exception event handling function
    pub fn error_handler(&mut self, handler: fn(err: Error) -> Response) -> &mut Self {
        self.error_handler = handler;
        self
    }

    /// register api function for path
    ///
    /// Arguments:
    ///
    /// * `path`: api path
    /// * `handler`: handle of api function
    pub fn register(&mut self, path: impl AsRef<str>, handler: impl HttpHandler) -> &mut Self {
        let real_path = Self::fix_path_of_reg(path.as_ref());
        self.router.insert(real_path, Box::new(handler));
        self
    }

    /// register middleware
    pub fn middleware(&mut self, middleware: Arc<dyn HttpMiddleware>) -> &mut Self {
        self.middlewares.push(middleware);
        self
    }

    /// set process exit cancel token
    pub fn cancel_manager(&mut self, cancel: CancelManager) -> &mut Self {
        self.cancel_manager = Some(cancel);
        self
    }

    /// register websocket handle
    #[cfg(feature = "websocket")]
    pub fn reg_websocket(&mut self, path: &str, handler: impl WsHandler) -> &mut Self {
        let real_path = Self::fix_path_of_reg(path);
        self.ws_router.insert(real_path, Arc::new(handler));
        self
    }

    /// run http service and enter message loop mode
    ///
    /// Arguments:
    ///
    /// * `addr`: listen addr
    pub async fn run(self, addr: std::net::SocketAddr) -> Result<()> {
        self.run_with(addr, async || Ok(())).await
    }

    /// run http service and enter message loop mode
    ///
    /// Arguments:
    ///
    /// * `addr`: Listening address
    /// * `f`: Asynchronous callback function after the listening port is successfully bound
    pub async fn run_with(
        self,
        addr: std::net::SocketAddr,
        f: impl AsyncFn() -> Result<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        f().await?;
        self.log_startup_info(addr);
        let srv = Arc::new(self);
        srv.serve(listener).await
    }

    /// bind addr
    ///
    /// Arguments:
    ///
    /// * `addr`: Listening address
    pub async fn listen(&self, addr: std::net::SocketAddr) -> Result<TcpListener> {
        let listener = TcpListener::bind(addr).await?;
        self.log_startup_info(addr);
        Ok(listener)
    }

    /// run loop accept
    ///
    /// Arguments:
    ///
    /// * `listener`: Listening address
    pub async fn serve(self: Arc<HttpServer>, listener: TcpListener) -> Result<()> {
        if let Some(cancel_manager) = &self.cancel_manager {
            let mut cancel_receiver = cancel_manager.new_cancel_receiver();
            loop {
                tokio::select! {
                    res = listener.accept() => self.run_on_accept(res?),
                    _ = cancel_receiver.cancel_event() => {
                        let task_count = cancel_receiver.finish();

                        #[cfg(not(feature = "english"))]
                        log::trace!("结束监听任务, 等待取消任务数: {}", task_count);
                        #[cfg(feature = "english")]
                        log::trace!("end listening task, wait for the number of cancelled tasks: {}", task_count);

                        break;
                    }
                }
            }
        } else {
            loop {
                self.run_on_accept(listener.accept().await?);
            }
        }

        Ok(())
    }

    fn run_on_accept(self: &Arc<HttpServer>, (tcp, addr): (TcpStream, SocketAddr)) {
        let io = TokioIo::new(tcp);
        tokio::spawn(self.clone().on_accept(addr, io));
    }

    async fn on_accept(self: Arc<HttpServer>, addr: SocketAddr, io: TokioIo<TcpStream>) {
        // 连接数量+1
        self.count.fetch_add(1, std::sync::atomic::Ordering::Release);
        // 获取当前连接的请求id
        let id = self.id.fetch_add(1, Ordering::Release);

        let srv_fn = service::service_fn(|req: hyper::Request<Incoming>| {
            self.process_request(id, addr, req)
        });

        let conn = http1::Builder::new().serve_connection(io, srv_fn);
        #[cfg(feature = "websocket")]
        let conn = conn.with_upgrades();

        if let Some(cancel_manager) = &self.cancel_manager {
            tokio::pin!(conn);
            let mut canceler = cancel_manager.new_cancel_receiver();

            loop {
                tokio::select! {
                    res = conn.as_mut() => {
                        if let Err(e) = res {
                            #[cfg(not(feature = "english"))]
                            log::error!("请求处理失败: {e:?}");
                            #[cfg(feature = "english")]
                            log::error!("request processing failed: {e:?}");
                        }

                        // 连接结束标志, 总连接数-1
                        let task_count = canceler.finish();

                        if canceler.is_cancel() {
                            #[cfg(not(feature = "english"))]
                            log::trace!("剩余待取消连接: {}", task_count);
                            #[cfg(feature = "english")]
                            log::trace!("remaining http request connection: {}", task_count);
                        }

                        break;
                    }
                    _ = canceler.cancel_event() => {
                        #[cfg(not(feature = "english"))]
                        log::trace!("收到进程退出通知，正在结束连接...");
                        #[cfg(feature = "english")]
                        log::trace!("receive Process exit notification, ending connection...");
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        } else {
            if let Err(e) = conn.await {
                #[cfg(not(feature = "english"))]
                log::error!("http请求处理失败: {e:?}");
                #[cfg(feature = "english")]
                log::error!("http request processing failed: {e:?}");
            }
        }

        // 请求已经处理完成，连接数量-1
        let count = self.count.fetch_sub(1, Ordering::Relaxed);
        #[cfg(not(feature = "english"))]
        log::trace!("关闭http连接, 剩余连接数: {}", count - 1);
        #[cfg(feature = "english")]
        log::trace!("close http connection, remaining tasks: {}", count - 1);
    }

    /// 请求处理函数
    ///
    /// Arguments:
    ///
    /// * `id`: 请求id，每个请求的id唯一
    /// * `addr`: 客户端地址及端口
    /// * `req`: 请求对象
    async fn process_request(
        &self,
        id: u32,
        addr: SocketAddr,
        req: Request,
    ) -> Result<Response, Infallible> {
        // 判断是否websocket协议，是的话直接跳转处理
        #[cfg(feature = "websocket")]
        if hyper_tungstenite::is_upgrade_request(&req) {
            return Ok(self.on_websocket(id, req, addr));
        }

        let path = req.uri().path();

        // 查找路由
        let (endpoint, match_path_len) = self.find_http_handler(path);

        // 找不到对应的路由，使用默认处理函数
        let endpoint = match endpoint {
            Some(v) => v,
            None => self.default_handler.as_ref(),
        };

        // 初始化调用链(中间件及最终的接口处理函数)
        let next = Next {
            endpoint,
            next_middleware: &self.middlewares,
        };

        // 读取请求体(body)
        let (parts, body) = match Self::parse_request(req).await {
            Ok(v) => v,
            Err(e) => return Ok((self.error_handler)(e)),
        };

        // 生成请求上下文
        let ctx = HttpContext {
            parts,
            body,
            match_path_len,
            context_path_len: self.context_path.len() as u32,
            addr,
            id,
            uid: CompactString::with_capacity(0),
            attrs: Vec::new(),
        };

        // 执行中间件及具体的接口函数
        let resp = match next.run(ctx).await {
            Ok(resp) => resp,
            Err(e) => (self.error_handler)(e),
        };

        Ok(resp)
    }

    /// 路由查找，返回路由处理函数及路径匹配的长度
    fn find_http_handler<'a>(&'a self, path: &str) -> (Option<&'a dyn HttpHandler>, u32) {
        let (handle, len) =
            Self::find_handler(&self.router, &self.context_path, &self.fuzzy_find, path);
        match handle {
            Some(h) => (Some(h.as_ref()), len),
            None => (None, len),
        }
    }

    /// websocket路由查找，返回路由处理函数及路径匹配的长度
    #[cfg(feature = "websocket")]
    fn find_ws_handler(&self, path: &str) -> (Option<Arc<dyn WsHandler>>, u32) {
        let (handle, len) = Self::find_handler(&self.ws_router, "", &self.fuzzy_find, path);
        match handle {
            Some(h) => (Some(h.clone()), len),
            None => (None, len),
        }
    }

    /// 路由查找，返回路由处理函数及路径匹配的长度
    fn find_handler<'a, T>(
        router: &'a HashMap<String, T>,
        context_path: &str,
        fuzzy_find: &FuzzyFind,
        mut path: &str,
    ) -> (Option<&'a T>, u32) {
        // 前缀不匹配
        if !path.starts_with(context_path) {
            return (None, 0);
        }

        let prefix_len = context_path.len() - 1;

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

    async fn parse_request(req: Request) -> Result<(Parts, BodyData)> {
        let (parts, body) = req.into_parts();

        // 请求体是json或者form数据才进行读取，不是则不读取
        if !is_form_or_json(&parts.headers) {
            return Ok((parts, BodyData::Incoming(body)));
        }

        // 参数化接口请求
        let body = match body.collect().await {
            Ok(v) => v.to_bytes(),
            Err(e) => {
                #[cfg(not(feature = "english"))]
                {
                    log::error!("读取请求体失败: {e:?}");
                    http_bail!("网络错误");
                }
                #[cfg(feature = "english")]
                {
                    log::error!("Failed to read the request body: {e:?}");
                    http_bail!("network error");
                }
            }
        };
        Ok((parts, BodyData::Bytes(body)))
    }

    fn handle_error(err: Error) -> Response {
        let (code, msg) = match err.downcast::<HttpError>() {
            Ok(e) => {
                if e.source.is_some() {
                    log::error!("{e:?}");
                }
                (e.code, e.message)
            }
            #[cfg(not(feature = "english"))]
            Err(e) => {
                log::error!("内部错误, {e:?}");
                (500, String::from("内部错误"))
            }
            #[cfg(feature = "english")]
            Err(e) => {
                log::error!("internal server error, {e:?}");
                (500, String::from("internal server error"))
            }
        };

        match Resp::fail_with_code(code, &msg) {
            Ok(val) => val,
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log::error!("错误处理函数异常: {e:?}");
                #[cfg(feature = "english")]
                log::error!("handle_error except: {e:?}");
                let body = Bytes::from_static(b"internal server error");
                let body = Full::new(body).map_err(map_infallible).boxed();
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
    fn on_websocket(&self, id: u32, mut req: Request, addr: SocketAddr) -> Response {
        let path = req.uri().path();
        let (endpoint, path_len) = self.find_ws_handler(path);

        // 找不到对应的路由，使用默认处理函数
        let endpoint = match endpoint {
            Some(v) => v,
            None => {
                #[cfg(not(feature = "english"))]
                log::error!("websocket找不到请求路径对应的处理函数: {path}");
                #[cfg(feature = "english")]
                log::error!("websocket request handler not found: {path}");
                return Resp::internal_server_error().unwrap();
            }
        };

        let (response, websocket) = match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((res, ws)) => {
                let (parts, body) = res.into_parts();
                let body = body.map_err(map_infallible).boxed();
                (hyper::Response::from_parts(parts, body), ws)
            }
            Err(e) => {
                #[cfg(not(feature = "english"))]
                log::error!("websocket协议错误: {e:?}");
                #[cfg(feature = "english")]
                log::error!("websocket protocol error: {e:?}");
                return Resp::internal_server_error().unwrap();
            }
        };

        let (req, _) = req.into_parts();
        let ctx = WsContext {
            req,
            id,
            path_len,
            addr,
            websocket,
        };

        // Spawn a task to handle the websocket connection.
        tokio::spawn(async move {
            if let Err(e) = endpoint.handle(ctx).await {
                #[cfg(not(feature = "english"))]
                log::error!("websocket接口发生错误: {e:?}");
                #[cfg(feature = "english")]
                log::error!("Error in websocket: {e:?}");
            }
        });

        // Return the response so the spawned future can continue.
        response
    }

    fn fix_path_of_reg(mut path: &str) -> String {
        debug_assert!(!path.is_empty());
        let path_bytes = path.as_bytes();
        let mut result = String::new();

        if path_bytes[0] != b'/' {
            result.push('/');
        }

        let len = path_bytes.len();
        if len > 2 && path_bytes[len - 1] == b'*' && path_bytes[len - 2] == b'/' {
            path = &path[..len - 1];
        }

        result.push_str(path);
        result
    }

    fn log_startup_info(&self, addr: SocketAddr) {
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
        log::info!("启动http服务: http://\x1b[34m{addr}\x1b[35m{}\x1b[0m", self.context_path);
        #[cfg(feature = "english")]
        log::info!(
            "Startup http server on http://\x1b[34m{addr}\x1b[35m{}\x1b[0m",
            self.context_path
        );
    }
}

/// 将Infallible转换为anyhow::Error
pub fn map_infallible(_: Infallible) -> Error {
    anyhow::anyhow!("")
}

pub(crate) fn is_form_or_json(headers: &HeaderMap<http::HeaderValue>) -> bool {
    if let Some(ct) = headers.get(CONTENT_TYPE) {
        let json = APPLICATION_JSON_PREFIX.as_bytes();
        let form = APPLICATION_FORM_SUFFIX.as_bytes();
        let ct = ct.as_bytes();
        ct.starts_with(json) || ct.starts_with(form)
    } else {
        false
    }
}
