use anyhow::Context;
use compact_str::CompactString;
use hyper::{body::Buf, header::AsHeaderName, http::HeaderValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicU32, RwLock},
    collections::HashMap
};

pub use compact_str;

/// Batch registration API interface
///
/// ## Example
/// ```rust
/// use anyhow::Result;
/// use httpserver::{HttpContext, Response, register_apis};
///
/// async fn ping(ctx: HttpContext) -> Result<Response> { todo!() }
/// async fn login(ctx: HttpContext) -> Result<Response> { todo!() }
///
/// let mut srv = HttpServer::new(true);
/// register_apis!(srv, "/api",
///     "/ping": apis::ping,
///     "/login": apis::login,
/// );
/// ```
#[macro_export]
macro_rules! register_apis {
    ($server:expr, $base:expr, $($path:literal : $handler:expr,)+) => {
        $(
            $server.register(&$crate::compact_str::format_compact!("{}{}",
                $base, $path), $handler);
        )*
    };
}

/// Error message response returned when struct fields is Option::None
///
/// ## Example
/// ```rust
/// struct User {
///     name: Option<String>,
///     age: Option<u8>,
/// }
///
/// let user = User { name: None, age: 48 };
///
/// httpserver::check_required!(user, name, age);
/// ```
#[macro_export]
macro_rules! check_required {
    ($val:expr, $($attr:tt),+) => {
        $(
            if $val.$attr.is_none() {
                return $crate::Resp::fail(&$crate::compact_str::format_compact!(
                    "{}{}", stringify!($attr), " can't be null"));
            }
        )*
    };
}

/// Error message response returned when struct fields is Option::None
///
/// ## Example
/// ```rust
/// struct User {
///     name: Option<String>,
///     age: Option<u8>,
/// }
///
/// let user = User { name: String::from("kiven"), age: 48 };
///
/// let (name, age) = httpserver::assign_required!(user, name, age);
///
/// assert_eq!("kiven", name);
/// assert_eq!(48, age);
/// ```
#[macro_export]
macro_rules! assign_required {
    ($val:expr, $($attr:tt),+) => {
        let ($($attr,)*) = (
            $(
                match &$val.$attr {
                    Some(v) => v,
                    None => return $crate::Resp::fail(
                        &$crate::compact_str::format_compact!(
                            "{}{}", stringify!($attr), " can't be null")),
                },
            )*
        );
    };
}

/// Error message response returned when expression is true
///
/// ## Example
/// ```rust
/// use httpserver::fail_if;
///
/// let age = 30;
/// fail_if!(age >= 100, "age must be range 1..100");
/// fail_if!(age >= 100, "age is {}, not in range 1..100", age);
/// ```
#[macro_export]
macro_rules! fail_if {
    ($b:expr, $msg:literal) => {
        if $b {
            return $crate::Resp::fail($msg);
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            return $crate::Resp::fail(&$crate::compact_str::format_compact!($($t)*));
        }
    };
}

/// Error message response returned when ApiResult.is_fail() == true
///
/// ## Example
/// ```rust
/// use httpserver::fail_if_api;
///
/// let f = || {
///     let ar = ApiResult::fail("open database error");
///     fail_if_api!(ar);
///     Resp::ok_with_empty()
/// }
/// assert_eq!(f(), Resp::fail_with_api_result(ApiResult::fail("open database error")));
/// ```
#[macro_export]
macro_rules! fail_if_api {
    ($ar:expr) => {
        if $ar.is_fail() {
            return $crate::Resp::fail_with_api_result($ar);
        }
    };
}

/// Conditional assignment, similar to the ternary operator
///
///  ## Example
/// ```rust
/// use httpserver::assign_if;
///
/// let a = assign_if!(true, 52, 42);
/// let b = assign_if!(false, 52, 42);
/// assert_eq!(52, a);
/// assert_eq!(42, b);
/// ```
#[macro_export]
macro_rules! assign_if {
    ($b:expr, $val1:expr, $val2:expr) => {
        if $b { $val1 } else { $val2 }
    };
}

/// Conditional assignment, similar to the ternary operator
///
///  ## Example
/// ```rust
/// use httpserver::assign_if;
///
/// let a = || api_fail_if!(true, "err");
/// let b = ApiResult::fail("err");
/// assert_eq!(a(), b);
/// ```
#[macro_export]
macro_rules! api_fail_if {
    ($b:expr, $msg:literal) => {
        if $b {
            return $crate::ApiResult::fail(String::from($msg));
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            return $crate::ApiResult::fail(format!($($t)*));
        }
    };
}

/// Conditional assignment, similar to the ternary operator
///
///  ## Example
/// ```rust
/// use httpserver::assign_if;
///
/// let a = || api_fail_if!(true, "err");
/// let b = ApiResult::fail("err");
/// assert_eq!(a(), Ok(b));
/// ```
#[macro_export]
macro_rules! result_api_fail_if {
    ($b:expr, $msg:literal) => {
        if $b {
            return Ok($crate::ApiResult::fail(String::from($msg)));
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            return Ok($crate::ApiResult::fail(format!($($t)*)));
        }
    };
}

/// check Result type, if Err(e) then log error and
/// return Resp::internal_server_error()
///
///  ## Example
/// ```rust
/// use httpserver::assign_if;
///
/// let f = || { Err("abc") }
/// check_result!(f());
/// ```
#[macro_export]
macro_rules! check_result {
    ($op: expr) => {
        match $op {
            Ok(v) => v,
            Err(e) => {
                log::error!("{e:?}");
                return Resp::internal_server_error();
            }
        }
    };
    ($op: expr, $msg:literal) => {
        match $op {
            Ok(v) => v,
            Err(e) => {
                log::error!("{}: {:?}", $msg, e);
                return Resp::internal_server_error();
            }
        }
    };
}

/// await and check Result type, if Err(e) then log error and
/// return Resp::internal_server_error()
///  ## Example
/// ```rust
/// use httpserver::await_result;
///
/// let f = || async { Err("abc") }
/// await_result!(f());
/// ```
#[macro_export]
macro_rules! await_result {
    ($op: expr) => {
        match $op.await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{e:?}");
                return Resp::internal_server_error();
            }
        }
    };
    ($op: expr, $msg:literal) => {
        match $op.await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{}: {:?}", $msg, e);
                return Resp::internal_server_error();
            }
        }
    };
}

/// http header "Content-Type"
pub const CONTENT_TYPE: &'static str = "Content-Type";
/// http header "applicatoin/json; charset=UTF-8"
pub const APPLICATION_JSON: &'static str = "applicatoin/json; charset=UTF-8";

/// Simplified declaration
pub type Request = hyper::Request<hyper::Body>;
pub type Response = hyper::Response<hyper::Body>;
pub type HttpResult = anyhow::Result<Response>;
pub type BoxHttpHandler = Box<dyn HttpHandler>;

#[derive(Error, Debug)]
pub enum HttpContextError {
    #[error("the request body is empty")]
    EmptyBody,
    #[error("read request body error")]
    ReadBody(#[from] hyper::Error),
    #[error(transparent)]
    DecodeJsonError(#[from] serde_json::error::Error),
}

/// use for HttpServer.run_with_callback
#[async_trait::async_trait]
pub trait RunCallback: Send + Sync + 'static {
    async fn handle(self) -> anyhow::Result<()>;
}

/// api function interface
#[async_trait::async_trait]
pub trait HttpHandler: Send + Sync + 'static {
    async fn handle(&self, ctx: HttpContext) -> HttpResult;
}

/// middleware interface
#[async_trait::async_trait]
pub trait HttpMiddleware: Send + Sync + 'static {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResult;
}

/// Universal API interface returns data format
#[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
pub struct ApiResult<T> {
    pub code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

/// api function param
pub struct HttpContext {
    pub req : Request,         // 请求对象
    addr    : SocketAddr,      // 请求客户端ip地址
    id      : u32,             // 请求id(每个请求id唯一)
    uid     : u32,             // 当前登录用户id(从token中解析, 未登录为0)
    attr    : HttpContextAttr, // 附加属性(用户自定义)
}

/// Build http response object
pub struct Resp;

/// http request process object
pub struct Next<'a> {
    pub endpoint: &'a dyn HttpHandler,
    pub next_middleware: &'a [Arc<dyn HttpMiddleware>],
}

/// Log middleware
pub struct AccessLog;

/// http server
pub struct HttpServer {
    prefix: CompactString,
    router: Router,
    middlewares: Vec<Arc<dyn HttpMiddleware>>,
    default_handler: BoxHttpHandler,
}

type HttpContextAttr = RwLock<HashMap<CompactString, Arc<Value>>>;
type Router = std::collections::HashMap<CompactString, BoxHttpHandler>;

impl <T> ApiResult<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 200,
            message: None,
            data: Some(data),
        }
    }

    pub fn ok_with_empty() -> Self {
        Self {
            code: 200,
            message: None,
            data: None,
        }
    }

    pub fn fail(msg: String) -> Self {
        Self {
            code: 500,
            message: Some(msg),
            data: None,
        }
    }

    pub fn fail_with_code(code: u32, msg: String) -> Self {
        Self {
            code,
            message: Some(msg),
            data: None,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.code == 200
    }

    pub fn is_fail(&self) -> bool {
        self.code != 200
    }
}


impl HttpContext {

    /// Asynchronous parsing of the body content of HTTP requests in JSON format
    ///
    /// Returns:
    ///
    /// **Ok(val)**: body parse success
    ///
    /// **Err(e)**: parse error
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, Response, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_json::<ReqParam>().await?;
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub async fn into_json<T: DeserializeOwned>(self) -> Result<T, HttpContextError> {
        match self.into_opt_json().await? {
            Some(v) => Ok(v),
            None => Err(HttpContextError::EmptyBody),
        }
    }

    /// Asynchronous parsing of the body content of HTTP requests in JSON format,
    ///
    /// Returns:
    ///
    /// **Ok(Some(val))**: parse body success
    ///
    /// **Ok(None)**: body is empty
    ///
    /// **Err(e)**: parse error
    ///
    ///  ## Example
    /// ```rust
    /// use httpserver::{HttpContext, Response, Resp};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_option_json::<ReqParam>().await?;
    ///     Resp::ok_with_empty()
    /// }
    /// ```
    pub async fn into_opt_json<T: DeserializeOwned>(self) -> Result<Option<T>, HttpContextError> {
        let body = hyper::body::aggregate(self.req).await?;
        if body.remaining() > 0 {
            Ok(serde_json::from_reader(body.reader())?)
        } else {
            Ok(None)
        }
    }

    /// 返回请求id，每个请求的id都是唯一的
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 返回当前用户的id
    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// 获取客户端的真实ip, 获取优先级为X-Real-IP > X-Forwarded-For > socketaddr
    pub fn remote_ip(&self) -> Ipv4Addr {
        if let Some(ip) = self.req.headers().get("X-Real-IP") {
            if let Ok(ip) = ip.to_str() {
                if let Ok(ip) = ip.parse() {
                    return ip;
                }
            }
        }

        if let Some(ip) = self.req.headers().get("X-Forwarded-For") {
            if let Ok(ip) = ip.to_str() {
                if let Some(ip) = ip.split(',').next() {
                    if let Ok(ip) = ip.parse() {
                        return ip;
                    }
                }
            }
        }

        match self.addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => std::net::Ipv4Addr::new(0, 0, 0, 0),
        }
    }

    pub fn header<K: AsHeaderName>(&self, key: K) -> Option<&HeaderValue> {
        self.req.headers().get(key)
    }

    pub fn attr<'a>(&'a self, key: &str) -> Option<Arc<Value>> {
        self.attr.read().unwrap().get(key).map(|v| v.clone())
    }

    pub fn set_attr(&mut self, key: CompactString, value: Value) {
        self.attr.write().unwrap().insert(key, Arc::new(value));
    }

}


impl Resp {

    /// Create a reply message with the specified status code and content
    ///
    /// Arguments:
    ///
    /// * `status`: http status code
    /// * `body`: http response body
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::resp(hyper::StatusCode::Ok, hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp(status: hyper::StatusCode, body: hyper::Body) -> HttpResult {
        Ok(hyper::Response::builder()
            .status(status)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(body).context("response build error")?)
    }

    /// Create a reply message with 200
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::resp_ok(hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp_ok(body: hyper::Body) -> HttpResult {
        Ok(hyper::Response::builder()
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(body).context("response build error")?)
    }

    /// Create a reply message with 200, response body is empty
    pub fn ok_with_empty() -> HttpResult {
        Self::resp_ok(hyper::Body::from(r#"{"code":200}"#))
    }

    /// Create a reply message with 200
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::ok(&serde_json::json!({
    ///     "code": 200,
    ///         "data": {
    ///             "name":"kiven",
    ///             "age": 48,
    ///         },
    /// }))?;
    /// ````
    pub fn ok<T: ?Sized + Serialize>(data: &T) -> HttpResult {
        Self::ok_option(Some(data))
    }

    pub fn ok_option<T: ?Sized + Serialize>(data: Option<&T>) -> HttpResult {
        // Self::resp_ok(to_json_body!({"code": 200, "data": data}))
        Self::resp_ok(hyper::Body::from(
            serde_json::to_vec(&ApiResult {
                code: 200,
                message: None,
                data,
            })?
        ))
    }

    /// Create a reply message with http status 500
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail("required field `username`")?;
    /// ````
    pub fn fail(message: &str) -> HttpResult {
        Self::fail_with_code(500, message)
    }

    /// Create a reply message with specified error code
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail_with_code(10086, "required field `username`")?;
    /// ````
    pub fn fail_with_code(code: u32, message: &str) -> HttpResult {
        Self::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }

    /// Create a reply message with specified http status and error code
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR,
    ///         10086, "required field `username`")?;
    /// ````
    pub fn fail_with_status(status: hyper::StatusCode, code: u32, message: &str) -> HttpResult {
        // Self::resp(status, to_json_body!({"code": code, "message": message}))
        Self::resp(status, hyper::Body::from(
            serde_json::to_vec(&ApiResult::<&str> {
                code,
                message: Some(String::from(message)),
                data: None,
            })?
        ))
    }

    pub fn fail_with_api_result<T>(ar: &ApiResult<T>) -> HttpResult {
        Self::fail_with_code(ar.code, ar.message.as_ref().unwrap())
    }

    pub fn internal_server_error() -> HttpResult {
        Self::fail("internal server error")
    }
}


#[async_trait::async_trait]
impl<FN: Send + Sync + 'static, Fut> RunCallback for FN
where
    FN: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    async fn handle(self) -> anyhow::Result<()> {
        self().await
    }
}


/// Definition of callback functions for API interface functions
#[async_trait::async_trait]
impl<FN: Send + Sync + 'static, Fut> HttpHandler for FN
where
    FN: Fn(HttpContext) -> Fut,
    Fut: std::future::Future<Output = HttpResult> + Send + 'static,
{
    async fn handle(&self, ctx: HttpContext) -> HttpResult {
        self(ctx).await
    }
}


impl<'a> Next<'a> {
    pub async fn run(mut self, ctx: HttpContext) -> HttpResult {
        if let Some((current, next)) = self.next_middleware.split_first() {
            self.next_middleware = next;
            current.handle(ctx, self).await
        } else {
            (self.endpoint).handle(ctx).await
        }
    }
}


#[async_trait::async_trait]
impl HttpMiddleware for AccessLog {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResult {
        let start = std::time::Instant::now();
        let ip = ctx.remote_ip();
        let id = ctx.id();
        let method = ctx.req.method().clone();
        let path = CompactString::new(ctx.req.uri().path());
        log::debug!("[{id:08x}] {method} \x1b[33m{path}\x1b[0m");

        let res = next.run(ctx).await;
        let ms = start.elapsed().as_millis();
        match &res {
            Ok(res) => {
                let c = assign_if!(res.status() == hyper::StatusCode::OK, 2, 1);
                log::info!("[{id:08x}] {method} \x1b[34m{path} \x1b[3{c}m{}\x1b[0m {ms}ms, client: {ip}",
                    res.status().as_u16());
            },
            Err(e)  => log::error!("[{id:08x}] {method} \x1b[34m{path}\x1b[0m \x1b[31m500\x1b[0m {ms}ms, error: {e:?}"),
        };

        res
    }
}


impl HttpServer {

    /// Create a new HttpServer
    ///
    /// Arguments:
    ///
    /// * `use_access_log`: set Log middleware if true
    ///
    pub fn new(prefix: &str, use_access_log: bool) -> Self {
        let mut middlewares: Vec<Arc<dyn HttpMiddleware>> = Vec::new();
        if use_access_log {
            middlewares.push(Arc::new(AccessLog));
        }
        HttpServer {
            prefix: CompactString::new(prefix),
            router: std::collections::HashMap::new(),
            middlewares,
            default_handler: Box::new(Self::handle_not_found),
        }
    }

    /// set default function when no matching api function is found
    ///
    /// Arguments:
    ///
    /// * `handler`: The default function when no matching interface function is found
    ///
    pub fn default_handler(&mut self, handler: impl HttpHandler) {
        self.default_handler = Box::new(handler);
    }

    /// register api function for path
    ///
    /// Arguments:
    ///
    /// * `path`: api path
    /// * `handler`: handle of api function
    #[inline]
    pub fn register(&mut self, path: &str, handler: impl HttpHandler) {
        self.router.insert(CompactString::new(path), Box::new(handler));
    }

    /// register middleware
    pub fn middleware<T: HttpMiddleware> (&mut self, middleware: T) -> Arc<T> {
        let result = Arc::new(middleware);
        self.middlewares.push(result.clone());
        result
    }

    // pub async fn run(self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
    //     self.run_with_callbacck(addr, || {}).await
    // }

    /// run http service and enter message loop mode
    ///
    /// Arguments:
    ///
    /// * `addr`: listen addr
    pub async fn run(self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
        self.run_with_callbacck(addr, || async { Ok(()) }).await
    }

    pub async fn run_with_callbacck(self, addr: std::net::SocketAddr, f: impl RunCallback) -> anyhow::Result<()> {
        use std::convert::Infallible;

        struct ServerData { server: HttpServer, id: AtomicU32 }

        let data = Arc::new(ServerData { server: self, id: AtomicU32::new(0) });

        let make_svc = hyper::service::make_service_fn(|conn: &hyper::server::conn::AddrStream| {
            let data = data.clone();
            let addr = conn.remote_addr();

            async move {
                Ok::<_, Infallible>(hyper::service::service_fn(move |req: Request| {
                    let data = data.clone();

                    async move {
                        let path = req.uri().path();
                        let endpoint = match data.server.find_http_handler(path) {
                            Some(handler) => handler,
                            None => data.server.default_handler.as_ref(),
                        };
                        let next = Next { endpoint, next_middleware: &data.server.middlewares };

                        let ctx = HttpContext {
                            req,
                            addr,
                            id: data.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                            uid: 0,
                            attr: RwLock::new(HashMap::new()),
                        };

                        let resp = match next.run(ctx).await {
                            Ok(resp) => resp,
                            Err(e) => Self::handle_error(e),
                        };

                        Ok::<_, Infallible>(resp)
                    }
                }))
            }
        });

        let server = hyper::Server::try_bind(&addr)
                .with_context(|| format!("bind sockaddr {addr} fail"))?
                .serve(make_svc);

        f.handle().await?;

        log::info!("Startup http server on \x1b[34m{addr}\x1b[0m");
        Ok(server.await?)
    }

    async fn handle_not_found(_: HttpContext) -> HttpResult {
        Ok(Resp::fail_with_status(hyper::StatusCode::NOT_FOUND, 404, "Not Found")?)
    }

    pub fn handle_error(err: anyhow::Error) -> Response {
        match Resp::fail(&err.to_string()) {
            Ok(val) => val,
            Err(e) => {
                log::error!("handle_error except: {e:?}");
                let mut res = hyper::Response::new(hyper::Body::from("internal server error"));
                *res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                res
            }
        }
    }

    pub fn concat_path(path1: &str, path2: &str) -> String {
        let mut s = String::with_capacity(path1.len() + path2.len() + 1);
        s.push_str(path1);
        if s.as_bytes()[s.len() - 1] != b'/' {
            s.push('/');
        }
        let path2 = if path2.as_bytes()[0] != b'/' { path2 } else { &path2[1..] };
        s.push_str(path2);
        return s;
    }

    fn find_http_handler(&self, path: &str) -> Option<&dyn HttpHandler> {
        // 前缀不匹配
        if !path.starts_with(self.prefix.as_str()) {
            return None;
        }

        // 找到直接匹配的路径
        let mut path = CompactString::new(&path[self.prefix.len()..]);
        if let Some(handler) = self.router.get(&path) {
            return Some(handler.as_ref());
        }

        // 尝试递归上级路径查找带路径参数的接口
        while let Some(pos) = path.rfind('/') {
            path.truncate(pos + 1);
            path.push('*');

            if let Some(handler) = self.router.get(&path) {
                return Some(handler.as_ref());
            }

            path.truncate(path.len() - 2);
        }

        None
    }
}
