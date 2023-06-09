use anyhow::Context;
use compact_str::CompactString;
use hyper::{body::Buf, header::AsHeaderName, http::HeaderValue};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{borrow::BorrowMut, net::Ipv4Addr, sync::{Arc, atomic::AtomicU32}};
use thiserror::Error;

/// Batch registration API interface
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
    ($server:expr, $base:literal, $($path:literal : $handler:expr,)+) => {
        $($server.register(concat!($base, $path), $handler); )*
    };
}

/// Error message response returned when struct fields is Option::None
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
                return $crate::ResBuiler::fail(concat!(stringify!($attr), " can't be null"));
            }
        )*
    };
}

/// Error message response returned when struct fields is Option::None
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
        {
            $(
                if $val.$attr.is_none() {
                    return $crate::ResBuiler::fail(concat!(stringify!($attr), " can't be null"));
                }
            )*
            (   $(
                    match &$val.$attr {
                        Some(v) => v,
                        None => unsafe { std::hint::unreachable_unchecked() },
                    },
                )*
            )
        }
    };
}

/// Error message response returned when expression is true
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
            return $crate::ResBuiler::fail($msg);
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            return $crate::ResBuiler::fail(&format!($($t)*));
        }
    };
}

#[macro_export]
macro_rules! fail_if_api {
    ($ar:expr) => {
        if $ar.is_fail() {
            return $crate::ResBuiler::fail_with_api_result($ar);
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
/// assert_eq(52, a);
/// assert_eq(42, b);
/// ```
#[macro_export]
macro_rules! assign_if {
    ($b:expr, $val1:expr, $val2:expr) => {
        if $b { $val1 } else { $val2 }
    };
}

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

pub const CONTENT_TYPE: &'static str = "Content-Type";
pub const APPLICATION_JSON: &'static str = "applicatoin/json; charset=UTF-8";

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

pub type Request = hyper::Request<hyper::Body>;
pub type Response = hyper::Response<hyper::Body>;

#[derive(Error, Debug)]
pub enum HttpContextError {
    #[error("the request body is empty")]
    EmptyBody,
    #[error("read request body error")]
    ReadBody(#[from] hyper::Error),
    #[error(transparent)]
    DecodeJsonError(#[from] serde_json::error::Error),
}

pub struct HttpContext {
    pub req: Request,
    pub addr: std::net::SocketAddr,
    id: u32,
    uid: u32,
    attrs: Value,
}

impl <T> ApiResult<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 200,
            message: None,
            data: Some(data),
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
    /// use httpserver::{HttpContext, Response, ResBuiler};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_json::<ReqParam>().await?;
    ///     ResBuiler::ok_with_empty()
    /// }
    /// ```
    pub async fn into_json<T: DeserializeOwned>(self) -> Result<T, HttpContextError> {
        match self.into_option_json().await? {
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
    /// use httpserver::{HttpContext, Response, ResBuiler};
    ///
    /// #[derive(serde::Deserialize)]
    /// struct ReqParam {
    ///     user: Option<String>,
    ///     pass: Option<String>,
    /// }
    ///
    /// async fn ping(ctx: HttpContext) -> anyhow::Result<Response> {
    ///     let req_param = ctx.into_option_json::<ReqParam>().await?;
    ///     ResBuiler::ok_with_empty()
    /// }
    /// ```
    pub async fn into_option_json<T: DeserializeOwned>(self) -> Result<Option<T>, HttpContextError> {
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

    pub fn attr(&self, key: &str) -> Option<&Value> {
        match &self.attrs {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn set_attr(&mut self, key: String, value: Value) {
        match self.attrs.borrow_mut() {
            Value::Object(m) => {
                m.insert(key, value);
            },
            _ => {
                let mut m = Map::new();
                m.insert(key, value);
                self.attrs = Value::Object(m);
            },
        };
    }

}

pub struct ResBuiler;

impl ResBuiler {

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
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::resp(hyper::StatusCode::Ok, hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp(status: hyper::StatusCode, body: hyper::Body) -> anyhow::Result<Response> {
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
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::resp_ok(hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp_ok(body: hyper::Body) -> anyhow::Result<Response> {
        Ok(hyper::Response::builder()
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(body).context("response build error")?)
    }

    /// Create a reply message with 200, response body is empty
    pub fn ok_with_empty() -> anyhow::Result<Response> {
        Self::resp_ok(hyper::Body::from(r#"{"code":200}"#))
    }

    /// Create a reply message with 200
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::ok(&serde_json::json!({
    ///     "code": 200,
    ///         "data": {
    ///             "name":"kiven",
    ///             "age": 48,
    ///         },
    /// }))?;
    /// ````
    pub fn ok<T: ?Sized + Serialize>(data: &T) -> anyhow::Result<Response> {
        Self::ok_option(Some(data))
    }

    pub fn ok_option<T: ?Sized + Serialize>(data: Option<&T>) -> anyhow::Result<Response> {
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
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::fail("required field `username`")?;
    /// ````
    pub fn fail(message: &str) -> anyhow::Result<Response> {
        Self::fail_with_code(500, message)
    }

    /// Create a reply message with specified error code
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::fail_with_code(10086, "required field `username`")?;
    /// ````
    pub fn fail_with_code(code: u32, message: &str) -> anyhow::Result<Response> {
        Self::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }

    /// Create a reply message with specified http status and error code
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::ResBuilder;
    ///
    /// ResBuiler::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR,
    ///         10086, "required field `username`")?;
    /// ````
    pub fn fail_with_status(status: hyper::StatusCode, code: u32, message: &str) -> anyhow::Result<Response> {
        // Self::resp(status, to_json_body!({"code": code, "message": message}))
        Self::resp(status, hyper::Body::from(
            serde_json::to_vec(&ApiResult::<&str> {
                code,
                message: Some(String::from(message)),
                data: None,
            })?
        ))
    }

    pub fn fail_with_api_result<T>(ar: &ApiResult<T>) -> anyhow::Result<Response> {
        Self::fail_with_code(ar.code, ar.message.as_ref().unwrap())
    }

    pub fn internal_server_error() -> anyhow::Result<Response> {
        Self::fail("internal server error")
    }
}

#[async_trait::async_trait]
pub trait RunCallback: Send + Sync + 'static {
    async fn handle(self) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl<FN: Send + Sync + 'static, Fut> RunCallback for FN
        where
            FN: FnOnce() -> Fut,
            Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static, {

    async fn handle(self) -> anyhow::Result<()> {
        self().await
    }
}

#[async_trait::async_trait]
pub trait HttpHandler: Send + Sync + 'static {
    async fn handle(&self, ctx: HttpContext) -> anyhow::Result<Response>;
}

pub type BoxHttpHandler = Box<dyn HttpHandler>;

/// Definition of callback functions for API interface functions
#[async_trait::async_trait]
impl<FN: Send + Sync + 'static, Fut> HttpHandler for FN
        where
            FN: Fn(HttpContext) -> Fut,
            Fut: std::future::Future<Output = anyhow::Result<Response>> + Send + 'static, {

    async fn handle(&self, ctx: HttpContext) -> anyhow::Result<Response> {
        self(ctx).await
    }
}

type Router = std::collections::HashMap<CompactString, BoxHttpHandler>;

#[async_trait::async_trait]
pub trait HttpMiddleware: Send + Sync + 'static {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> anyhow::Result<Response>;
}

pub struct Next<'a> {
    pub endpoint: &'a dyn HttpHandler,
    pub next_middleware: &'a [Arc<dyn HttpMiddleware>],
}

impl<'a> Next<'a> {
    pub async fn run(mut self, ctx: HttpContext) -> anyhow::Result<Response> {
        if let Some((current, next)) = self.next_middleware.split_first() {
            self.next_middleware = next;
            current.handle(ctx, self).await
        } else {
            (self.endpoint).handle(ctx).await
        }
    }
}

/// Log middleware
pub struct AccessLog;

#[async_trait::async_trait]
impl HttpMiddleware for AccessLog {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> anyhow::Result<Response> {
        let start = std::time::Instant::now();
        let ip = ctx.remote_ip();
        let id = ctx.id();
        let method = ctx.req.method().clone();
        let path = CompactString::new(ctx.req.uri().path());

        let res = next.run(ctx).await;
        let ms = start.elapsed().as_millis();
        match &res {
            Ok(res) => {
                if log::log_enabled!(log::Level::Debug) {
                    let c = if res.status() == hyper::StatusCode::OK { 2 } else { 1 };
                    log::debug!("[{id:08x}] {method} \x1b[34m{path} \x1b[3{c}m{}\x1b[0m {ms}ms, client: {ip}", res.status().as_u16());
                }
            },
            Err(e)  => log::error!("[{id:08x}] {method} \x1b[34m{path}\x1b[0m \x1b[31m500\x1b[0m {ms}ms, error: {e:?}"),
        };

        res
    }
}

pub struct HttpServer {
    router: Router,
    middlewares: Vec<Arc<dyn HttpMiddleware>>,
    default_handler: BoxHttpHandler,
}

impl HttpServer {

    /// Create a new HttpServer
    ///
    /// Arguments:
    ///
    /// * `use_access_log`: set Log middleware if true
    ///
    pub fn new(use_access_log: bool) -> Self {
        let mut middlewares: Vec<Arc<dyn HttpMiddleware>> = Vec::new();
        if use_access_log {
            middlewares.push(Arc::new(AccessLog));
        }
        HttpServer {
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
                        let endpoint = match data.server.router.get(path) {
                            Some(handler) => &**handler,
                            None => data.server.default_handler.as_ref(),
                        };
                        let next = Next { endpoint, next_middleware: &data.server.middlewares };
                        let id = data.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let ctx = HttpContext { req, addr, id, uid: 0, attrs: Value::Null };

                        let resp = match next.run(ctx).await {
                            Ok(resp) => resp,
                            Err(e) => Self::handle_error(e),
                        };

                        Ok::<_, Infallible>(resp)
                    }
                }))
            }
        });

        log::info!("Starting http server on \x1b[34m{addr}\x1b[0m");
        let server = hyper::Server::try_bind(&addr)
                .with_context(|| format!("bind sockaddr {addr} fail"))?
                .serve(make_svc);

        f.handle().await?;

        Ok(server.await?)
    }

    async fn handle_not_found(_: HttpContext) -> anyhow::Result<Response> {
        Ok(ResBuiler::fail_with_status(hyper::StatusCode::NOT_FOUND, 404, "Not Found")?)
    }

    pub fn handle_error(err: anyhow::Error) -> Response {
        match ResBuiler::fail(&err.to_string()) {
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

}
