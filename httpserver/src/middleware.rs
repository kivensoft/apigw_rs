use compact_str::CompactString;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, header::HeaderValue};

use crate::{
    log_debug, log_error, log_info, log_trace, if_else, HttpContext, HttpResponse,
    Next, Response, CONTENT_TYPE
};

/// middleware interface
#[async_trait::async_trait]
pub trait HttpMiddleware: Send + Sync + 'static {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse;
}

/// Log middleware，访问日志中间件
pub struct AccessLog;
/// Cors middleware，跨域访问中间件
pub struct CorsMiddleware;

#[async_trait::async_trait]
impl HttpMiddleware for AccessLog {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        let start = std::time::Instant::now();
        let ip = ctx.remote_ip();
        let id = ctx.id;
        let method = ctx.req.method().clone();
        let path = CompactString::new(ctx.req.uri().path());
        log_debug!(id, "{method} \x1b[33m{path}\x1b[0m");

        // 记录请求参数日志
        if log::log_enabled!(log::Level::Trace) {
            if let Some(query) = ctx.req.uri().query() {
                if !query.is_empty() {
                    log_trace!(id, "[QUERY] {query}");
                }
            }
            let mut buf = String::with_capacity(512);
            for header in ctx.req.headers() {
                buf.push_str("\n\t");
                buf.push_str(header.0.as_str());
                buf.push_str(": ");
                buf.push_str(std::str::from_utf8(header.1.as_bytes()).unwrap());
            }
            log_trace!(id, "[HEADER] ->{buf}");

            if let Some(ct) = ctx.req.headers().get(CONTENT_TYPE) {
                let ct = ct.as_bytes();
                if ct.starts_with(b"application/json")
                    || ct.starts_with(b"application/x-www-form-urlencoded")
                {
                    log_trace!(id, "[BODY] {}", std::str::from_utf8(&ctx.body).unwrap());
                }
            }
        }

        let mut res = next.run(ctx).await;
        // 输出接口调用耗时
        let ms = start.elapsed().as_millis();
        match &res {
            Ok(res) => {
                let c = if_else!(res.status() == hyper::StatusCode::OK, 2, 1);
                log_info!(
                    id,
                    "{method} \x1b[34m{path} \x1b[3{c}m{}\x1b[0m {ms}ms, client: {ip}",
                    res.status().as_u16()
                );
            }
            Err(e) => log_error!(
                id,
                "{method} \x1b[34m{path}\x1b[0m \x1b[31m500\x1b[0m {ms}ms, error: {e:?}"
            ),
        };

        // 记录回复结果日志
        if log::log_enabled!(log::Level::Trace) {
            if let Ok(r) = res {
                let (parts, body) = r.into_parts();
                let body: Bytes = body.collect().await.unwrap().to_bytes();
                log_trace!(id, "[RESP] {}", std::str::from_utf8(&body).unwrap());
                res = Ok(Response::from_parts(parts, Full::from(body)));
            }
        }
        res
    }
}

#[async_trait::async_trait]
impl HttpMiddleware for CorsMiddleware {
    async fn handle<'a>(&'a self, ctx: HttpContext, next: Next<'a>) -> HttpResponse {
        use hyper::header::{
                ALLOW,
                ACCESS_CONTROL_ALLOW_HEADERS,
                ACCESS_CONTROL_ALLOW_METHODS,
                ACCESS_CONTROL_ALLOW_ORIGIN
        };

        let is_options = ctx.req.method() == hyper::Method::OPTIONS;
        let allow_host = HeaderValue::from_str("*").unwrap();
        if is_options {
            Ok(
                hyper::Response::builder()
                    .header(ACCESS_CONTROL_ALLOW_HEADERS, allow_host.clone())
                    .header(ACCESS_CONTROL_ALLOW_METHODS, allow_host.clone())
                    .header(ACCESS_CONTROL_ALLOW_ORIGIN, allow_host.clone())
                    .header(ALLOW, HeaderValue::from_str("GET,HEAD,OPTIONS").unwrap())
                    .body(Full::<Bytes>::new(Bytes::new()))?)
        } else {
            let mut res = next.run(ctx).await?;
            let h = res.headers_mut();
            h.append(ACCESS_CONTROL_ALLOW_HEADERS, allow_host.clone());
            h.append(ACCESS_CONTROL_ALLOW_METHODS, allow_host.clone());
            h.append(ACCESS_CONTROL_ALLOW_ORIGIN, allow_host.clone());
            Ok(res)
        }
    }
}
