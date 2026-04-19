use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use compact_str::CompactString;
use futures_util::stream::Stream;
use http_body::Body as HttpBody;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::ReqId;

#[derive(Clone, Debug)]
pub struct ReqPath(pub CompactString);

/// 中间件, 捕获输出结果
pub async fn capture_response_body(
    State(max_size): State<u32>, req: Request<Body>, next: Next,
) -> impl IntoResponse {
    let req_path = ReqPath(req.uri().path().into());
    let rid = req.extensions().get::<ReqId>().map_or(0, |v| v.0);
    let mut response = next.run(req).await;
    response.extensions_mut().insert(req_path);

    let (parts, incoming) = response.into_parts();
    let use_log = tracing::enabled!(tracing::Level::DEBUG) && resp_is_text(&parts.headers);
    // 创建流式 body，直接传递帧数据
    let logged_body = LoggingBody::new(incoming, max_size as usize, use_log, rid);

    Response::from_parts(parts, Body::from_stream(logged_body))
}

// 自定义 Body 实现，实现 HttpBody trait，边 poll 边记录
// pub struct LoggingBody<B> {
pub struct LoggingBody {
    // inner: B,
    inner: Body,
    buffer: BytesMut,
    log_limit: usize,
    use_log: bool,
    rid: u32,
}

// impl<B> LoggingBody<B> {
impl LoggingBody {
    pub fn new(body: Body, log_limit: usize, use_log: bool, rid: u32) -> Self {
        Self {
            inner: body,
            buffer: BytesMut::with_capacity(log_limit),
            log_limit,
            use_log,
            rid,
        }
    }
}

impl Stream for LoggingBody {
    type Item = Result<Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let span = tracing::error_span!("REQ", id = %self.rid);
        let _enter = span.enter();
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 提取数据
                if let Some(data) = frame.data_ref() {
                    // 捕获数据到缓冲区
                    if self.use_log && self.buffer.len() < self.log_limit {
                        let remaining = self.log_limit - self.buffer.len();
                        let take = std::cmp::min(data.len(), remaining);
                        self.buffer.extend_from_slice(&data[..take]);
                    }
                    Poll::Ready(Some(Ok(data.clone())))
                } else {
                    // 非数据帧（如 trailers），忽略并继续
                    self.poll_next(cx)
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                if self.use_log {
                    let preview = str_truncate(&self.buffer, self.log_limit);
                    tracing::debug!("响应预览: {preview}");
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// 正确截断为为合法 UTF-8（对 emoji 等多字节字符也正确）
// 基于字符串进行截断并返回字符串, 保证“合法 UTF‑8 前缀”（不会留下半个 code point）
fn str_truncate(bytes: &[u8], max: usize) -> &str {
    if bytes.len() <= max {
        return std::str::from_utf8(bytes).unwrap_or("");
    }

    // 从尾部回退，最多检查 3 个字节（因为 UTF-8 最长 4 字节）
    // let start = max.saturating_sub(4);
    for i in (0..max).rev() {
        let b = bytes[i];
        // 如果 bytes[i] 是一个 UTF-8 字符的起始字节，则尝试将切片截断到 i 并验证
        // 起始字节的高位模式：0xxxxxxx or 110xxxxx or 1110xxxx or 11110xxx
        // 连续字节的模式：10xxxxxx (不作为起始字节)
        if (b & 0b1100_0000) != 0b1000_0000 {
            // b 看起来像一个可能的起始字节，验证到这里是否为合法 UTF-8
            return std::str::from_utf8(&bytes[..i]).unwrap_or("");
        }
    }

    // 如果都不行，返回空字符串
    ""
}

fn resp_is_text(headers: &HeaderMap<HeaderValue>) -> bool {
    const TEXT_CONTENT_TYPES: [&str; 5] =
        ["application/json", "text/html", "text/plain", "text/xml", "application/xml"];

    if let Some(content_type_value) = headers.get(axum::http::header::CONTENT_TYPE)
        && let Ok(content_type) = content_type_value.to_str()
    {
        for ct in TEXT_CONTENT_TYPES {
            if content_type.starts_with(ct) {
                return true;
            }
        }
    }

    false
}
