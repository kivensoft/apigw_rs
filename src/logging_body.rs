use bytes::BytesMut;
use http_body::{Body as HttpBody, Frame};
use hyper::body::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};

// 自定义 Body 实现，实现 HttpBody trait，边 poll 边记录
pub struct LoggingBody<B> {
    inner: B,
    buffer: BytesMut,
    max_log_size: usize,
    logged: bool,
    use_log: bool,
}

impl<B> LoggingBody<B> {
    pub fn new(body: B, max_log_size: usize, use_log: bool) -> Self {
        Self {
            inner: body,
            buffer: BytesMut::with_capacity(max_log_size),
            max_log_size,
            logged: false,
            use_log,
        }
    }
}

impl<B, E> HttpBody for LoggingBody<B>
where
    B: HttpBody<Data = Bytes, Error = E> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 如果是数据帧，记录内容
                if let Some(data) = frame.data_ref()
                    && this.use_log
                    && !this.logged
                    && this.buffer.len() < this.max_log_size
                {
                    let remaining = this.max_log_size - this.buffer.len();
                    let to_copy = std::cmp::min(data.len(), remaining);
                    this.buffer.extend_from_slice(&data[..to_copy]);

                    if this.buffer.len() >= this.max_log_size {
                        this.logged = true;
                        let preview = str_truncate(&this.buffer, this.max_log_size);
                        tracing::info!(body = %preview, "上游响应预览");
                    }
                }

                Poll::Ready(Some(Ok(frame)))
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // 流结束，输出剩余日志
                if this.use_log && !this.logged && !this.buffer.is_empty() {
                    this.logged = true;
                    let preview = str_truncate(&this.buffer, this.max_log_size);
                    tracing::info!(body = %preview, "上游响应预览");
                }
                Poll::Ready(None)
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
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
