use std::{fmt::Write as _, sync::atomic::{AtomicU32, Ordering}};

use axum::http::Request;
use compact_str::CompactString;
use rclite::Arc;
use smallstr::SmallString;
use smallvec::SmallVec;
use time::{OffsetDateTime, format_description::BorrowedFormatItem, macros::format_description};
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    trace::{MakeSpan, OnRequest, TraceLayer},
};
use tracing::{
    Event, Level, Span, Subscriber,
    field::{Field, ValueSet, Visit},
};
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_log::NormalizeEvent;
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{self, FmtContext, FormatEvent, FormatFields, format::Writer},
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use crate::{ReqId, write_json_str};

/// if else ternary expression
///
///  ## Example
/// ```rust
/// use httpserver::if_else;
///
/// let a = if_else!(true, 52, 42);
/// let b = if_else!(false, 52, 42);
/// assert_eq!(52, a);
/// assert_eq!(42, b);
/// ```
#[macro_export]
macro_rules! if_else {
    ($b:expr, $val1:expr, $val2:expr) => {
        if $b { $val1 } else { $val2 }
    };
}

pub const DATETIME_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
pub const SHORT_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
pub const FULL_DATETIME_FORMAT: &[BorrowedFormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");

const MAX_SPAN_ID: u32 = 99999;

pub fn now_str() -> String {
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(DATETIME_FORMAT)
        .unwrap_or_else(|s| s.to_string())
}

pub fn now_str_into<W: std::io::Write>(output: &mut W) {
    let _ = OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format_into(output, DATETIME_FORMAT);
}

pub type ClassIfier = SharedClassifier<ServerErrorsAsFailures>;

pub fn custom_trace_layer() -> TraceLayer<ClassIfier, CustomMakeSpan, CustomOnRequest> {
    TraceLayer::new_for_http()
        .make_span_with(CustomMakeSpan::new())
        .on_request(CustomOnRequest)
}

// 自定义 OnRequest - 输出 started processing request
#[derive(Clone)]
pub struct CustomOnRequest;

impl<B> OnRequest<B> for CustomOnRequest {
    fn on_request(&mut self, request: &axum::http::Request<B>, _span: &Span) {
        tracing::debug!(
            // target: "tower_http::trace::on_request",
            path = %request.uri().path(),
            "started processing request"
        );
    }
}

/// 自定义tracing的span, 生成req_id
#[derive(Clone)]
pub struct CustomMakeSpan(Arc<AtomicU32>);

impl CustomMakeSpan {
    pub fn new() -> Self {
        CustomMakeSpan(Arc::new(AtomicU32::new(1)))
    }

    /// 获取当前值，并原子性地增加到下一个值（循环）
    pub fn fetch_next(&self) -> u32 {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                let next = if current >= MAX_SPAN_ID {
                    1
                } else {
                    current + 1
                };
                Some(next)
            })
            .expect("update always succeeds")
    }

    /// 只获取当前值，不自增
    pub fn load(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }

    /// 重置为 0
    pub fn reset(&self) {
        self.0.store(0, Ordering::SeqCst);
    }
}

impl<B> MakeSpan<B> for CustomMakeSpan {
    fn make_span(&mut self, req: &Request<B>) -> Span {
        // let path = request.uri().path();
        // let query = request.uri().query().unwrap_or("");

        let req_id = req.extensions().get::<ReqId>();
        let id = req_id.map(|id| id.0).unwrap_or(0);

        // info_span 表示只要缺省日志级别只要大于等于info, 该span就会被创建
        tracing::info_span!(
            "REQ",
            %id,
            // method = %request.method(),
            // path = %path,
            // query = %query,
            // request_id = %uuid::Uuid::new_v4(),
        )
    }
}

/// 创建tracing日志的构造类
pub struct TracingBuilder {
    directives: String,
    file: Option<(CompactString, CompactString)>,
    // max_size: u32,
    // max_backups: u32,
    disable_console: bool,
}

impl TracingBuilder {
    pub fn new() -> Self {
        Self {
            directives: String::new(),
            file: None,
            // max_size: 10 * 1024 * 1024,
            // max_backups: 3,
            disable_console: false,
        }
    }

    /// 设置日志过滤规则, 使用了该函数, 则 [default_level] 将失效,
    ///     而 [add_directive] 还可以继续使用
    ///
    /// 例如: "info,axum=debug,tower_http::request=trace"
    pub fn directives<T: Into<String>>(mut self, directives: T) -> Self {
        self.directives = directives.into();
        self
    }

    pub fn default_level(mut self, default_level: Level) -> Self {
        if self.directives.is_empty() {
            self.directives.push_str(default_level.as_str());
        }
        self
    }

    /// 添加特定的日志过滤规则。
    ///
    /// 允许为指定的模块或目标设置独立的日志级别，
    /// 这些规则会在全局级别基础上进行补充。
    ///
    /// ### 参数
    /// * `filter` - 模块名或目标名称过滤字符串 = 日志级别
    ///
    /// ### 返回值
    /// 返回修改后的 [`LogOpt`] 实例，支持链式调用
    pub fn add_directive(mut self, target: &str, level: Level) -> Self {
        if !self.directives.is_empty() {
            self.directives.push(',');
        }
        self.directives.push_str(target);
        self.directives.push('=');
        self.directives.push_str(level.as_str());
        self
    }

    pub fn file<T: Into<CompactString>>(mut self, dir: T, file: T) -> Self {
        self.file = Some((dir.into(), file.into()));
        self
    }

    // pub fn max_size(mut self, max_size: u32) -> Self {
    //     self.max_size = max_size;
    //     self
    // }

    // pub fn max_backups(mut self, max_backups: u32) -> Self {
    //     self.max_backups = max_backups;
    //     self
    // }

    pub fn disable_console(mut self, disable_console: bool) -> Self {
        self.disable_console = disable_console;
        self
    }

    pub fn build(self) -> Option<WorkerGuard> {
        // 既不输出到控制台, 也不输出到文件, 直接返回
        if self.disable_console && self.file.is_none() {
            return None;
        }

        // 创建日志过滤器, 设置缺省日志级别及添加自定义日志级别过滤器
        let filter = EnvFilter::new(self.directives);
        let registry = tracing_subscriber::registry();

        // ========== 控制台层：自定义格式 ==========
        let console_layer = if !self.disable_console {
            let console_layer = fmt::layer()
                .event_format(CustomFormatter::new(true))
                .with_filter(filter.clone());
            Some(console_layer)
        } else {
            None
        };

        // ========== 文件层：JSON 结构化格式 ==========
        let guard = if let Some((dir, file)) = &self.file {
            let file_appender = rolling::daily(dir, file);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            if let Some(console_layer) = console_layer {
                let file_layer = fmt::layer()
                    .with_writer(non_blocking)
                    .event_format(CustomFormatter::new(false))
                    .with_filter(filter);
                registry.with(console_layer).with(file_layer).init();
            } else {
                let file_layer = fmt::layer()
                    .with_writer(non_blocking)
                    .event_format(CustomFormatter::new(false))
                    .with_filter(filter);
                registry.with(file_layer).init();
            }

            Some(guard)
        } else {
            if let Some(console_layer) = console_layer {
                registry.with(console_layer).init();
            }
            None
        };

        // 尝试初始化 log => tracing 的兼容性处理
        let _ = tracing_log::LogTracer::init();

        guard
    }

}

struct CustomFormatter {
    use_ansi: bool,
}

impl CustomFormatter {
    fn new(use_ansi: bool) -> Self {
        Self { use_ansi }
    }
}

impl<S, N> FormatEvent<S, N> for CustomFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>,
    ) -> std::fmt::Result {
        // 关键：使用 NormalizeEvent trait 获取 log 的原始 metadata
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());

        let mut time_buf = SmallVec::<[u8; 32]>::new();
        // 时间
        let time_str = {
            let time = OffsetDateTime::now_local().unwrap();
            let fmt = if_else!(self.use_ansi, SHORT_FORMAT, FULL_DATETIME_FORMAT);
            let _ = time.format_into(&mut time_buf, fmt);
            unsafe { std::str::from_utf8_unchecked(&time_buf) }
        };
        // 级别
        let level = meta.level();

        // [时间] [级别]
        if self.use_ansi {
            write!(
                writer,
                "[\x1b[32m{}\x1b[0m] [\x1b[{}m{:5}\x1b[0m] ",
                time_str,
                level_to_color_code(level),
                level
            )?;
        } else {
            write!(writer, "[{}] [{:5}] ", time_str, level)?;
        }

        // 当前 span 及其字段
        if let Some(span) = ctx.current_span().id().and_then(|id| ctx.span(id)) {
            let meta = span.metadata();
            if self.use_ansi {
                write!(writer, "[\x1b[36m{}\x1b[0m", meta.name())?;
            } else {
                write!(writer, "[{}", meta.name())?;
            }

            // Span 字段
            let ext = span.extensions();
            if let Some(fields) = ext.get::<fmt::FormattedFields<N>>()
                && !fields.is_empty()
            {
                if self.use_ansi {
                    write!(writer, "\x1b[31m{{\x1b[0m{}\x1b[31m}}\x1b[0m", fields)?;
                } else {
                    writer.write_char('{')?;
                    write_with_ansi_escapes(&mut writer, fields);
                    writer.write_char('}')?;
                }
            }

            write!(writer, "] ")?;
        }

        if self.use_ansi {
            write!(writer, "[\x1b[90m{}\x1b[0m] ", meta.target())?;
        } else {
            write!(writer, "[{}] ", meta.target())?;
        }

        // 消息
        let mut visitor = CollectVisitor::new();
        event.record(&mut visitor);
        visitor.write_fields(&mut writer, self.use_ansi);
        // if self.use_ansi {
        //     writer.write_str("\x1b[31m{\x1b[0m")?;
        //     ctx.field_format().format_fields(writer.by_ref(), event)?;
        //     writer.write_str("\x1b[31m}\x1b[0m")?;
        // } else {
        //     event.record(&mut visitor);
        // }

        writeln!(writer)
    }
}

fn level_to_color_code(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 31, // Red
        Level::WARN => 35,  // Magenta
        Level::INFO => 34,  // Blue
        Level::DEBUG => 33, // Yellow
        Level::TRACE => 37, // White
    }
}

/// 去除 ANSI 转义序列的方式写入 [`Writer`]
fn write_with_ansi_escapes(writer: &mut Writer, text: &str) {
    let bytes = text.as_bytes();
    for item in SkipAnsiColorIter::new(bytes) {
        let s = unsafe { std::str::from_utf8_unchecked(item) };
        let _ = writer.write_str(s);
    }
}

/// 基于日志文本内容的去除ansi颜色信息的迭代器, 每次迭代获取不包含ansi色彩设置的文本内容
struct SkipAnsiColorIter<'a> {
    data: &'a [u8],
    pos: usize,
    find_len: usize,
}

impl<'a> SkipAnsiColorIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let find_len = if data.len() > 3 { data.len() - 3 } else { 0 };
        SkipAnsiColorIter { data, pos: 0, find_len }
    }
}

impl<'a> Iterator for SkipAnsiColorIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // 过滤ansi颜色
        let (mut pos, find_len, data) = (self.pos, self.find_len, self.data);
        while pos < find_len {
            unsafe {
                if *data.get_unchecked(pos) != 0x1b || *data.get_unchecked(pos + 1) != b'[' {
                    pos += 1;
                    continue;
                }

                // 找到ansi颜色前缀，返回前缀前的字符串并更新当前位置和已写入字节
                let n = if *data.get_unchecked(pos + 3) == b'm' {
                    4
                } else {
                    5
                };
                let p = self.pos;
                self.pos = pos + n;
                return Some(&data[p..pos]);
            }
        }

        // 写入剩余的数据
        let dl = data.len();
        if pos < dl {
            let p = self.pos;
            self.pos = dl;
            return Some(&data[p..dl]);
        }

        None
    }
}

// 创建一个 Visitor 来收集字段
// struct CustomVisitor<'a> {
//     writer: Writer<'a>,
//     first: bool,
//     use_ansi: bool,
// }

// impl<'a> CustomVisitor<'a> {
//     fn new(writer: Writer<'a>, use_ansi: bool) -> Self {
//         CustomVisitor { writer, first: true, use_ansi }
//     }

//     fn write_field(&mut self, field: &Field) {
//         if field.name() == "message" {
//             if self.use_ansi {
//                 let _ = self.writer.write_str("\x1b[31m【\x1b[0m");
//             } else {
//                 let _ = self.writer.write_str("【");
//             }
//             return;
//         }

//         if !self.first {
//             let _ = self.writer.write_str(", ");
//         } else {
//             if self.use_ansi {
//                 let _ = self.writer.write_str("\x1b[31m】\x1b[0m ");
//             } else {
//                 let _ = self.writer.write_str("】 ");
//             }
//             self.first = false;
//         }

//         if self.use_ansi {
//             let _ = self.writer.write_str("\x1b[33m");
//             let _ = self.writer.write_str(field.name());
//             // let _ = self.writer.write_str("\x1b[0m");
//             let _ = self.writer.write_str("\x1b[90m=\x1b[0m");
//         } else {
//             let _ = self.writer.write_str(field.name());
//             let _ = self.writer.write_char('=');
//         }
//     }
// }

// impl<'a> Visit for CustomVisitor<'a> {
//     fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
//         self.write_field(field);
//         let _ = write!(self.writer, r#"{:?}"#, value);
//     }

//     // 也可以实现其他 record_* 方法来优化显示
//     fn record_str(&mut self, field: &Field, value: &str) {
//         self.write_field(field);
//         let _ = self.writer.write_char('"');
//         let _ = write_json_str(&mut self.writer, value);
//         let _ = self.writer.write_char('"');
//     }

//     fn record_i64(&mut self, field: &Field, value: i64) {
//         self.write_field(field);
//         let mut buf = itoa::Buffer::new();
//         let _ = self.writer.write_str(buf.format(value));
//     }

//     fn record_u64(&mut self, field: &Field, value: u64) {
//         self.write_field(field);
//         let mut buf = itoa::Buffer::new();
//         let _ = self.writer.write_str(buf.format(value));
//     }

//     fn record_bool(&mut self, field: &Field, value: bool) {
//         self.write_field(field);
//         let v = if value { "true" } else { "false" };
//         let _ = self.writer.write_str(v);
//     }

//     fn record_f64(&mut self, field: &Field, value: f64) {
//         self.write_field(field);
//         let _ = write!(self.writer, "{}", value);
//     }

// }


type ValueStr = SmallString<[u8; 128]>;

struct CollectVisitor {
    message: ValueStr,
    fields: SmallVec<[(CompactString, ValueStr); 64]>,
}

impl CollectVisitor {
    fn new() -> Self {
        Self {
            message: ValueStr::new(),
            fields: SmallVec::new(),
        }
    }

    fn is_message(field_name: &str) -> bool {
        field_name == "message"
    }

    fn push(&mut self, field: &Field, value: ValueStr) {
        let name = field.name();
        if Self::is_message(name) {
            self.message = value;
        } else {
            self.fields.push((name.into(), value));
        }
    }

    fn write_fields(&self, writer: &mut Writer<'_>, use_ansi: bool) {
        macro_rules! wstr {
            ($expr:expr) => {
                let _ = writer.write_str($expr);
            };
        }

        macro_rules! wch {
            ($expr:expr) => {
                let _ = writer.write_char($expr);
            };
        }

        if !self.message.is_empty() {
            if use_ansi { wstr!("\x1b[31m"); }
            wch!('【');
            if use_ansi { wstr!("\x1b[0m"); }
            wstr!(&self.message);
            if use_ansi { wstr!("\x1b[31m"); }
            wch!('】');
            if use_ansi { wstr!("\x1b[0m"); }
            wch!(' ');
        }

        let mut first = true;
        for field in &self.fields {
            if !first {
                wstr!(", ");
            } else {
                wch!('{');
                first = false;
            }

            if use_ansi {
                wstr!("\x1b[33m");
            } else {
                wch!('[');
            }
            wstr!(&field.0);
            if use_ansi {
                wstr!("\x1b[90m=\x1b[0m\"");
            } else {
                wstr!("]=\"");
            }

            let _ = write_json_str(writer, &field.1);
            wch!('"');
        }

        if !first {
            wch!('}');
        }
    }

}

impl Visit for CollectVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut vstr = ValueStr::new();
        let _ = write!(&mut vstr, "{:?}", value);
        self.push(field, vstr);

    }

    // 也可以实现其他 record_* 方法来优化显示
    fn record_str(&mut self, field: &Field, value: &str) {
        let vstr = ValueStr::from_str(value);
        self.push(field, vstr);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        let mut buf = itoa::Buffer::new();
        let vstr = ValueStr::from_str(buf.format(value));
        self.push(field, vstr);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        let mut buf = itoa::Buffer::new();
        let vstr = ValueStr::from_str(buf.format(value));
        self.push(field, vstr);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        let vstr = ValueStr::from_str(if value { "true" } else { "false" });
        self.push(field, vstr);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let mut vstr = ValueStr::new();
        let _ = write!(&mut vstr, "{}", value);
        self.push(field, vstr);
    }

}
