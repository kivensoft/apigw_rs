//! macros

/// 类似anyhow::bail宏, 返回anyhow::Result类型，使用anyhow::Error作为错误类型，包装HttpError错误
#[macro_export]
macro_rules! http_bail {
    ($msg:literal) => {
        return Err($crate::HttpError::new($msg.to_string()))
    };

    ($msg:expr) => {
        return Err($crate::HttpError::new($msg))
    };

    ($fmt:literal, $($arg:tt)*) => {
        return Err($crate::HttpError::new(format!($fmt, $($arg)*)))
    };
}

/// 类似anyhow::anyhow宏, 返回anyhow::Error类型，包装HttpError错误
#[macro_export]
macro_rules! http_error {
    ($msg:literal) => {
        $crate::HttpError::new($msg.to_string())
    };

    ($err:expr) => {
        $crate::HttpError::new($err)
    };

    ($fmt:literal, $($arg:tt)*) => {
        $crate::HttpError::new(format!($fmt, $($arg)*))
    };
}

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
            $server.register(&format!("{}{}", $base, $path), $handler);
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
                #[cfg(not(feature = "english"))]
                $crate::http_bail!(format!("{}{}", stringify!($attr), " 不能为空"));
                #[cfg(feature = "english")]
                $crate::http_bail!(format!("{}{}", stringify!($attr), " cannot be null"));
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
        (
            $(
                match &$val.$attr {
                    Some(v) => v,
                    None => {
                        #[cfg(not(feature = "english"))]
                        $crate::http_bail!(format!("{}{}", stringify!($attr), " 不能为空"))
                        #[cfg(feature = "english")]
                        $crate::http_bail!(format!("{}{}", stringify!($attr), " cannot be null"))
                    }
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
            $crate::http_bail!(String::from($msg));
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            $crate::http_bail!(format!($($t)*));
        }
    };
}

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
        if $b {
            $val1
        } else {
            $val2
        }
    };
}

#[macro_export]
macro_rules! if_expr {
    ($b:expr, $exp:expr) => {
        if $b {
            $exp
        }
    };
}

#[macro_export]
macro_rules! log_trace {
    (target: $target:expr, $reqid:expr, $($arg:tt)+) => (log::trace!(target: $target, "[http-req:{}] {}", $reqid, format_args!($($arg)+)));
    ($reqid:expr, $($arg:tt)+) => (log::trace!("[http-req:{}] {}", $reqid, format_args!($($arg)+)))
}

#[macro_export]
macro_rules! log_debug {
    (target: $target:expr, $reqid:expr, $($arg:tt)+) => (log::debug!(target: $target, "[http-req:{}] {}", $reqid, format_args!($($arg)+)));
    ($reqid:expr, $($arg:tt)+) => (log::debug!("[http-req:{}] {}", $reqid, format_args!($($arg)+)))
}

#[macro_export]
macro_rules! log_info {
    (target: $target:expr, $reqid:expr, $($arg:tt)+) => (log::info!(target: $target, "[http-req:{}] {}", $reqid, format_args!($($arg)+)));
    ($reqid:expr, $($arg:tt)+) => (log::info!("[http-req:{}] {}", $reqid, format_args!($($arg)+)))
}

#[macro_export]
macro_rules! log_warn {
    (target: $target:expr, $reqid:expr, $($arg:tt)+) => (log::warn!(target: $target, "[http-req:{}] {}", $reqid, format_args!($($arg)+)));
    ($reqid:expr, $($arg:tt)+) => (log::warn!("[http-req:{}] {}", $reqid, format_args!($($arg)+)))
}

#[macro_export]
macro_rules! log_error {
    (target: $target:expr, $reqid:expr, $($arg:tt)+) => (log::error!(target: $target, "[http-req:{}] {}", $reqid, format_args!($($arg)+)));
    ($reqid:expr, $($arg:tt)+) => (log::error!("[http-req:{}] {}", $reqid, format_args!($($arg)+)))
}
