//! macros

/// 类似anyhow::bail宏
#[macro_export]
macro_rules! http_bail {
    ($msg:literal $(,)?) => {
        return Err($crate::HttpError::Custom(String::from($msg)))
    };
    ($err:expr $(,)?) => {
        return Err($crate::HttpError::Custom($err))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err($crate::HttpError::Custom(format!($fmt, $($arg)*)))
    };
}

/// 类似anyhow::anyhow宏
#[macro_export]
macro_rules! http_err {
    ($msg:literal $(,)?) => {
        $crate::HttpError::Custom(String::from($msg))
    };
    ($err:expr $(,)?) => {
        $crate::HttpError::Custom($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::HttpError::Custom(format!($fmt, $($arg)*))
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
                #[cfg(not(feature = "english"))]
                return Err($crate::HttpError::Custom(format!("{}{}", stringify!($attr), " 不能为空")))
                #[cfg(feature = "english")]
                return Err($crate::HttpError::Custom(format!("{}{}", stringify!($attr), " cannot be null")))
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
                    None => {
                        #[cfg(not(feature = "english"))]
                        return Err($crate::HttpError::Custom(format!("{}{}", stringify!($attr), " 不能为空")))
                        #[cfg(feature = "english")]
                        return Err($crate::HttpError::Custom(format!("{}{}", stringify!($attr), " cannot be null")))
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
            return Err($crate::HttpError::Custom(String::from($msg)))
        }
    };
    ($b:expr, $($t:tt)+) => {
        if $b {
            return Err($crate::HttpError::Custom(format!($($t)*)))
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
        if $ar.is_ok() {
            $ar.data
        } else {
            log::info!("ApiResult error: code = {}, msg = {}", $ar.code, $ar.msg);
            return Err($crate::HttpError::Custom(format!($ar.msg)));
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
