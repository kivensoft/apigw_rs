/// 格式化参数错误信息
#[macro_export]
macro_rules! arg_err {
    ($text:literal) => {
        concat!("参数 ", $text, " 格式错误")
    };
}

/// 用于错误上下文的宏，例如 `file.read().with_context(|| emsg!("文件读取失败"))`
/// 用法类似format!宏
#[macro_export]
macro_rules! efmt {
    () => {
        format!("at [{}:{}]", file!(), line!())
    };
    ($msg:expr) => {
        format!("{} at [{}:{}]", $msg, file!(), line!())
    };
    ($fmt:expr, $($arg:tt)*) => {
        format!("{} at [{}:{}]", format_args!($fmt, $($arg)*), file!(), line!())
    };
}

/// 使用格式化字符串返回一个anyhow::Error类型的错误，用法类似format!宏
#[macro_export]
macro_rules! err {
    ($msg:expr) => {
        anyhow::anyhow!(format!("{} at [{}:{}]", $msg, file!(), line!()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        anyhow::anyhow!(format!("{} at [{}:{}]", format_args!($fmt, $($arg)*), file!(), line!()))
    };
}

/// 使用格式化字符串返回一个anyhow::Result类型的错误，用法类似format!宏
#[macro_export]
macro_rules! fail {
    ($fmt:expr) => {
        anyhow::bail!(format!("{} at [{}:{}]", $fmt, file!(), line!()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        anyhow::bail!(format!("{} at [{}:{}]", format_args!($fmt, $($arg)*), file!(), line!()))
    };
}

/// 如果条件为真，使用格式化字符串返回一个anyhow::Result类型的错误，用法类似format!宏
#[macro_export]
macro_rules! fail_if {
    ($cond:expr, $msg:expr $(,)?) => {
        if $cond {
            $crate::fail!($msg)
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if $cond {
            $crate::fail!($fmt, $($arg)*);
        }
    };
}

// #[macro_export]
// macro_rules! if_else {
//     ($cond:expr, $true:expr, $false:expr) => {
//         if $cond { $true } else { $false }
//     }
// }
