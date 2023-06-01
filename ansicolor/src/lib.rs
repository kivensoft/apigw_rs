pub const Z: &str = "\x1b[0m";
pub const K: &str = "\x1b[30m";
pub const R: &str = "\x1b[31m";
pub const G: &str = "\x1b[32m";
pub const Y: &str = "\x1b[33m";
pub const B: &str = "\x1b[34m";
pub const M: &str = "\x1b[35m";
pub const C: &str = "\x1b[36m";
pub const W: &str = "\x1b[37m";

#[doc(hidden)]
#[macro_export]
macro_rules! __ac_color {
    ($c:literal, $e:literal) => { concat!("\x1b[3", $c, "m", $e, "\x1b[0m") };
    ($c:literal, $e:expr)    => { format_args!(concat!("\x1b[3", $c, "m{}\x1b[0m"), $e) };
    ($c:literal, $($t:tt)*)  => { format_args!(concat!("\x1b[3", $c, "m{}\x1b[0m"), format_args!($($t)*)) };
}

#[macro_export]
macro_rules! ac_black {
    ($($t:tt)*) => { $crate::__ac_color!("0", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_red!("red"));
/// println!("this color is {}.", ansicolor::ac_red!(72));
/// println!("this color is {}.", ansicolor::ac_red!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_red {
    ($($t:tt)*) => { $crate::__ac_color!("1", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_green!("green"));
/// println!("this color is {}.", ansicolor::ac_green!(72));
/// println!("this color is {}.", ansicolor::ac_green!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_green {
    ($($t:tt)*) => { $crate::__ac_color!("2", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_yellow!("yellow"));
/// println!("this color is {}.", ansicolor::ac_yellow!(72));
/// println!("this color is {}.", ansicolor::ac_yellow!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_yellow {
    ($($t:tt)*) => { $crate::__ac_color!("3", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_blue!("blue"));
/// println!("this color is {}.", ansicolor::ac_blue!(72));
/// println!("this color is {}.", ansicolor::ac_blue!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_blue {
    ($($t:tt)*) => { $crate::__ac_color!("4", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_magenta!("magenta"));
/// println!("this color is {}.", ansicolor::ac_magenta!(72));
/// println!("this color is {}.", ansicolor::ac_magenta!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_magenta {
    ($($t:tt)*) => { $crate::__ac_color!("5", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_cyan!("cyan"));
/// println!("this color is {}.", ansicolor::ac_cyan!(72));
/// println!("this color is {}.", ansicolor::ac_cyan!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_cyan {
    ($($t:tt)*) => { $crate::__ac_color!("6", $($t)*) };
}

/// ## Example:
/// ```rust
/// println!("this color is {}.", ansicolor::ac_white!("white"));
/// println!("this color is {}.", ansicolor::ac_white!(72));
/// println!("this color is {}.", ansicolor::ac_white!("my name is {}, age is {}", "kiven", 18));
/// ```
#[macro_export]
macro_rules! ac_white {
    ($($t:tt)*) => { $crate::__ac_color!("7", $($t)*) };
}

pub enum AnsiColor { Z, K, R, G, Y, B, M, C, W }

impl std::fmt::Display for AnsiColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AnsiColor::Z => "\x1b[0m",      // 重置, reset
            AnsiColor::K => "\x1b[30m",     // 黑, black
            AnsiColor::R => "\x1b[31m",     // 红, red
            AnsiColor::G => "\x1b[32m",     // 绿, green
            AnsiColor::Y => "\x1b[33m",     // 黄, yellow
            AnsiColor::B => "\x1b[34m",     // 蓝, blue
            AnsiColor::M => "\x1b[35m",     // 紫, magenta
            AnsiColor::C => "\x1b[36m",     // 青, cyan
            AnsiColor::W => "\x1b[37m",     // 白, white
        };
        write!(f, "{}", s)
    }
}

impl std::convert::From<u32> for AnsiColor {
    fn from(value: u32) -> Self {
        match value {
            0 => AnsiColor::Z,
            1 => AnsiColor::K,
            2 => AnsiColor::R,
            3 => AnsiColor::G,
            4 => AnsiColor::Y,
            5 => AnsiColor::B,
            6 => AnsiColor::M,
            7 => AnsiColor::C,
            8 => AnsiColor::W,
            _ => AnsiColor::Z,
        }
    }
}
