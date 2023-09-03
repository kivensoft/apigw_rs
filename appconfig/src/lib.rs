mod getopts;
pub use getopts::{Options, Matches};
use rand::Rng;
use std::fmt::Display;
use std::path::Path;
use thiserror::Error;

#[cfg(feature = "cfg_file")]
mod config;
#[cfg(feature = "cfg_file")]
pub use config::Config;
#[cfg(not(feature = "cfg_file"))]
pub struct Config;

/// Application Parameter Definition Macro.
///
/// ## Examples
///
/// ```rust
/// use appconfig;
///
/// appconfig::appconfig_define!(AppConf,
///     log_level: String => ["L",  "log-level", "LogLevel", "log level(trace/debug/info/warn/error/off)"],
///     log_file : String => ["F",  "log-file", "LogFile", "log filename"],
///     log_max  : String => ["M",  "log-max", "LogFileMaxSize", "log file max size(unit: k/m/g)"],
///     listen   : String => ["l",  "", "Listen", "http service ip:port"],
///     debug    : bool   => ["",  "debug", "", "debug mode"],
/// );
///
/// impl Default for AppConf {
///     fn default() -> Self {
///         AppConf {
///             log_level: String::from("info"),
///             log_file : String::new(),
///             log_max  : String::from("10m"),
///             listen   : String::from("0.0.0.0:8080"),
///             debug    : false,
///         }
///     }
/// }
///
/// let mut ac = AppConf::default();
/// if !appconfig::parse_args(&mut ac, "example application").unwrap();
///     return;
/// }
/// ```
#[macro_export]
macro_rules! appconfig_define {
    // set_opt_flag
    (@set_opt_flag $opts:expr, $short_opt:literal, $long_opt:literal, $opt_name:literal, $desc:literal, $val:expr, bool) => {
        $opts.optflag($short_opt, $long_opt, $desc)
    };
    (@set_opt_flag $opts:expr, $short_opt:literal, $long_opt:literal, $opt_name:literal, $desc:literal, $val:expr, $_:ty) => {
        let s = match $val.len() {
            0 => std::borrow::Cow::Borrowed($desc),
            _ => std::borrow::Cow::Owned($crate::format_opt_desc($desc, &$val)),
        };
        $opts.optopt($short_opt, $long_opt, &s, $opt_name)
    };

    // get_opt_value
    (@get_opt_value $matches:expr, "help", $out_val:expr, $t:ty) => {};
    (@get_opt_value $matches:expr, "conf-file", $out_val:expr, $t:ty) => {};
    (@get_opt_value $matches:expr, $name:expr, $out_val:expr, String) => {
        if let Some(s) = $matches.opt_str($name) {
            $out_val = s;
        }
    };
    (@get_opt_value $matches:expr, $name:expr, $out_val:expr, bool) => {
        if $matches.opt_present($name) {
            $out_val = true;
        }
    };

    // get_cfg_value
    (@get_cfg_value $cfg: expr, "conf-file", $out_val: expr, $t:ty) => {};
    (@get_cfg_value $cfg: expr, $name: expr, $out_val: expr, String) => {
        if let Ok(s) = $cfg.get_str($name) {
            if let Some(s) = s {
                $out_val = s;
            }
        }
    };
    (@get_cfg_value $cfg: expr, $name: expr, $out_val: expr, bool) => {
        if let Ok(s) = $cfg.get_str($name) {
            if let Some(s) = s {
                $out_val = s == "true";
            }
        }
    };

    ( $mod_name:ident, $struct_name:ident, $($field:ident : $type:tt =>
            [$short_opt:literal, $long_opt:tt, $opt_name:literal, $desc:literal]$(,)?)+ ) => {

        mod $mod_name {
            #[derive(Debug, Clone)]
            pub struct $struct_name {
                $( pub $field: $type,)*
            }

            impl $crate::AppConfig for $struct_name {
                fn to_opts(&self) -> $crate::Options {
                    let mut opts = $crate::Options::new();
                    $( $crate::appconfig_define!(@set_opt_flag opts, $short_opt, $long_opt, $opt_name, $desc, self.$field, $type); )*
                    opts
                }

                fn set_from_getopts(&mut self, matches: &$crate::Matches) {
                    $( $crate::appconfig_define!(@get_opt_value matches, $long_opt, self.$field, $type); )*
                }

                fn set_from_cfg(&mut self, cfg: &$crate::Config) {
                    $( $crate::appconfig_define!(@get_cfg_value cfg, $long_opt, self.$field, $type); )*
                }
            }

            impl $struct_name {
                pub fn init() -> &'static mut Self {
                    unsafe {
                        #[cfg(debug_assertions)]
                        if APP_CONFIG_INIT {
                            panic!(stringify!(The $struct_name global variable has already been initialized, and reinitialization is not allowed));
                        }
                        #[cfg(debug_assertions)]
                        { APP_CONFIG_INIT = true; }
                        APP_CONFIG.write(Self::default())
                    }
                }

                pub fn get() -> &'static Self {
                    unsafe {
                        #[cfg(debug_assertions)]
                        if !APP_CONFIG_INIT {
                            panic!(stringify!(The $struct_name global variable no initialized, please initialized it first))
                        }
                        &*APP_CONFIG.as_ptr()
                    }
                }
            }

            static mut APP_CONFIG: std::mem::MaybeUninit<$struct_name> = std::mem::MaybeUninit::uninit();
            #[cfg(debug_assertions)]
            static mut APP_CONFIG_INIT: bool = false;
        }

        pub use $mod_name::$struct_name;
    };
}

#[macro_export]
macro_rules! appglobal_define {
    ( $mod_name:ident, $struct_name:ident, $($field:ident : $type:ty,)+ ) => {

        mod $mod_name {
            #[derive(Debug, Clone)]
            pub struct $struct_name {
                $(pub $field: $type,)*
            }

            impl $struct_name {
                pub fn get() -> &'static Self {
                    unsafe {
                        #[cfg(debug_assertions)]
                        if !INITED {
                            panic!("GLOBAL_VALUE has not been initialized yet");
                        }
                        &*GLOBAL_VALUE.as_ptr()
                    }
                }

                pub fn init(value: Self) -> &'static mut Self {
                    unsafe {
                        #[cfg(debug_assertions)]
                        if INITED {
                            panic!("GLOBAL_VALUE already init");
                        }
                        #[cfg(debug_assertions)]
                        { INITED = true; }
                        GLOBAL_VALUE.write(value)
                    }
                }
            }

            static mut GLOBAL_VALUE: std::mem::MaybeUninit<$struct_name> = std::mem::MaybeUninit::uninit();
            #[cfg(debug_assertions)]
            static mut INITED: bool = false;
        }

        pub use $mod_name::$struct_name;

    }
}

const C_HELP: &str = "help";
#[cfg(feature = "cfg_file")]
const C_CONF_FILE: &str = "conf-file";


#[derive(Error, Debug)]
#[error("{msg}: {source}")]
pub struct AppCfgError {
    msg: String,
    source: Box<dyn std::error::Error>,
}

pub trait AppConfig {
    fn to_opts(&self) -> getopts::Options;
    fn set_from_getopts(&mut self, matches: &getopts::Matches);
    fn set_from_cfg(&mut self, cfg: &Config);
}

pub fn print_banner(banner: &str, use_color: bool) {
    if banner.is_empty() { return; }
    if !use_color { return println!("{}", banner); }

    let mut rng = rand::thread_rng();
    let mut text = Vec::with_capacity(512);
    let mut dyn_color: [u8; 5] = [b'\x1b', b'[', b'3', b'0', b'm'];
    let (mut n1, mut n2) = (0, 0);

    for line in banner.lines() {
        loop {
            let i = rng.gen_range(1..8);
            if n1 != i && n2 != i { n1 = n2; n2 = i; break }
        }
        dyn_color[3] = b'0' + n2;
        text.extend_from_slice(&dyn_color);
        text.extend_from_slice(line.as_bytes());
        text.push(b'\n');
    }

    text.extend_from_slice(b"\x1b[0m\n");
    print!("{}", unsafe { std::str::from_utf8_unchecked(&text) });
}

/// Parsing configuration from command line parameters and configuration files
/// and populate it with the variable `ac`
///
/// If the return value is Ok(false), it indicates that the program needs to be terminated immediately.
///
/// Arguments:
///
/// * `app_config`: Output variable, which will be filled after parameter parsing
/// * `banner`: application banner
///
/// Returns:
///
/// Ok(true): success, Ok(false): require terminated, Err(e): error
///
#[inline]
pub fn parse_args<T: AppConfig>(app_config: &mut T, banner: &str) -> Result<bool, AppCfgError> {
    parse_args_ext(app_config, banner, |_| true)
}

/// Parsing configuration from command line parameters and configuration files
/// and populate it with the variable `ac`
///
/// If the return value is false, it indicates that the program needs to be terminated immediately.
///
/// * `app_config`: application config variable
/// * `banner`: application banner
/// * `f`: A user-defined callback function that checks the validity of parameters.
/// If it returns false, this function will print the help information and return Ok(false)
///
/// Returns:
///
/// Ok(true): success, Ok(false): require terminated, Err(e): error
///
pub fn parse_args_ext<T: AppConfig, F: Fn(&T) -> bool>(app_config: &mut T, version: &str, f: F) -> Result<bool, AppCfgError> {
    let mut args = std::env::args();
    let prog = args.next().unwrap();

    let mut opts = app_config.to_opts();
    #[cfg(not(feature = "chinese"))]
    opts.optflag("h", C_HELP, "this help");
    #[cfg(feature = "chinese")]
    opts.optflag("h", C_HELP, "显示帮助信息");

    #[cfg(feature = "cfg_file")]
    {
        #[cfg(not(feature = "chinese"))]
        opts.optopt("c", C_CONF_FILE, "set configuration file", "ConfigFile");
        #[cfg(feature = "chinese")]
        opts.optopt("c", C_CONF_FILE, "从配置文件中加载参数信息", "ConfigFile");
    }

    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(e) => {
            print_usage(&prog, version, &opts);
            #[cfg(not(feature = "chinese"))]
            return Err(AppCfgError{msg: String::from("parse cmdline args error"), source: Box::new(e)});
            #[cfg(feature = "chinese")]
            return Err(AppCfgError{msg: String::from("解析命令行参数出错"), source: Box::new(e)});
        }
    };

    if matches.opt_present(C_HELP) {
        print_usage(&prog, version, &opts);
        return Ok(false);
    }

    // 参数设置优先级：命令行参数 > 配置文件参数
    // 因此, 先从配置文件读取参数覆盖缺省值, 然后用命令行参数覆盖
    // 从配置文件读取参数, 如果环境变量及命令行未提供配置文件参数, 则允许读取失败, 否则, 读取失败返回错误
    #[cfg(feature = "cfg_file")]
    get_from_config_file(app_config, &matches, &prog)?;

    // 从命令行读取参数
    app_config.set_from_getopts(&matches);

    if !f(app_config) {
        print_usage(&prog, version, &opts);
        return Ok(false);
    }

    // print_banner(banner, true);

    Ok(true)
}

pub fn format_opt_desc<T: Display>(desc: &str, val: &T) -> String {
    #[cfg(not(feature = "chinese"))]
    return format!("{} (\x1b[34mdefault: \x1b[32m{}\x1b[0m)", desc, val);
    #[cfg(feature = "chinese")]
    return format!("{} (\x1b[34m缺省值: \x1b[32m{}\x1b[0m)", desc, val);
}


fn print_usage(prog: &str, version: &str, opts: &getopts::Options) {
    if version.len() > 0 {
        println!("\n{}", version);
    }
    let path = std::path::Path::new(prog);
    let prog = path.file_name().unwrap().to_str().unwrap();
    #[cfg(not(feature = "chinese"))]
    let brief = format!("\nUsage: \x1b[36m{} \x1b[33m{}\x1b[0m", &prog, "[options]");
    #[cfg(feature = "chinese")]
    let brief = format!("\n使用方法: \x1b[36m{} \x1b[33m{}\x1b[0m", &prog, "[选项]");
    println!("{}", opts.usage(&brief));
}

#[cfg(feature = "cfg_file")]
fn get_from_config_file<T: AppConfig>(ac: &mut T, matches: &Matches, prog: &str) -> Result<(), AppCfgError> {

    let (conf_is_set, conf_file) = match matches.opt_str(C_CONF_FILE) {
        Some(s) => (true, s),
        None => {
            let mut path = std::path::PathBuf::from(prog);
            path.set_extension("conf");
            (false, path.to_str().unwrap().to_owned())
        }
    };

    match Config::with_file(&Path::new(&conf_file)) {
        Ok(cfg) => ac.set_from_cfg(&cfg),
        Err(e) => {
            if conf_is_set {
                #[cfg(not(feature = "chinese"))]
                return Err(AppCfgError{msg: format!("can't load app config file {conf_file}"), source: Box::new(e)});
                #[cfg(feature = "chinese")]
                return Err(AppCfgError{msg: format!("加载应用程序配置文件{conf_file}失败"), source: Box::new(e)});
            };
        }
    };
    Ok(())
}


#[cfg(not(feature = "cfg_file"))]
impl Config {
    pub fn get_str(&self, _: &str) -> Result<Option<String>> {
        Ok(None)
    }
}
