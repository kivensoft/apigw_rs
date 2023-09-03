use std::borrow::Cow;
use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("The escape character format is not supported \\{0}")]
    InvalidEscapeChar(char),
    #[error("parse value error: {0}")]
    FromStrError(String),
    #[error("{0} at line {1}")]
    ParseError(&'static str, usize),
    #[error("{0}")]
    StdError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Config Struct
pub struct Config {
    data: Vec<u8>,
    key_values: Vec<ConfigItem>,
}

pub struct ConfigIter<'a> {
    cfg: &'a Config,
    idx: usize,
}

macro_rules! skip_chars {
    (@sub $c:expr, $c1:expr) => { if $c != $c1 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr) => { if $c != $c1 && $c != $c2 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr, $c3:expr) => { if $c != $c1 && $c != $c2 && $c != $c3 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr, $c3:expr, $c4:expr) => { if $c != $c1 && $c != $c2 && $c != $c3 && $c != $c4 { break; } };

    ($val: expr, $pos: expr, $max: expr, $($t: tt)*) => {
        {
            let mut c = 0;
            while $pos < $max {
                c = $val[$pos];
                skip_chars!(@sub c, $($t)*);
                $pos += 1;
            };
            if $pos >= $max { break; } else { c }
        }
    };
}

macro_rules! util_chars {
    (@sub $c:expr, $c1:expr) => { if $c == $c1 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr) => { if $c == $c1 || $c == $c2 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr, $c3:expr) => { if $c == $c1 || $c == $c2 || $c == $c3 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr, $c3:expr, $c4:expr) => { if $c == $c1 || $c == $c2 || $c == $c3 || $c == $c4 { break; } };
    (@sub $c:expr, $c1:expr, $c2:expr, $c3:expr, $c4:expr, $c5:expr) => { if $c == $c1 || $c == $c2 || $c == $c3 || $c == $c4 || $c == $c5 { break; } };

    ($val: expr, $pos: expr, $max: expr, $($t: tt)*) => {
        {
            let mut c = 0;
            while $pos < $max {
                c = $val[$pos];
                util_chars!(@sub c, $($t)*);
                $pos += 1;
            }
            if $pos >= $max { break; } else { c }
        }
    };
}

struct ConfigItem {
    key_begin: usize,
    key_end: usize,
    val_begin: usize,
    val_end: usize,
}

impl ConfigItem {
    fn new() -> Self { Self {key_begin: 0, key_end: 0, val_begin: 0, val_end: 0} }
}

/// Config Implementation
impl Config {
    pub fn with_file<T: AsRef<Path>>(file: T) -> Result<Self, ConfigError> {
        let data = fs::read(file).map_err(|e| ConfigError::StdError(e.into()))?;
        std::str::from_utf8(&data).map_err(|e| ConfigError::StdError(e.into()))?;
        let kv = Self::parse(&data)?;
        Ok(Self {data, key_values: kv})
    }

    pub fn with_text(text: String) -> Result<Self, ConfigError> {
        let data = text.into_bytes();
        let kv = Self::parse(&data)?;
        Ok(Self {data, key_values: kv})
    }

    pub fn with_data(data: Vec<u8>) -> Result<Self, ConfigError> {
        let kv = Self::parse(&data)?;
        std::str::from_utf8(&data).map_err(|e| ConfigError::StdError(e.into()))?;
        Ok(Self {data, key_values: kv})
    }

    pub fn iter(&self) -> ConfigIter {
        ConfigIter { cfg: self, idx: 0 }
    }

    /// Get a value from config as ayn type (That Impls str::FromStr)
    pub fn get<T>(&self, key: &str) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        T::Err: Display,
    {
        match self.get_raw(key) {
            Some(s) => {
                let cs = Self::decode(s)?;
                match cs.parse::<T>() {
                    Ok(v) => Ok(Some(v)),
                    Err(_) => Err(ConfigError::FromStrError(String::from(cs))),
                }
            }
            None => Ok(None),
        }
    }

    /// Get a value from config as a String
    pub fn get_str(&self, key: &str) -> Result<Option<String>, ConfigError> {
        match self.get_raw(key) {
            Some(s) => Ok(Some(Self::decode(s)?.into_owned())),
            None => Ok(None),
        }
    }

    /// Get a value as original data (not escape)
    pub fn get_raw<'a>(&'a self, key: &str) -> Option<&'a [u8]> {
        let key = key.as_bytes();
        for kv in self.key_values.iter() {
            if key == &self.data[kv.key_begin..kv.key_end] {
                return Some(&self.data[kv.val_begin..kv.val_end]);
            }
        }
        None
    }

    // decode value
    fn decode(val: &[u8]) -> Result<Cow<str>, ConfigError> {
        // 删除尾部空白
        let val = Self::trim_whitespace(val);

        // 有转义字符，生成新的转义后的字符串，没有转义字符则返回原串
        if val.contains(&b'\\') {
            let mut v = Vec::with_capacity(val.len() + 32);
            let (mut i, imax) = (0, val.len());
            while i < imax {
                match val[i] {
                    // 转义字符，需要对下一个字符进行判断和处理
                    b'\\' => {
                        i += 1;
                        if i < imax {
                            let c = val[i];
                            // 行尾的'\'，是连接符，跳过下一行的回车换行空白符并继续处理
                            if c == b'\r' || c == b'\n' {
                                skip_chars!(val, i, imax, b'\r', b'\n');
                                skip_chars!(val, i, imax, b' ', b'\t');
                                i -= 1;
                            } else {
                                v.push(Self::escape(c)?);
                            }
                        }
                    }
                    c => v.push(c),
                }
                i += 1;
            }
            // parse之前已经做过utf8有效性检测了，因此这里无需再做1次
            Ok(Cow::Owned(unsafe { String::from_utf8_unchecked(v) }))
        } else {
            // parse之前已经做过utf8有效性检测了，因此这里无需再做1次
            Ok(Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(val) }))
        }
    }

    // 删除尾部的空白字符
    fn trim_whitespace(val: &[u8]) -> &[u8] {
        let mut pos = val.len();
        while pos > 0 {
            let c = val[pos - 1];
            if c != b' ' && c != b'\t' && c != b'\r' && c != b'\n' {
                return &val[..pos];
            }
            pos -= 1;
        }
        val
    }

    // 解析转义字符
    fn escape(v: u8) -> Result<u8, ConfigError> {
        let c = match v {
            b't' => b'\t',
            b'r' => b'\r',
            b'n' => b'\n',
            b's' => b' ',
            b'\\' => b'\\',
            _ => return Err(ConfigError::InvalidEscapeChar(v as char)),
        };
        Ok(c)
    }

    /// Parse a string into the config
    fn parse(data: &[u8]) -> Result<Vec<ConfigItem>, ConfigError> {
        enum ParseStatus { KeyBegin, Comment, Key, Equal, ValBegin, Val, ValContinue }

        let mut result = Vec::with_capacity(64);
        let mut pstate = ParseStatus::KeyBegin;
        let mut curr = ConfigItem::new();
        let (mut i, imax, mut line_no) = (0, data.len(), 1);

        macro_rules! push_str {
            ($vec: expr, $item: expr, $pos: expr, $state: expr, $next_state: expr) => {{
                    $state = $next_state;
                    $item.val_end = $pos;
                    $vec.push($item);
                    $item = ConfigItem::new();
            }};
        }

        while i < imax {
            let c = data[i];
            if c == b'\n' {
                line_no += 1
            };

            match pstate {
                ParseStatus::KeyBegin => {
                    match skip_chars!(data, i, imax, b' ', b'\t', b'\r', b'\n') {
                        b'#' => pstate = ParseStatus::Comment,
                        b'=' => {
                            return Err(ConfigError::ParseError("Not allow start with '='", line_no))
                        }
                        _ => {
                            curr.key_begin = i;
                            pstate = ParseStatus::Key
                        }
                    }
                }
                ParseStatus::Comment => {
                    util_chars!(data, i, imax, b'\r', b'\n');
                    pstate = ParseStatus::KeyBegin;
                }
                ParseStatus::Key => {
                    let c = util_chars!(data, i, imax, b' ', b'\t', b'=', b'\r', b'\n');
                    curr.key_end = i;
                    match c {
                        b'=' => pstate = ParseStatus::ValBegin,
                        b' ' | b'\t' => pstate = ParseStatus::Equal,
                        b'\r' | b'\n' => {
                            return Err(ConfigError::ParseError("Not found field value", line_no))
                        }
                        _ => {}
                    }
                }
                ParseStatus::Equal => match skip_chars!(data, i, imax, b' ', b'\t') {
                    b'=' => pstate = ParseStatus::ValBegin,
                    _ => return Err(ConfigError::ParseError("Not found '='", line_no)),
                },
                ParseStatus::ValBegin => match skip_chars!(data, i, imax, b' ', b'\t') {
                    b'\r' | b'\n' => push_str!(result, curr, 0, pstate, ParseStatus::KeyBegin),
                    b'#' => push_str!(result, curr, 0, pstate, ParseStatus::Comment),
                    _ => {
                        pstate = ParseStatus::Val;
                        curr.val_begin = i;
                    }
                },
                ParseStatus::Val => match util_chars!(data, i, imax, b'\r', b'\n', b'#') {
                    c @ (b'\r' | b'\n') => {
                        if data[i - 1] == b'\\' {
                            pstate = ParseStatus::ValContinue;
                            if c == b'\r' && i + 1 < imax && data[i + 1] == b'\n' {
                                i += 1;
                            }
                        } else {
                            push_str!(result, curr, i, pstate, ParseStatus::KeyBegin);
                        }
                    }
                    b'#' => push_str!(result, curr, i, pstate, ParseStatus::Comment),
                    _ => {}
                },
                ParseStatus::ValContinue => {
                    skip_chars!(data, i, imax, b' ', b'\t');
                    pstate = ParseStatus::Val;
                    continue;
                }
            }
            i += 1;
        }

        match pstate {
            ParseStatus::ValBegin => result.push(curr),
            ParseStatus::Val | ParseStatus::ValContinue => {
                curr.val_end = imax;
                result.push(curr);
            }
            ParseStatus::Key | ParseStatus::Equal => {
                return Err(ConfigError::ParseError("Not found value", line_no))
            }
            _ => {}
        }

        Ok(result)
    }

}

impl Default for Config {
    fn default() -> Config {
        Config {data: Vec::with_capacity(0), key_values: Vec::with_capacity(0)}
    }
}

impl <'a> Iterator for ConfigIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<(&'a str, &'a str)> {
        if self.idx < self.cfg.key_values.len() {
            let kvs = &self.cfg.key_values[self.idx];
            self.idx += 1;
            let k = &self.cfg.data[kvs.key_begin..kvs.key_end];
            let k = unsafe { std::str::from_utf8_unchecked(k) };
            let v = &self.cfg.data[kvs.val_begin..kvs.val_end];
            let v = unsafe { std::str::from_utf8_unchecked(v) };
            Some((k, v))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn test_config() {
        let cf = Config::with_text(r#"  a = \
        b\\c\s\

        user_name = 中文 \
        输入 #comment

        #abc
age=48#this is age
        this=
      sex=ma\n\\n"#.to_owned()).unwrap();

        assert_eq!("b\\c ", cf.get_str("a").unwrap().unwrap());
        assert_eq!("中文 输入", cf.get_str("user_name").unwrap().unwrap());
        assert_eq!("48", cf.get_str("age").unwrap().unwrap());
        assert_eq!("", cf.get_str("this").unwrap().unwrap());
        assert_eq!("ma\n\\n", cf.get_str("sex").unwrap().unwrap());
    }
}
