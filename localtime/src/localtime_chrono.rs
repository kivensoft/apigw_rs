use std::{fmt::{Display, Formatter}, str::FromStr, ops::Add, time::SystemTime};
use chrono::{Local, DateTime, TimeZone, NaiveDateTime};
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::Visitor};
pub use chrono::format::ParseError as TimeParseError;

pub const DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

pub fn parse_datetime(input: &str) -> Result<DateTime<Local>, TimeParseError> {
    Ok(Local.datetime_from_str(input, DATETIME_FORMAT)?)
}

/// Custom chrono::Datetime format
/// ## Excample
/// ```rust
/// use httpserver::datetime_format;
///
/// #[derive(Serialize)]
/// struct MyData {
///     name: String,
///     #[serde(with = "datetime_format")]
///     now: chrono::DateTime<Local>,
/// }
///
/// let data = MyData {
///     name: String::from("kiven"),
///     now: chrono::Local.with_ymd_and_hms(2023, 03, 28, 12, 0, 9).unwrap()
/// };
///
/// let data_json: MyData = serde_json::to_string(&data).unwrap();
///
/// assert_eq!(r#"{"name":"kiven","now":"2023-03-28 12:00:09"}"#, data_json);
/// ```
pub mod datetime_format {
    use chrono::{Local, DateTime, TimeZone};
    use serde::{Deserialize, Serializer, Deserializer};

    pub fn serialize<S>(date: &DateTime<Local>, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer, {
        serializer.serialize_str(&format!("{}", date.format(super::DATETIME_FORMAT)))
    }

    pub fn deserialize<'de, D>( deserializer: D,) -> Result<DateTime<Local>, D::Error>
            where D: Deserializer<'de>, {
        Local.datetime_from_str(&String::deserialize(deserializer)?, super::DATETIME_FORMAT).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct LocalTime(DateTime<Local>);

impl LocalTime {
    pub fn now() -> Self {
        LocalTime(Local::now())
    }

    pub fn from_unix_timestamp(timestamp: i64) -> Self {
        Self(Local.timestamp_opt(timestamp, 0).unwrap())
    }

    pub fn parse(input: &str) -> Result<Self, TimeParseError> {
        Ok(Self(parse_datetime(input)?))
    }

    pub fn timestamp(&self) -> i64 {
        self.0.timestamp()
    }
}

impl Default for LocalTime {
    fn default() -> Self {
        Self(DateTime::<Local>::default())
    }
}

impl Display for LocalTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.format(DATETIME_FORMAT).fmt(f)
    }
}

impl Add<std::time::Duration> for LocalTime {
    type Output = Self;

    fn add(self, duration: std::time::Duration) -> Self::Output {
        Self(self.0.add(chrono::Duration::from_std(duration).unwrap()))
    }
}

impl AsRef<DateTime<Local>> for LocalTime {
    fn as_ref(&self) -> &DateTime<Local> {
        &self.0
    }
}

impl AsMut<DateTime<Local>> for LocalTime {
    fn as_mut(&mut self) -> &mut DateTime<Local> {
        &mut self.0
    }
}

impl From<DateTime<Local>> for LocalTime {
    fn from(value: DateTime<Local>) -> Self {
        LocalTime(value)
    }
}

impl From<SystemTime> for LocalTime {
    fn from(value: SystemTime) -> Self {
        LocalTime(DateTime::<Local>::from(value).with_timezone(&Local))
    }
}

impl FromStr for LocalTime {
    type Err = TimeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Local.datetime_from_str(s, DATETIME_FORMAT) {
            Ok(v) => Ok(Self(v)),
            Err(e) => Err(e),
        }
    }
}

impl Serialize for LocalTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl <'de> Deserialize<'de> for LocalTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> {
        deserializer.deserialize_str(LocalTimeVisitor)         // 为 Deserializer 提供 Visitor
    }
}

struct LocalTimeVisitor; // LocalDateTime 的 Visitor，用来反序列化

impl <'de> Visitor<'de> for LocalTimeVisitor {
    type Value = LocalTime; // Visitor 的类型参数，这里我们需要反序列化的最终目标是 LocalDateTime

    // 必须重写的函数，用于为预期之外的类型提供错误信息
    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("datetime format must is yyyy-MM-dd HH:mm:ss")
    }

    // 从字符串中反序列化
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        match Local.datetime_from_str(v, DATETIME_FORMAT) {
            Ok(t) => Ok(LocalTime(t)),
            Err(_) => Err(E::custom("datetime format must is yyyy-MM-dd HH:mm:ss")),
        }
    }
}
