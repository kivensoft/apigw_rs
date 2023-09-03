use std::{fmt::{Display, Formatter}, str::FromStr, sync::Once, mem::MaybeUninit, ops::Add, time::SystemTime};
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Visitor, Unexpected}};
use time::{OffsetDateTime, macros, format_description::FormatItem, PrimitiveDateTime, UtcOffset, util::local_offset};
pub use time::error::Parse as TimeParseError;

pub const DATETIME_FORMAT: &[FormatItem] = macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

pub fn local_offset() -> UtcOffset {
    static mut LOCAL_OFFSET: MaybeUninit<UtcOffset> = MaybeUninit::uninit();
    static LOCAL_OFFSET_INIT: Once = Once::new();
    unsafe {
        LOCAL_OFFSET_INIT.call_once(|| {
            LOCAL_OFFSET.write(UtcOffset::current_local_offset().unwrap());
        });
        (*LOCAL_OFFSET.as_ptr()).clone()
    }
}

pub fn parse_datetime(input: &str) -> Result<OffsetDateTime, TimeParseError> {
    let t = PrimitiveDateTime::parse(input, DATETIME_FORMAT)?;
    Ok(t.assume_offset(local_offset()))
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
///     now: time::OffsetDateTime,
/// }
///
/// let data = MyData {
///     name: String::from("kiven"),
///     now: time::datetime!("2023-03-28 12:00:09")
/// };
///
/// let data_json: MyData = serde_json::to_string(&data).unwrap();
///
/// assert_eq!(r#"{"name":"kiven","now":"2023-03-28 12:00:09"}"#, data_json);
/// ```
pub mod datetime_format {
    use serde::{Deserialize, Serializer, Deserializer};
    use time::OffsetDateTime;


    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer, {
        serializer.serialize_str(&date.format(super::DATETIME_FORMAT).map_err(serde::ser::Error::custom)?)
    }

    pub fn deserialize<'de, D>( deserializer: D,) -> Result<OffsetDateTime, D::Error>
            where D: Deserializer<'de>, {
        OffsetDateTime::parse(&String::deserialize(deserializer)?, super::DATETIME_FORMAT).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct LocalTime(OffsetDateTime);

impl LocalTime {
    pub fn now() -> Self {
        unsafe { local_offset::set_soundness(local_offset::Soundness::Unsound); }
        Self(OffsetDateTime::now_local().unwrap())
    }

    pub fn from_unix_timestamp(timestamp: i64) -> Self {
        Self(OffsetDateTime::from_unix_timestamp(timestamp).unwrap())
    }

    pub fn parse(input: &str) -> Result<Self, TimeParseError> {
        Ok(Self(parse_datetime(input)?))
    }

    pub fn timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }
}

impl Default for LocalTime {
    fn default() -> Self {
        Self(OffsetDateTime::from_unix_timestamp(0).unwrap())
    }
}

impl Display for LocalTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.format(DATETIME_FORMAT) {
            Ok(s) => {
                f.write_str(&s)?;
                Ok(())
            }
            Err(_) => Err(std::fmt::Error),
        }
    }
}

impl Add<std::time::Duration> for LocalTime {
    type Output = Self;

    fn add(self, duration: std::time::Duration) -> Self::Output {
        Self(self.0.add(duration))
    }
}

impl AsRef<OffsetDateTime> for LocalTime {
    fn as_ref(&self) -> &OffsetDateTime {
        &self.0
    }
}

impl AsMut<OffsetDateTime> for LocalTime {
    fn as_mut(&mut self) -> &mut OffsetDateTime {
        &mut self.0
    }
}

impl From<OffsetDateTime> for LocalTime {
    fn from(value: OffsetDateTime) -> Self {
        LocalTime(value)
    }
}

impl From<PrimitiveDateTime> for LocalTime {
    fn from(value: PrimitiveDateTime) -> Self {
        LocalTime(value.assume_offset(local_offset()))
    }
}

impl From<SystemTime> for LocalTime {
    fn from(value: SystemTime) -> Self {
        LocalTime(OffsetDateTime::from(value).to_offset(local_offset()))
    }
}

impl FromStr for LocalTime {
    type Err = TimeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match OffsetDateTime::parse(s, DATETIME_FORMAT) {
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
        deserializer.deserialize_str(LocalTimeVisitor) // 为 Deserializer 提供 Visitor
    }
}

struct LocalTimeVisitor; // LocalDateTime 的 Visitor，用来反序列化

impl <'de> Visitor<'de> for LocalTimeVisitor {
    type Value = LocalTime; // Visitor 的类型参数，这里我们需要反序列化的最终目标是 LocalDateTime

    // 必须重写的函数，用于为预期之外的类型提供错误信息
    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("datetime format yyyy-MM-dd HH:mm:ss")
    }

    // 从字符串中反序列化
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        match PrimitiveDateTime::parse(v, DATETIME_FORMAT) {
            Ok(t) => Ok(LocalTime(t.assume_offset(local_offset()))),
            Err(_) => Err(E::invalid_value(Unexpected::Str(v), &self)),
        }
    }
}

#[cfg(feature = "mysql_common")]
use mysql_common::value::{Value, convert::{ConvIr, FromValue, FromValueError}};

#[cfg(feature = "mysql_common")]
impl ConvIr<LocalTime> for PrimitiveDateTime {
    fn new(v: Value) -> Result<PrimitiveDateTime, FromValueError> {
        match v {
            Value::Date(y, m, d, h, min, s, ms) => {
                let month = match time::Month::try_from(m as u8) {
                    Ok(m) => m,
                    Err(_) => return Err(FromValueError(v)),
                };
                let date = match time::Date::from_calendar_date(y as i32, month, d) {
                    Ok(d) => d,
                    Err(_) => return Err(FromValueError(v)),
                };
                let time = match time::Time::from_hms_micro(h, min, s, ms) {
                    Ok(t) => t,
                    Err(_) => return Err(FromValueError(v)),
                };
                Ok(PrimitiveDateTime::new(date, time))
            }
            v => Err(FromValueError(v)),
        }
    }
    fn commit(self) -> LocalTime {
        LocalTime(self.assume_offset(local_offset()))
    }
    fn rollback(self) -> Value {
        Value::Date(self.year() as u16, self.month().into(), self.day(),
                self.hour(), self.minute(), self.second(), self.microsecond())
    }
}

#[cfg(feature = "mysql_common")]
impl FromValue for LocalTime {
    type Intermediate = PrimitiveDateTime;
}

#[cfg(feature = "mysql_common")]
impl From<LocalTime> for Value {
    fn from(value: LocalTime) -> Self {
        Value::Date(value.0.year() as u16, value.0.month().into(), value.0.day(),
        value.0.hour(), value.0.minute(), value.0.second(), value.0.microsecond())
    }
}
