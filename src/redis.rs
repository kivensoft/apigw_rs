//! 简单的redis客户端
use anyhow_ext::Result;
use redis_async::{client::{ConnectionBuilder, PairedConnection}, resp_array};

use crate::staticmut::StaticMut;


pub struct RedisConfig<'a> {
    pub host: &'a str,
    pub port: &'a str,
    pub user: &'a str,
    pub pass: &'a str,
    pub db: &'a str,
}


// static CONN: OnceLock<PairedConnection> = OnceLock::new();
static mut CONN: StaticMut<PairedConnection> = StaticMut::new();

pub async fn init(cfg: &RedisConfig<'_>) -> Result<()> {
    let port = cfg.port.parse::<u16>().unwrap_or(6379);
    let db = cfg.db.parse::<usize>().unwrap_or(0);

    let mut builder = ConnectionBuilder::new(cfg.host, port)?;
    if !cfg.user.is_empty() {
        builder.username(cfg.user);
    }
    if !cfg.pass.is_empty() {
        builder.password(cfg.pass);
    }

    let conn = builder.paired_connect().await?;
    if !cfg.db.is_empty() {
        conn.send(resp_array!["SELECT", db]).await?;
    }
    conn.send::<String>(resp_array!["PING"]).await?;

    unsafe { CONN.init(conn); }

    Ok(())
}

pub async fn get(key: &str) -> Result<Option<String>> {
    Ok(get_conn().send(resp_array!["GET", key]).await?)
}

pub async fn set(key: &str, value: &str, ttl: u32) -> Result<()> {
    let mut buf = itoa::Buffer::new();
    let ttl_str = buf.format(ttl);
    Ok(get_conn().send(resp_array!["SETEX", key, ttl_str, value]).await?)
}

pub async fn del(key: &str) -> Result<usize> {
    Ok(get_conn().send(resp_array!["DEL", key]).await?)
}

fn get_conn() -> &'static PairedConnection {
    unsafe { CONN.get() }
}
