use std::sync::OnceLock;

use anyhow_ext::Result;
use redis_async::{client::{paired_connect, PairedConnection}, resp_array};


static CONN: OnceLock<PairedConnection> = OnceLock::new();

pub async fn init(host: &str, port: &str, user: &str, pass: &str, db: &str) -> Result<()> {
    debug_assert!(CONN.get().is_none());

    let port = if !port.is_empty() {
        port.parse::<u16>()?
    } else {
        6379
    };

    let _ = CONN.set(paired_connect(host, port).await?);

    auth(user, pass, db).await
}

pub async fn get(key: &str) -> Result<Option<String>> {
    Ok(get_conn().send(resp_array!["GET", key]).await?)
}

pub async fn set(key: &str, value: &str, ttl: u32) -> Result<()> {
    let mut buf = itoa::Buffer::new();
    let ttl_str = buf.format(ttl);
    Ok(get_conn().send(resp_array!["SETEX", key, ttl_str, value]).await?)
}

pub async fn auth(user: &str, pass: &str, db: &str) -> Result<()> {
    let conn = get_conn();

    if !pass.is_empty() {
        if !user.is_empty() {
            conn.send(resp_array!["AUTH", user, pass]).await?;
        } else {
            conn.send(resp_array!["AUTH", pass]).await?;
        }
    }

    if !db.is_empty() {
        conn.send(resp_array!["SELECT", db]).await?;
    }

    conn.send::<String>(resp_array!["PING"]).await?;

    Ok(())
}

fn get_conn() -> &'static PairedConnection {
    debug_assert!(CONN.get().is_some());

    match CONN.get() {
        Some(conn) => conn,
        None => unsafe { std::hint::unreachable_unchecked() },
    }
}
