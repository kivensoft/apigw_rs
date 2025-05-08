use std::sync::OnceLock;

use anyhow::{bail, Result};
use localtime::unix_timestamp;
use redb::{Database, TableDefinition};

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("invalid_token");

static DB: OnceLock<Database> = OnceLock::new();

pub fn init(path: &str) {
    let db = Database::create(path).unwrap();
    if DB.set(db).is_err() {
        panic!("init db error");
    }
}

pub fn is_valid() -> bool {
    DB.get().is_some()
}

pub fn exists(token_sign: &str) -> bool {
    let exp = match get(token_sign) {
        Ok(Some(exp)) => exp,
        _ => return false,
    };

    let now = unix_timestamp();
    if exp >= now {
        return true;
    }

    // 该token已过期，删除
    let _ = delete(token_sign);
    false
}

pub fn get(token_sign: &str) -> Result<Option<u64>> {
    match DB.get() {
        Some(db) => {
            let txn = db.begin_read()?;
            let table = txn.open_table(TABLE)?;
            Ok(table.get(token_sign)?.map(|v| v.value()))
        }
        None => bail!("db not init"),
    }
}

pub fn put(token_sign: &str, expire: u64) -> Result<()> {
    match DB.get() {
        Some(db) => {
            let txn = db.begin_write()?;
            let mut table = txn.open_table(TABLE)?;
            table.insert(token_sign, expire)?;
            Ok(())
        }
        None => bail!("db not init"),
    }
}

pub fn delete(token_sign: &str) -> Result<()> {
    match DB.get() {
        Some(db) => {
            let txn = db.begin_write()?;
            let mut table = txn.open_table(TABLE)?;
            table.remove(token_sign)?;
            Ok(())
        }
        None => Ok(()),
    }
}

/// 删除过期的键
pub fn remove_expired() {
    match DB.get() {
        Some(db) => {
            let now = unix_timestamp();
            match db.begin_write() {
                Ok(txn) => {
                    match txn.open_table(TABLE) {
                        Ok(mut table) => {
                            if let Err(e) = table.retain(|_, v| v >= now) {
                                log::error!("retain error: {e:?}")
                            }
                        }
                        Err(e) => log::error!("open table error: {e:?}")
                    }
                }
                Err(e) => log::error!("create write trans error: {e:?}")
            }

        }
        None => log::error!("db not init")
    }
}
