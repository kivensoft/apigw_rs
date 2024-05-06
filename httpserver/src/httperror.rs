use std::{error::Error as StdError, fmt::Display};

use anyhow::Error;

#[derive(Debug)]
pub struct HttpError {
    pub code: u32,
    pub message: String,
    pub source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl HttpError {
    pub fn create(message: String) -> Error {
        Error::new(Self { code: 500, message, source: None })
    }

    pub fn create_with_code(code: u32, message: String) -> Error {
        Error::new(Self { code, message, source: None })
    }

    pub fn create_with_source<E>(message: String, source: E) -> Error
    where
        E: StdError + Sync + Send + 'static,
    {
        Error::new(Self { code: 500, message, source: Some(Box::new(source)) })
    }

    pub fn create_with_full<E>(code: u32, message: String, source: E) -> Error
    where
        E: StdError + Sync + Send + 'static,
    {
        Error::new(Self { code, message, source: Some(Box::new(source)) })
    }

    pub fn result<T>(message: String) -> anyhow::Result<T> {
        Err(Self::create(message))
    }

    pub fn result_with_code<T>(code: u32, message: String) -> anyhow::Result<T> {
        Err(Self::create_with_code(code, message))
    }

    pub fn result_with_source<T, E>(message: String, source: E) -> anyhow::Result<T>
    where
        E: StdError + Sync + Send + 'static,
    {
        Err(Self::create_with_source(message, source))
    }

    pub fn result_with_full<T, E>(code: u32, message: String, source: E) -> anyhow::Result<T>
    where
        E: StdError + Sync + Send + 'static,
    {
        Err(Self::create_with_full(code, message, source))
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.source {
            Some(s) => Some(s.as_ref()),
            None => None,
        }
    }
}

impl Display for HttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(source) = &self.source {
            write!(formatter, "code = {}, message = {}, source = {:?}",
                self.code, self.message, source)
        } else {
            write!(formatter, "code = {}, message = {}", self.code, self.message)
        }
    }
}
