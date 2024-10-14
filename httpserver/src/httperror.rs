use std::{error::Error as StdError, fmt::Display};

use anyhow::Error;

#[derive(Debug)]
pub struct HttpError {
    pub code: u32,
    pub message: String,
    pub source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl HttpError {
    pub fn new(message: String) -> Error {
        Error::new(Self { code: 500, message, source: None })
    }

    pub fn new_with_code(code: u32, message: String, ) -> Error {
        Error::new(Self { code, message, source: None })
    }

    pub fn new_with_source<E>(message: String, source: E) -> Error
    where
        E: StdError + Sync + Send + 'static,
    {
        Error::new(Self { code: 500, message, source: Some(Box::new(source)) })
    }

    pub fn new_with_full<E>(code: u32, message: String, source: E) -> Error
    where
        E: StdError + Sync + Send + 'static,
    {
        Error::new(Self { code, message, source: Some(Box::new(source)) })
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
        write!(formatter, "code = {}, message = {}",
                self.code, self.message)?;

        if let Some(source) = &self.source {
            write!(formatter, ", source = {source:?}")?;
        }

        Ok(())
    }
}
