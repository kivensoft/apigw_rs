//! resp

use std::fmt::Display;

use anyhow::Context;
use http_body_util::Full;
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};

use crate::{HttpResponse, APPLICATION_JSON, CONTENT_TYPE};

/// Universal API interface returns data format
#[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
pub struct ApiResult<T> {
    /// result code (usually, 200 represents success, and 500 represents failure)
    pub code: u32,
    /// error message, When the code is equal to 500, it indicates an error message, and when the code is equal to 200, it is None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// result data, When the code is equal to 200, it indicates the specific return object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

/// Build http response object
pub struct Resp;

impl<T> ApiResult<T> {
    /// Generate an ApiResult that represents success using the specified data
    #[inline]
    pub fn ok(data: T) -> Self {
        Self {
            code: 200,
            message: None,
            data: Some(data),
        }
    }

    /// Generate an ApiResult that represents success using empty data
    #[inline]
    pub fn ok_with_empty() -> Self {
        Self {
            code: 200,
            message: None,
            data: None,
        }
    }

    /// Generate an ApiResult indicating failure using the specified error message
    #[inline]
    pub fn fail(msg: String) -> Self {
        Self {
            code: 500,
            message: Some(msg),
            data: None,
        }
    }

    /// Generate an ApiResult representing a failure using the specified error code and error message
    #[inline]
    pub fn fail_with_code(code: u32, msg: String) -> Self {
        Self {
            code,
            message: Some(msg),
            data: None,
        }
    }

    /// Determine if ApiResult indicates successful return
    #[inline]
    pub fn is_ok(&self) -> bool {
        self.code == 200
    }

    /// Determine if ApiResult indicates a return failure
    #[inline]
    pub fn is_fail(&self) -> bool {
        self.code != 200
    }

    pub fn unwrap(self) -> Option<T> {
        if self.is_ok() {
            self.data
        } else {
            match self.message {
                Some(msg) => panic!("ApiResult failed: code = {}, message = {}", self.code, msg),
                None => panic!("ApiResult failed: code = {}", self.code),
            }

        }
    }

    pub fn context(self, context: String) -> anyhow::Result<Option<T>> {
        if self.is_ok() {
            Ok(self.data)
        } else {
            let err = match self.message {
                Some(msg) => format!("ApiResult failed: code = {}, message = {}", self.code, msg),
                None => format!("ApiResult failed: code = {}", self.code),
            };
            Err(anyhow::Error::msg(err).context(context))
        }
    }

    pub fn with_context<C, F>(self, f: F) -> anyhow::Result<Option<T>>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        if self.is_ok() {
            Ok(self.data)
        } else {
            let err = match self.message {
                Some(msg) => format!("ApiResult failed: code = {}, message = {}", self.code, msg),
                None => format!("ApiResult failed: code = {}", self.code),
            };
            Err(anyhow::Error::msg(err).context(f()))
        }
    }
}

impl Resp {
    /// Create a reply message with the specified status code and content
    ///
    /// Arguments:
    ///
    /// * `status`: http status code
    /// * `body`: http response body
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::resp(hyper::StatusCode::Ok, hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp<T: Into<Bytes>>(status: hyper::StatusCode, body: T) -> HttpResponse {
        Ok(
            hyper::Response::builder()
                .status(status)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Full::new(body.into()))?
        )
    }

    /// Create a reply with ApiResult
    ///
    /// Arguments:
    ///
    /// * `ar`: ApiResult
    ///
    pub fn resp_with<T: Serialize>(ar: &ApiResult<T>) -> HttpResponse {
        let status = if ar.is_ok() {
            hyper::StatusCode::OK
        } else {
            hyper::StatusCode::INTERNAL_SERVER_ERROR
        };

        #[cfg(not(feature = "english"))]
        let body = serde_json::to_vec(&ar.data).context("json序列化失败")?;
        #[cfg(feature = "english")]
        let body = serde_json::to_vec(&ar.data).context("json serialization failed")?;

        Ok(
            hyper::Response::builder()
                .status(status)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Full::from(body))?
        )

    }

    /// Create a reply message with 200
    ///
    /// Arguments:
    ///
    /// * `body`: http response body
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::resp_ok(hyper::Body::from(format!("{}",
    ///     serde_json::json!({
    ///         "code": 200,
    ///             "data": {
    ///                 "name":"kiven",
    ///                 "age": 48,
    ///             },
    ///     })
    /// ))?;
    /// ````
    pub fn resp_ok<T: Into<Bytes>>(body: T) -> HttpResponse {
        Ok(
            hyper::Response::builder()
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Full::from(body.into()))?
        )
    }

    /// Create a reply message with 200, response body is empty
    pub fn ok_with_empty() -> HttpResponse {
        Self::resp_ok(hyper::body::Bytes::from(r#"{"code":200}"#))
    }

    /// Create a reply message with 200
    ///
    /// Arguments:
    ///
    /// * `data`: http response for ApiResult.data
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::ok(&serde_json::json!({
    ///     "code": 200,
    ///         "data": {
    ///             "name":"kiven",
    ///             "age": 48,
    ///         },
    /// }))?;
    /// ````
    #[inline]
    pub fn ok<T: ?Sized + Serialize>(data: &T) -> HttpResponse {
        // Self::ok_opt(Some(data))
        let mut w = Vec::with_capacity(512);
        w.extend_from_slice(br#"{"code":200,"data":"#);
        #[cfg(not(feature = "english"))]
        serde_json::to_writer(&mut w, data).context("json序列化失败")?;
        #[cfg(feature = "english")]
        serde_json::to_writer(&mut w, data).context("json serialization failed")?;
        w.push(b'}');
        Self::resp_ok(w)
    }

    /// Create a reply message with 200
    ///
    /// Arguments:
    ///
    /// * `data`: http response for ApiResult.data
    ///
    #[inline]
    pub fn ok_opt<T: ?Sized + Serialize>(data: Option<&T>) -> HttpResponse {
        match data {
            Some(v) => Self::ok(v),
            None => Self::ok_with_empty(),
        }
    }

    /// Create a reply message with http status 500
    ///
    /// Arguments:
    ///
    /// * `message`: http error message
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail("required field `username`")?;
    /// ````
    #[inline]
    pub fn fail(message: &str) -> HttpResponse {
        Self::fail_with_code(500, message)
    }

    /// Create a reply message with specified error code
    ///
    /// Arguments:
    ///
    /// * `code`: http error code
    /// * `message`: http error message
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail_with_code(10086, "required field `username`")?;
    /// ````
    #[inline]
    pub fn fail_with_code(code: u32, message: &str) -> HttpResponse {
        Self::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }

    /// Create a reply message with specified http status and error code
    ///
    /// Arguments:
    ///
    /// * `status`: http reponse status
    /// * `code`: http error code
    /// * `message`: http error message
    ///
    /// # Examples
    ///
    /// ```
    /// use httpserver::Resp;
    ///
    /// Resp::fail_with_status(hyper::StatusCode::INTERNAL_SERVER_ERROR,
    ///         10086, "required field `username`")?;
    /// ````
    pub fn fail_with_status(status: hyper::StatusCode, code: u32, message: &str) -> HttpResponse {
        let mut buf = itoa::Buffer::new();
        let code = buf.format(code);
        let mut w = Vec::with_capacity(256);
        w.extend_from_slice(br#"{"code":"#);
        w.extend_from_slice(code.as_bytes());
        w.extend_from_slice(br#","message":"#);
        #[cfg(not(feature = "english"))]
        serde_json::to_writer(&mut w, message).context("json序列化失败")?;
        #[cfg(feature = "english")]
        serde_json::to_writer(&mut w, message).context("json serialization failed")?;
        w.push(b'}');
        Self::resp(status, w)
    }

    /// Create a reply message with specified http status and error code
    ///
    /// Arguments:
    ///
    /// * `status`: http reponse status
    /// * `code`: http error code
    /// * `message`: http error message
    ///
    #[inline]
    pub fn internal_server_error() -> HttpResponse {
        Self::fail("internal server error")
    }
}
