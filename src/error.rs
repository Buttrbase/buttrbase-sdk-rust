use thiserror::Error;

/// All failures from `ButtrBaseClient`. Split into variants so callers
/// can handle "caller sent a bad request" (4xx), "ButtrBase is down" (5xx),
/// and "network/TLS" distinctly — without parsing error strings.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP transport layer (connect, TLS, timeout).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// ButtrBase returned a 4xx with a machine-readable body.
    #[error("api error {status}: {message}")]
    Api {
        status: u16,
        message: String,
        code: Option<String>,
    },

    /// ButtrBase returned an unexpected status (e.g. 500) or an
    /// unparseable body — preserves the raw text for logging.
    #[error("unexpected response {status}: {body}")]
    Unexpected { status: u16, body: String },

    /// JWT verification failure (network or crypto). From `VerifyError`.
    #[error("token verification failed: {0}")]
    Verify(#[from] crate::verify::VerifyError),

    /// JSON serialisation/deserialisation error (should never happen in
    /// practice, but surfaces a clear message if the API schema drifts).
    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),
}
