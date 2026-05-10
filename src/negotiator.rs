use reqwest::header::{HeaderMap, ACCEPT};

pub enum DataFormat {
    Json,
    FlatBuffers,
}

pub struct FormatNegotiator;

impl FormatNegotiator {
    pub fn add_headers(headers: &mut HeaderMap, format: DataFormat) {
        let val = match format {
            DataFormat::Json => "application/json",
            DataFormat::FlatBuffers => "application/x-flatbuffers",
        };
        headers.insert(ACCEPT, val.parse().unwrap());
    }

    pub fn is_binary(headers: &HeaderMap) -> bool {
        headers.get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("application/x-flatbuffers"))
            .unwrap_or(false)
    }
}
