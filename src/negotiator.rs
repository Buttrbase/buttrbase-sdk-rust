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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

    #[test]
    fn test_add_headers_json() {
        let mut headers = HeaderMap::new();
        FormatNegotiator::add_headers(&mut headers, DataFormat::Json);
        assert_eq!(
            headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn test_add_headers_flatbuffers() {
        let mut headers = HeaderMap::new();
        FormatNegotiator::add_headers(&mut headers, DataFormat::FlatBuffers);
        assert_eq!(
            headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some("application/x-flatbuffers")
        );
    }

    #[test]
    fn test_is_binary_true() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-flatbuffers"),
        );
        assert!(FormatNegotiator::is_binary(&headers));
    }

    #[test]
    fn test_is_binary_false_for_json() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(!FormatNegotiator::is_binary(&headers));
    }

    #[test]
    fn test_is_binary_false_when_no_content_type() {
        let headers = HeaderMap::new();
        assert!(!FormatNegotiator::is_binary(&headers));
    }

    #[test]
    fn test_add_headers_overrides_existing_accept() {
        let mut headers = HeaderMap::new();
        FormatNegotiator::add_headers(&mut headers, DataFormat::Json);
        // Override with FlatBuffers
        FormatNegotiator::add_headers(&mut headers, DataFormat::FlatBuffers);
        assert_eq!(
            headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some("application/x-flatbuffers")
        );
    }
}
