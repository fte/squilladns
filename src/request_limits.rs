use axum::extract::DefaultBodyLimit;

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const ENV_MAX_REQUEST_BODY_BYTES: &str = "MAX_REQUEST_BODY_BYTES";

pub fn parse_max_request_body_bytes(value: Option<&str>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_MAX_REQUEST_BODY_BYTES);
    };
    let limit = value
        .parse::<usize>()
        .map_err(|_| format!("{} must be a positive integer", ENV_MAX_REQUEST_BODY_BYTES))?;
    if limit == 0 {
        return Err(format!(
            "{} must be greater than zero",
            ENV_MAX_REQUEST_BODY_BYTES
        ));
    }
    Ok(limit)
}

pub fn body_limit(limit: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(limit)
}
