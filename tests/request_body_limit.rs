use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use squilladns::request_limits::{
    body_limit, parse_max_request_body_bytes, DEFAULT_MAX_REQUEST_BODY_BYTES,
};
use tower::ServiceExt;

#[test]
fn request_body_limit_defaults_to_one_mibibyte_and_parses_config() {
    assert_eq!(
        parse_max_request_body_bytes(None).unwrap(),
        DEFAULT_MAX_REQUEST_BODY_BYTES
    );
    assert_eq!(parse_max_request_body_bytes(Some("4096")).unwrap(), 4096);
    assert!(parse_max_request_body_bytes(Some("0")).is_err());
    assert!(parse_max_request_body_bytes(Some("not-a-number")).is_err());
}

#[tokio::test]
async fn request_body_limit_accepts_at_limit_and_rejects_over_limit() {
    let app = Router::new()
        .route(
            "/payload",
            post(|body: Bytes| async move { (StatusCode::OK, body.len().to_string()) }),
        )
        .layer(body_limit(4));

    let at_limit = app
        .clone()
        .oneshot(Request::post("/payload").body(Body::from("1234")).unwrap())
        .await
        .unwrap();
    assert_eq!(at_limit.status(), StatusCode::OK);

    let over_limit = app
        .oneshot(Request::post("/payload").body(Body::from("12345")).unwrap())
        .await
        .unwrap();
    assert_eq!(over_limit.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
