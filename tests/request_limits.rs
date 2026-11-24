use axum::{
    body::{Body, Bytes},
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use squilladns::request_limits::{body_limit, run_limited, BlockingWorkError, RequestLimits};
use std::sync::{mpsc, Arc};
use tokio::sync::Semaphore;
use tower::ServiceExt;

#[test]
fn request_limits_default_and_parse_environment_values() {
    let defaults = RequestLimits::from_values(None, None, None, None, None, None).unwrap();
    assert_eq!(defaults.max_request_body_bytes, 1024 * 1024);
    assert_eq!(defaults.max_records_per_zone, 10_000);
    assert_eq!(defaults.max_record_name_bytes, 253);
    assert_eq!(defaults.max_record_value_bytes, 4096);
    assert_eq!(defaults.max_parallel_validations, 4);
    assert_eq!(defaults.max_parallel_io, 4);

    let configured = RequestLimits::from_values(
        Some("8192".into()),
        Some("500".into()),
        Some("100".into()),
        Some("2048".into()),
        Some("2".into()),
        Some("3".into()),
    )
    .unwrap();
    assert_eq!(configured.max_request_body_bytes, 8192);
    assert_eq!(configured.max_records_per_zone, 500);
    assert_eq!(configured.max_record_name_bytes, 100);
    assert_eq!(configured.max_record_value_bytes, 2048);
    assert_eq!(configured.max_parallel_validations, 2);
    assert_eq!(configured.max_parallel_io, 3);

    assert!(RequestLimits::from_values(Some("0".into()), None, None, None, None, None).is_err());
    assert!(RequestLimits::from_values(None, Some("x".into()), None, None, None, None).is_err());
    assert!(RequestLimits::from_values(None, None, Some("0".into()), None, None, None).is_err());
    assert!(RequestLimits::from_values(None, None, None, Some("nope".into()), None, None).is_err());
    assert!(RequestLimits::from_values(None, None, None, None, Some("0".into()), None).is_err());
    assert!(RequestLimits::from_values(None, None, None, None, None, Some("0".into())).is_err());
}

#[tokio::test]
async fn body_limit_accepts_at_limit_and_rejects_over_limit() {
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

#[tokio::test]
async fn bounded_blocking_work_rejects_when_all_validation_slots_are_busy() {
    let slots = Arc::new(Semaphore::new(1));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_slots = Arc::clone(&slots);
    let first = tokio::spawn(async move {
        run_limited(first_slots, move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            42
        })
        .await
    });

    started_rx.await.expect("le travail bloquant doit démarrer");
    let second = run_limited(Arc::clone(&slots), || 7).await;
    assert_eq!(second, Err(BlockingWorkError::Saturated));

    release_tx.send(()).unwrap();
    assert_eq!(first.await.unwrap().unwrap(), 42);
}
