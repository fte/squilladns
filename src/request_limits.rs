use axum::extract::DefaultBodyLimit;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_RECORDS_PER_ZONE: usize = 10_000;
pub const DEFAULT_MAX_RECORD_NAME_BYTES: usize = 253;
pub const DEFAULT_MAX_RECORD_VALUE_BYTES: usize = 4096;
pub const DEFAULT_MAX_PARALLEL_VALIDATIONS: usize = 4;
pub const ENV_MAX_REQUEST_BODY_BYTES: &str = "MAX_REQUEST_BODY_BYTES";
pub const ENV_MAX_RECORDS_PER_ZONE: &str = "MAX_RECORDS_PER_ZONE";
pub const ENV_MAX_RECORD_NAME_BYTES: &str = "MAX_RECORD_NAME_BYTES";
pub const ENV_MAX_RECORD_VALUE_BYTES: &str = "MAX_RECORD_VALUE_BYTES";
pub const ENV_MAX_PARALLEL_VALIDATIONS: &str = "MAX_PARALLEL_VALIDATIONS";

#[derive(Debug, Clone, Copy)]
pub struct RequestLimits {
    pub max_request_body_bytes: usize,
    pub max_records_per_zone: usize,
    pub max_record_name_bytes: usize,
    pub max_record_value_bytes: usize,
    pub max_parallel_validations: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_records_per_zone: DEFAULT_MAX_RECORDS_PER_ZONE,
            max_record_name_bytes: DEFAULT_MAX_RECORD_NAME_BYTES,
            max_record_value_bytes: DEFAULT_MAX_RECORD_VALUE_BYTES,
            max_parallel_validations: DEFAULT_MAX_PARALLEL_VALIDATIONS,
        }
    }
}

impl RequestLimits {
    pub fn from_env() -> Result<Self, String> {
        Self::from_values(
            env_value(ENV_MAX_REQUEST_BODY_BYTES)?,
            env_value(ENV_MAX_RECORDS_PER_ZONE)?,
            env_value(ENV_MAX_RECORD_NAME_BYTES)?,
            env_value(ENV_MAX_RECORD_VALUE_BYTES)?,
            env_value(ENV_MAX_PARALLEL_VALIDATIONS)?,
        )
    }

    pub fn from_values(
        max_request_body_bytes: Option<String>,
        max_records_per_zone: Option<String>,
        max_record_name_bytes: Option<String>,
        max_record_value_bytes: Option<String>,
        max_parallel_validations: Option<String>,
    ) -> Result<Self, String> {
        let max_parallel_validations = parse_limit(
            ENV_MAX_PARALLEL_VALIDATIONS,
            max_parallel_validations.as_deref(),
            DEFAULT_MAX_PARALLEL_VALIDATIONS,
        )?;
        if max_parallel_validations > Semaphore::MAX_PERMITS {
            return Err(format!(
                "{} exceeds Tokio's maximum permit count",
                ENV_MAX_PARALLEL_VALIDATIONS
            ));
        }

        Ok(Self {
            max_request_body_bytes: parse_limit(
                ENV_MAX_REQUEST_BODY_BYTES,
                max_request_body_bytes.as_deref(),
                DEFAULT_MAX_REQUEST_BODY_BYTES,
            )?,
            max_records_per_zone: parse_limit(
                ENV_MAX_RECORDS_PER_ZONE,
                max_records_per_zone.as_deref(),
                DEFAULT_MAX_RECORDS_PER_ZONE,
            )?,
            max_record_name_bytes: parse_limit(
                ENV_MAX_RECORD_NAME_BYTES,
                max_record_name_bytes.as_deref(),
                DEFAULT_MAX_RECORD_NAME_BYTES,
            )?,
            max_record_value_bytes: parse_limit(
                ENV_MAX_RECORD_VALUE_BYTES,
                max_record_value_bytes.as_deref(),
                DEFAULT_MAX_RECORD_VALUE_BYTES,
            )?,
            max_parallel_validations,
        })
    }
}

fn env_value(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{} must be valid UTF-8", name)),
    }
}

fn parse_limit(name: &str, value: Option<&str>, default: usize) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let limit = value
        .parse::<usize>()
        .map_err(|_| format!("{} must be a positive integer", name))?;
    if limit == 0 {
        return Err(format!("{} must be greater than zero", name));
    }
    Ok(limit)
}

pub fn body_limit(limit: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(limit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingWorkError {
    Saturated,
    WorkerFailed,
}

/// Exécute un travail CPU borné dans le pool bloquant Tokio, sans file d’attente
/// applicative : si tous les permis sont pris, retourne immédiatement Saturated.
pub async fn run_limited<F, T>(semaphore: Arc<Semaphore>, work: F) -> Result<T, BlockingWorkError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit: OwnedSemaphorePermit = semaphore
        .try_acquire_owned()
        .map_err(|_| BlockingWorkError::Saturated)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| BlockingWorkError::WorkerFailed)
}
