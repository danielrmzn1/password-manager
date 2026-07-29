//! S3-compatible object access for exactly one object: the vault container.
//!
//! Deliberately narrow. The only operations are HEAD, GET and conditional PUT,
//! which is all the sync protocol needs and keeps the required bucket
//! permissions minimal (no `ListBucket`).
//!
//! Custom endpoints are a first-class requirement, not an add-on: Cloudflare R2
//! is the primary target, with AWS S3, MinIO and Backblaze B2 also supported.

use std::time::Duration;

use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, RequestChecksumCalculation};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

use crate::error::{AppError, Result};
use crate::sync::SyncConfig;
use crate::vault::container::MAX_CONTAINER_LEN;

/// How a remote operation failed, in terms the sync protocol cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    NotFound,
    /// The `If-Match`/`If-None-Match` guard did not hold: someone else wrote.
    PreconditionFailed,
    /// The service does not implement conditional writes at all.
    PreconditionUnsupported,
    /// Authentication or authorization failure.
    AccessDenied,
    Other(String),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "the object does not exist"),
            Self::PreconditionFailed => write!(f, "the object changed on the server"),
            Self::PreconditionUnsupported => {
                write!(f, "this service does not support conditional writes")
            }
            Self::AccessDenied => write!(f, "access denied — check the credentials and bucket"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<RemoteError> for AppError {
    fn from(err: RemoteError) -> Self {
        match err {
            RemoteError::PreconditionFailed => AppError::SyncConflict,
            other => AppError::Sync(other.to_string()),
        }
    }
}

pub struct RemoteObject {
    pub bytes: Vec<u8>,
    pub etag: Option<String>,
}

pub struct S3Store {
    client: Client,
    bucket: String,
    key: String,
}

impl S3Store {
    pub fn new(config: &SyncConfig) -> Result<Self> {
        config.validate()?;

        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            None,
            None,
            "password-manager",
        );

        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .endpoint_url(config.endpoint.trim_end_matches('/').to_string())
            .credentials_provider(credentials)
            .force_path_style(config.force_path_style)
            // Cloudflare R2 rejects the streaming trailer checksums that recent
            // SDK versions add by default (`WhenSupported`). Restricting
            // checksums to operations that actually require them is what makes
            // uploads work against R2 and several other S3-compatible services.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(10))
                    // A vault is small; anything slower than this is a dead
                    // endpoint and should surface as an error, not a hang.
                    .operation_timeout(Duration::from_secs(60))
                    .build(),
            );

        if config.region.trim().is_empty() {
            builder = builder.region(Region::new("auto".to_string()));
        }

        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            key: config.object_key(),
        })
    }

    pub fn object_key(&self) -> &str {
        &self.key
    }

    /// The current ETag, or `None` if the object does not exist yet.
    pub async fn head(&self) -> std::result::Result<Option<String>, RemoteError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
        {
            Ok(output) => Ok(output.e_tag().map(str::to_string)),
            Err(err) => {
                if let SdkError::ServiceError(ref service) = err {
                    if service.err().is_not_found() {
                        return Ok(None);
                    }
                }
                match classify(&err) {
                    RemoteError::NotFound => Ok(None),
                    other => Err(other),
                }
            }
        }
    }

    pub async fn get(&self) -> std::result::Result<Option<RemoteObject>, RemoteError> {
        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(err) => {
                if let SdkError::ServiceError(ref service) = err {
                    if service.err().is_no_such_key() {
                        return Ok(None);
                    }
                }
                return match classify(&err) {
                    RemoteError::NotFound => Ok(None),
                    other => Err(other),
                };
            }
        };

        // Guard against a hostile or misconfigured bucket serving something
        // enormous: the body is buffered in memory.
        if let Some(len) = output.content_length() {
            if len > MAX_CONTAINER_LEN as i64 {
                return Err(RemoteError::Other(
                    "the remote vault object is implausibly large".into(),
                ));
            }
        }

        let etag = output.e_tag().map(str::to_string);
        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| RemoteError::Other(format!("could not read the remote vault: {e}")))?
            .into_bytes()
            .to_vec();

        if bytes.len() > MAX_CONTAINER_LEN {
            return Err(RemoteError::Other(
                "the remote vault object is implausibly large".into(),
            ));
        }

        Ok(Some(RemoteObject { bytes, etag }))
    }

    /// Upload only if the object does not exist. Used for the very first push.
    pub async fn put_if_absent(
        &self,
        bytes: Vec<u8>,
    ) -> std::result::Result<Option<String>, RemoteError> {
        self.put(bytes, Some(Guard::IfNoneMatchAny)).await
    }

    /// Upload only if the object still has `etag`.
    pub async fn put_if_match(
        &self,
        bytes: Vec<u8>,
        etag: &str,
    ) -> std::result::Result<Option<String>, RemoteError> {
        self.put(bytes, Some(Guard::IfMatch(etag.to_string())))
            .await
    }

    /// Upload with no precondition. Only reached when the service does not
    /// implement conditional writes.
    pub async fn put_unconditional(
        &self,
        bytes: Vec<u8>,
    ) -> std::result::Result<Option<String>, RemoteError> {
        self.put(bytes, None).await
    }

    async fn put(
        &self,
        bytes: Vec<u8>,
        guard: Option<Guard>,
    ) -> std::result::Result<Option<String>, RemoteError> {
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .body(ByteStream::from(bytes))
            .content_type("application/octet-stream");

        match guard {
            Some(Guard::IfMatch(ref etag)) => request = request.if_match(etag.clone()),
            Some(Guard::IfNoneMatchAny) => request = request.if_none_match("*"),
            None => {}
        }

        match request.send().await {
            Ok(output) => Ok(output.e_tag().map(str::to_string)),
            Err(err) => Err(classify(&err)),
        }
    }

    /// Verify the endpoint, credentials and bucket are usable.
    ///
    /// Implemented as a HEAD of our own key, where "not found" counts as
    /// success: it proves the request was signed and routed correctly without
    /// needing `ListBucket` permission.
    pub async fn test_connection(&self) -> std::result::Result<(), RemoteError> {
        self.head().await.map(|_| ())
    }
}

enum Guard {
    IfMatch(String),
    IfNoneMatchAny,
}

/// Translate an SDK error into the small set of cases the protocol handles.
///
/// Checks the HTTP status first because S3-compatible services are inconsistent
/// about the error *code* string, but consistent about the status.
fn classify<E, R>(err: &SdkError<E, R>) -> RemoteError
where
    E: ProvideErrorMetadata,
    R: HasStatus,
{
    if let Some(status) = err.raw_response().and_then(HasStatus::status_code) {
        match status {
            404 => return RemoteError::NotFound,
            // 409 is what some services return for a failed `If-None-Match: *`.
            412 | 409 => return RemoteError::PreconditionFailed,
            501 => return RemoteError::PreconditionUnsupported,
            401 | 403 => return RemoteError::AccessDenied,
            _ => {}
        }
    }

    let code = err.code().unwrap_or_default();
    match code {
        "NotFound" | "NoSuchKey" => RemoteError::NotFound,
        "PreconditionFailed" => RemoteError::PreconditionFailed,
        "NotImplemented" => RemoteError::PreconditionUnsupported,
        "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" => {
            RemoteError::AccessDenied
        }
        "NoSuchBucket" => RemoteError::Other("the bucket does not exist".into()),
        _ => {
            // `err.message()` is the service's message; it never contains vault
            // material because the request body is opaque ciphertext.
            let message = err.message().unwrap_or("the request failed");
            if code.is_empty() {
                RemoteError::Other(message.to_string())
            } else {
                RemoteError::Other(format!("{code}: {message}"))
            }
        }
    }
}

/// Lets [`classify`] read a status code without naming the concrete smithy
/// response type at every call site.
pub trait HasStatus {
    fn status_code(&self) -> Option<u16>;
}

impl HasStatus for aws_sdk_s3::config::http::HttpResponse {
    fn status_code(&self) -> Option<u16> {
        Some(self.status().as_u16())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SyncConfig {
        SyncConfig {
            endpoint: "https://accountid.r2.cloudflarestorage.com".into(),
            region: "auto".into(),
            bucket: "vault-bucket".into(),
            prefix: "devices/laptop".into(),
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "secret".into(),
            force_path_style: false,
        }
    }

    #[test]
    fn client_construction_succeeds_for_r2_style_config() {
        let store = S3Store::new(&config()).unwrap();
        assert_eq!(store.object_key(), "devices/laptop/vault.pmv");
    }

    #[test]
    fn trailing_slashes_in_the_endpoint_are_tolerated() {
        let mut c = config();
        c.endpoint = "https://example.com/".into();
        assert!(S3Store::new(&c).is_ok());
    }

    #[test]
    fn empty_region_falls_back_to_auto() {
        let mut c = config();
        c.region = String::new();
        assert!(S3Store::new(&c).is_ok());
    }

    #[test]
    fn invalid_config_is_rejected_before_any_request() {
        let mut c = config();
        c.bucket = String::new();
        assert!(S3Store::new(&c).is_err());

        let mut c = config();
        c.endpoint = "not-a-url".into();
        assert!(S3Store::new(&c).is_err());
    }

    #[test]
    fn precondition_failure_maps_to_a_conflict() {
        assert!(matches!(
            AppError::from(RemoteError::PreconditionFailed),
            AppError::SyncConflict
        ));
        assert!(matches!(
            AppError::from(RemoteError::AccessDenied),
            AppError::Sync(_)
        ));
    }
}
