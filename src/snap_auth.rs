//! Authentication towards the SNAP / endhost API.
//!
//! Two modes are supported:
//! - a static SNAP token read from a file (`snap_token_path`), and
//! - an Anapaya API key (`api_key_path` + `aa_url`) that is exchanged for short-lived SNAP tokens
//!   at the Anapaya AA (Authentication and Authorization) service. The tokens are refreshed
//!   automatically before they expire, so long-running clients keep working.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scion_sdk_reqwest_connect_rpc::token_source::TokenSourceError;
use scion_sdk_reqwest_connect_rpc::token_source::refresh::{RefreshTokenSource, TokenWithExpiry};
use scion_stack::scionstack::ScionStackBuilder;
use prost::Message;
use tracing::{info, warn};
use url::Url;

/// Connect-RPC path of the AA `AuthenticateByKey` method.
const AUTHENTICATE_BY_KEY_PATH: &str = "anapaya.aa.v1.AuthService/AuthenticateByKey";
/// Timeout for a single request to the AA service.
const AA_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Device ID used when none is configured and the hostname cannot be determined.
const FALLBACK_DEVICE_ID: &str = "connect-ip-rust-scion";

/// How the SCION stack authenticates towards the SNAP / endhost API.
#[derive(Debug, Clone, Default)]
pub enum SnapAuth {
    /// No authentication (e.g. a local endhost API that does not require a token).
    #[default]
    None,
    /// A static SNAP token read from a file.
    StaticToken { token_path: PathBuf },
    /// An Anapaya API key that is exchanged for SNAP tokens at the AA service.
    ApiKey {
        api_key_path: PathBuf,
        aa_url: Url,
        device_id: String,
    },
}

impl SnapAuth {
    /// Builds the authentication mode from the (already merged) configuration values.
    pub fn from_config(
        snap_token_path: Option<PathBuf>,
        api_key_path: Option<PathBuf>,
        aa_url: Option<Url>,
        device_id: Option<String>,
    ) -> Result<Self> {
        match (snap_token_path, api_key_path) {
            (Some(_), Some(_)) => {
                bail!("Only one of snap_token_path and api_key_path may be provided.")
            }
            (Some(token_path), None) => Ok(SnapAuth::StaticToken { token_path }),
            (None, Some(api_key_path)) => {
                let aa_url = aa_url.ok_or_else(|| {
                    anyhow!("aa_url must be provided when api_key_path is used.")
                })?;
                let device_id = device_id.unwrap_or_else(default_device_id);
                Ok(SnapAuth::ApiKey {
                    api_key_path,
                    aa_url,
                    device_id,
                })
            }
            (None, None) => Ok(SnapAuth::None),
        }
    }

    /// Configures the authentication on the given SCION stack builder.
    pub fn apply(&self, builder: ScionStackBuilder) -> Result<ScionStackBuilder> {
        match self {
            SnapAuth::None => Ok(builder),
            SnapAuth::StaticToken { token_path } => {
                let snap_token = fs::read_to_string(token_path)
                    .with_context(|| format!("failed to read token file {:?}", token_path))?
                    .trim()
                    .to_string();
                if snap_token.is_empty() {
                    bail!("token file {:?} is empty", token_path);
                }
                Ok(builder.with_auth_token(snap_token))
            }
            SnapAuth::ApiKey {
                api_key_path,
                aa_url,
                device_id,
            } => {
                // Read the key once at startup so that a missing or malformed file fails fast.
                let api_key = read_api_key(api_key_path)?;
                let endpoint = aa_endpoint(aa_url);
                let http = reqwest::Client::builder()
                    .timeout(AA_REQUEST_TIMEOUT)
                    .build()
                    .context("failed to build HTTP client for the AA service")?;
                if aa_url.scheme() != "https" {
                    warn!("AA URL {aa_url} does not use https; the API key is sent in plain text");
                }
                info!("Using API key authentication via AA {aa_url} (device ID '{device_id}')");

                let device_id = device_id.clone();
                let refresher = move || {
                    let http = http.clone();
                    let endpoint = endpoint.clone();
                    let api_key = api_key.clone();
                    let device_id = device_id.clone();
                    async move {
                        fetch_snap_token(&http, &endpoint, &api_key, &device_id)
                            .await
                            .map_err(|e| -> TokenSourceError {
                                warn!("failed to obtain SNAP token from AA: {e:#}");
                                e.into()
                            })
                    }
                };
                let source = RefreshTokenSource::builder("anapaya-aa", refresher).build();
                Ok(builder.with_auth_token_source(source))
            }
        }
    }
}

/// Request message `anapaya.aa.v1.AuthenticateByKeyRequest`.
///
/// The AA only accepts the Connect-RPC protobuf encoding (`application/proto`), not JSON.
#[derive(Clone, PartialEq, Message)]
struct AuthenticateByKeyRequest {
    #[prost(string, tag = "1")]
    api_key: String,
    #[prost(string, tag = "2")]
    device_id: String,
    /// Requested token validity in seconds; 0 lets the AA choose its default.
    #[prost(int32, tag = "3")]
    requested_validity: i32,
}

/// Response message `anapaya.aa.v1.AuthenticateByKeyResponse` (metadata is ignored).
#[derive(Clone, PartialEq, Message)]
struct AuthenticateByKeyResponse {
    #[prost(string, tag = "1")]
    snap_token: String,
}

/// Exchanges the API key for a SNAP token at the AA service.
async fn fetch_snap_token(
    http: &reqwest::Client,
    endpoint: &Url,
    api_key: &str,
    device_id: &str,
) -> Result<TokenWithExpiry> {
    let body = AuthenticateByKeyRequest {
        api_key: api_key.to_string(),
        device_id: device_id.to_string(),
        requested_validity: 0,
    }
    .encode_to_vec();
    let response = http
        .post(endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/proto")
        .body(body)
        .send()
        .await
        .with_context(|| format!("request to AA {} failed", endpoint))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read AA response")?;
    if !status.is_success() {
        bail!(
            "AA returned {}: {}",
            status,
            String::from_utf8_lossy(&bytes).trim()
        );
    }
    let response =
        AuthenticateByKeyResponse::decode(bytes).context("invalid AA response")?;

    let exp = jwt_expiry_unix(&response.snap_token)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if exp <= now {
        bail!("AA returned a SNAP token that is already expired (exp={exp}, now={now})");
    }
    info!("obtained SNAP token from AA, valid for {}s", exp - now);
    Ok(TokenWithExpiry {
        token: response.snap_token,
        expires_at: Instant::now() + Duration::from_secs(exp - now),
    })
}

/// Reads the API key secret (`aakey_...`) from a file that contains only the secret.
fn read_api_key(path: &Path) -> Result<String> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read API key file {:?}", path))?;
    let key = content.trim();
    if key.is_empty() {
        bail!("API key file {:?} does not contain an API key", path);
    }
    Ok(key.to_string())
}

/// Returns the full URL of the `AuthenticateByKey` method for the given AA base URL.
fn aa_endpoint(aa_url: &Url) -> Url {
    let mut url = aa_url.clone();
    let path = format!("{}/{}", url.path().trim_end_matches('/'), AUTHENTICATE_BY_KEY_PATH);
    url.set_path(&path);
    url
}

/// Extracts the `exp` claim (seconds since the Unix epoch) from a JWT without verifying it.
///
/// The token is verified by the SNAP; the client only needs the expiry to schedule refreshes.
fn jwt_expiry_unix(token: &str) -> Result<u64> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("SNAP token is not a JWT"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("SNAP token payload is not valid base64url")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).context("SNAP token payload is not valid JSON")?;
    claims
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow!("SNAP token has no numeric exp claim"))
}

fn default_device_id() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| FALLBACK_DEVICE_ID.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt_with_payload(payload: &str) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn parses_jwt_expiry() {
        let token = jwt_with_payload(r#"{"sub":"device","exp":1893456000}"#);
        assert_eq!(jwt_expiry_unix(&token).unwrap(), 1_893_456_000);
    }

    #[test]
    fn rejects_jwt_without_expiry() {
        let token = jwt_with_payload(r#"{"sub":"device"}"#);
        assert!(jwt_expiry_unix(&token).is_err());
        assert!(jwt_expiry_unix("not-a-jwt").is_err());
    }

    #[test]
    fn reads_api_key_file() {
        let path = std::env::temp_dir().join(format!("cirs-api-key-test-{}", std::process::id()));
        fs::write(&path, "  aakey_secret\n").unwrap();
        assert_eq!(read_api_key(&path).unwrap(), "aakey_secret");
        fs::write(&path, " \n").unwrap();
        assert!(read_api_key(&path).is_err());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn encodes_request_as_protobuf() {
        let body = AuthenticateByKeyRequest {
            api_key: "k".into(),
            device_id: "d".into(),
            requested_validity: 0,
        }
        .encode_to_vec();
        assert_eq!(body, b"\x0a\x01k\x12\x01d");
    }

    #[test]
    fn builds_aa_endpoint() {
        let url: Url = "https://aa.example.org".parse().unwrap();
        assert_eq!(
            aa_endpoint(&url).as_str(),
            "https://aa.example.org/anapaya.aa.v1.AuthService/AuthenticateByKey"
        );
        let url: Url = "https://aa.example.org/api/".parse().unwrap();
        assert_eq!(
            aa_endpoint(&url).as_str(),
            "https://aa.example.org/api/anapaya.aa.v1.AuthService/AuthenticateByKey"
        );
    }

    #[test]
    fn rejects_conflicting_auth_options() {
        let result = SnapAuth::from_config(
            Some("token".into()),
            Some("key".into()),
            Some("https://aa.example.org".parse().unwrap()),
            None,
        );
        assert!(result.is_err());
        let result = SnapAuth::from_config(None, Some("key".into()), None, None);
        assert!(result.is_err());
    }
}
