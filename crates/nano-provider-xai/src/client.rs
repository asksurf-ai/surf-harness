//! Direct xAI Responses HTTP client with one bounded transport replay.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use futures_util::StreamExt;
use nano_types::contract::AgentProfile;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode, Url};
#[cfg(feature = "test-loopback")]
use std::net::IpAddr;

use crate::request::serialize_request;
use crate::sse::ResponseStream;
use crate::types::{
    CompletedTurn, PreparedTurnRequest, Provider, ProviderFailure, ProviderSendTelemetry,
    TurnRequest,
};

const OFFICIAL_RESPONSES_ENDPOINT: &str = "https://api.x.ai/v1/responses";
const MAX_TRANSPORT_ATTEMPTS: u64 = 2;

#[derive(Debug, Clone)]
pub struct XaiProviderSettings {
    pub model: String,
    pub reasoning_effort: String,
    pub include: Vec<String>,
    pub parallel_tool_calls: bool,
    pub tool_choice: String,
    pub service_tier: String,
    pub max_output_tokens: u64,
    pub max_request_body_bytes: u64,
    pub max_function_arguments_bytes: u64,
    pub max_sse_events: u64,
    pub max_sse_event_bytes: u64,
    pub max_sse_response_bytes: u64,
    pub max_json_depth: u64,
    pub connect_timeout: Duration,
    pub first_event_timeout: Duration,
    pub inter_event_timeout: Duration,
    pub total_timeout: Duration,
}

impl XaiProviderSettings {
    pub fn from_profile(profile: &AgentProfile) -> Result<Self, ProviderFailure> {
        if profile.provider.provider_id != "xai"
            || profile.provider.api != "responses-v1"
            || profile.provider.endpoint != OFFICIAL_RESPONSES_ENDPOINT
            || profile.provider.store
            || !profile.provider.stream
            || profile.provider.retry_max != 0
        {
            return Err(ProviderFailure::new("provider_profile_invalid"));
        }
        let settings = Self {
            model: profile.provider.model.clone(),
            reasoning_effort: profile.provider.reasoning_effort.clone(),
            include: profile.provider.include.clone(),
            parallel_tool_calls: profile.provider.parallel_tool_calls,
            tool_choice: profile.provider.tool_choice.clone(),
            service_tier: profile.provider.service_tier.clone(),
            max_output_tokens: profile.context.max_output_tokens_per_request,
            max_request_body_bytes: profile.context.max_request_body_bytes,
            max_function_arguments_bytes: profile.transport.max_function_arguments_bytes,
            max_sse_events: profile.transport.max_sse_events_per_response,
            max_sse_event_bytes: profile.transport.max_sse_event_bytes,
            max_sse_response_bytes: profile.transport.max_sse_response_bytes,
            max_json_depth: profile.transport.max_json_depth,
            connect_timeout: Duration::from_secs(profile.deadlines.provider_connect_timeout_sec),
            first_event_timeout: Duration::from_secs(
                profile.deadlines.provider_first_event_timeout_sec,
            ),
            inter_event_timeout: Duration::from_secs(
                profile.deadlines.provider_inter_event_timeout_sec,
            ),
            total_timeout: Duration::from_secs(profile.deadlines.provider_total_timeout_sec),
        };
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), ProviderFailure> {
        if self.model.is_empty()
            || self.reasoning_effort.is_empty()
            || self.include.iter().any(String::is_empty)
            || self.tool_choice.is_empty()
            || self.service_tier.is_empty()
            || self.max_output_tokens == 0
            || self.max_request_body_bytes == 0
            || self.max_function_arguments_bytes == 0
            || self.max_sse_events == 0
            || self.max_sse_event_bytes == 0
            || self.max_sse_response_bytes == 0
            || self.max_json_depth == 0
            || self.connect_timeout.is_zero()
            || self.first_event_timeout.is_zero()
            || self.inter_event_timeout.is_zero()
            || self.total_timeout.is_zero()
        {
            return Err(ProviderFailure::new("provider_settings_invalid"));
        }
        Ok(())
    }
}

pub struct XaiProvider {
    endpoint: Url,
    api_key: String,
    settings: XaiProviderSettings,
    client: Client,
    send_telemetry: ProviderSendTelemetry,
}

impl Debug for XaiProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XaiProvider")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl XaiProvider {
    /// Construct the production provider. The endpoint cannot be overridden.
    pub fn new(api_key: String, settings: XaiProviderSettings) -> Result<Self, ProviderFailure> {
        settings.validate()?;
        let endpoint = Url::parse(OFFICIAL_RESPONSES_ENDPOINT)
            .map_err(|_| ProviderFailure::new("provider_endpoint_invalid"))?;
        Self::build(endpoint, api_key, settings)
    }

    /// Construct a test provider restricted to a numeric loopback address.
    ///
    /// This never permits a caller-controlled non-loopback production endpoint.
    #[doc(hidden)]
    #[cfg(feature = "test-loopback")]
    pub fn for_loopback_test(
        endpoint: &str,
        api_key: String,
        settings: XaiProviderSettings,
    ) -> Result<Self, ProviderFailure> {
        settings.validate()?;
        let endpoint =
            Url::parse(endpoint).map_err(|_| ProviderFailure::new("provider_endpoint_invalid"))?;
        let is_loopback = endpoint.scheme() == "http"
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if !is_loopback {
            return Err(ProviderFailure::new("provider_loopback_endpoint_required"));
        }
        Self::build(endpoint, api_key, settings)
    }

    fn build(
        endpoint: Url,
        api_key: String,
        settings: XaiProviderSettings,
    ) -> Result<Self, ProviderFailure> {
        if api_key.is_empty() || api_key.chars().any(char::is_whitespace) {
            return Err(ProviderFailure::new("provider_api_key_invalid"));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(settings.connect_timeout)
            .build()
            .map_err(|_| ProviderFailure::new("provider_client_build_failed"))?;
        Ok(Self {
            endpoint,
            api_key,
            settings,
            client,
            send_telemetry: ProviderSendTelemetry::default(),
        })
    }

    async fn send_once(&self, body: Vec<u8>) -> Result<CompletedTurn, AttemptFailure> {
        let authorization = format!("Bearer {}", self.api_key);
        let started = tokio::time::Instant::now();
        let deadline = started + self.settings.total_timeout;
        let response = tokio::time::timeout(
            self.settings.total_timeout,
            self.client
                .post(self.endpoint.clone())
                .header(AUTHORIZATION, authorization)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "text/event-stream")
                .body(body)
                .send(),
        )
        .await
        .map_err(|_| AttemptFailure::new("provider_total_timeout", AttemptStage::Request))?
        .map_err(|error| AttemptFailure::transport(error, AttemptStage::Request))?;

        let status = response.status();
        if status != StatusCode::OK {
            let code = classify_http_status(status);
            return Err(AttemptFailure::new(code, AttemptStage::ResponseHeaders));
        }
        let is_event_stream = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
        if !is_event_stream {
            return Err(AttemptFailure::new(
                "provider_content_type_invalid",
                AttemptStage::ResponseHeaders,
            ));
        }

        let mut first = true;
        let mut stream = response.bytes_stream();
        let mut validator = ResponseStream::new(&self.settings);
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(AttemptFailure::new(
                    "provider_total_timeout",
                    AttemptStage::ResponseStream,
                ));
            }
            let event_timeout = if first {
                self.settings.first_event_timeout
            } else {
                self.settings.inter_event_timeout
            };
            let wait = event_timeout.min(deadline - now);
            let next = tokio::time::timeout(wait, stream.next())
                .await
                .map_err(|_| {
                    AttemptFailure::new(
                        if first {
                            "provider_first_event_timeout"
                        } else {
                            "provider_inter_event_timeout"
                        },
                        AttemptStage::ResponseStream,
                    )
                })?;
            match next {
                Some(Ok(bytes)) => {
                    first = false;
                    validator.feed(&bytes).map_err(|failure| AttemptFailure {
                        failure,
                        stage: AttemptStage::ResponseStream,
                    })?;
                }
                Some(Err(error)) => {
                    return Err(AttemptFailure::transport(
                        error,
                        AttemptStage::ResponseStream,
                    ));
                }
                None => {
                    return validator.finish().map_err(|failure| AttemptFailure {
                        failure,
                        stage: AttemptStage::ResponseStream,
                    });
                }
            }
        }
    }
}

impl Provider for XaiProvider {
    fn preflight(&self, request: TurnRequest) -> Result<PreparedTurnRequest, ProviderFailure> {
        let body = serialize_request(&request, &self.settings)?;
        Ok(PreparedTurnRequest::serialized(body))
    }

    async fn send(
        &mut self,
        request: PreparedTurnRequest,
    ) -> Result<CompletedTurn, ProviderFailure> {
        let body = request.into_serialized_body()?;
        self.send_telemetry = ProviderSendTelemetry::default();
        for attempt in 1..=MAX_TRANSPORT_ATTEMPTS {
            self.send_telemetry.attempt_count = attempt;
            match self.send_once(body.clone()).await {
                Ok(completed) => return Ok(completed),
                Err(failure)
                    if attempt < MAX_TRANSPORT_ATTEMPTS && failure.retryable_transport() =>
                {
                    self.send_telemetry.retry_code = Some(failure.failure.code().to_owned());
                    self.send_telemetry.retry_stage = Some(failure.stage.as_str().to_owned());
                }
                Err(failure) => return Err(failure.failure),
            }
        }
        unreachable!("bounded provider attempt loop always returns")
    }

    fn send_telemetry(&self) -> ProviderSendTelemetry {
        self.send_telemetry.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptStage {
    Request,
    ResponseHeaders,
    ResponseStream,
}

impl AttemptStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::ResponseHeaders => "response_headers",
            Self::ResponseStream => "response_stream",
        }
    }
}

struct AttemptFailure {
    failure: ProviderFailure,
    stage: AttemptStage,
}

impl AttemptFailure {
    fn new(code: &'static str, stage: AttemptStage) -> Self {
        Self {
            failure: ProviderFailure::new(code),
            stage,
        }
    }

    fn transport(error: reqwest::Error, stage: AttemptStage) -> Self {
        Self {
            failure: classify_transport_error(error),
            stage,
        }
    }

    fn retryable_transport(&self) -> bool {
        matches!(
            self.failure.code(),
            "provider_transport_timeout" | "provider_connect_failed" | "provider_transport_failed"
        )
    }
}

fn classify_transport_error(error: reqwest::Error) -> ProviderFailure {
    if error.is_timeout() {
        ProviderFailure::new("provider_transport_timeout")
    } else if error.is_connect() {
        ProviderFailure::new("provider_connect_failed")
    } else {
        ProviderFailure::new("provider_transport_failed")
    }
}

fn classify_http_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "provider_http_400",
        401 => "provider_http_401",
        403 => "provider_http_403",
        404 => "provider_http_404",
        415 => "provider_http_415",
        422 => "provider_http_422",
        429 => "provider_http_429",
        500..=599 => "provider_http_5xx",
        300..=399 => "provider_http_3xx",
        _ => "provider_http_error",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::XaiProviderSettings;

    fn settings() -> XaiProviderSettings {
        XaiProviderSettings {
            model: "future-xai-model".to_owned(),
            reasoning_effort: "medium".to_owned(),
            include: Vec::new(),
            parallel_tool_calls: false,
            tool_choice: "required".to_owned(),
            service_tier: "flex".to_owned(),
            max_output_tokens: 1,
            max_request_body_bytes: 1,
            max_function_arguments_bytes: 1,
            max_sse_events: 1,
            max_sse_event_bytes: 1,
            max_sse_response_bytes: 1,
            max_json_depth: 1,
            connect_timeout: Duration::from_secs(1),
            first_event_timeout: Duration::from_secs(1),
            inter_event_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn settings_validate_capabilities_not_experiment_choices() {
        settings().validate().expect("profile-bound choices");

        for field in ["model", "reasoning_effort", "tool_choice", "service_tier"] {
            let mut invalid = settings();
            match field {
                "model" => invalid.model.clear(),
                "reasoning_effort" => invalid.reasoning_effort.clear(),
                "tool_choice" => invalid.tool_choice.clear(),
                "service_tier" => invalid.service_tier.clear(),
                _ => unreachable!(),
            }
            assert!(invalid.validate().is_err(), "{field} must remain explicit");
        }
    }
}
