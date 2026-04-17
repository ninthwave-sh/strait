//! gRPC service implementation for `strait-host`.
//!
//! This module wires the generated `strait_proto::v1::StraitHost` service
//! trait to a concrete implementation. H-HCP-2 ships the protocol surface
//! only: `RegisterContainer` and `Heartbeat` have usable behaviour so the
//! agent can prove the channel works end to end, and the remaining four
//! RPCs return `Status::unimplemented` with a pointer to the follow-on work
//! item that fills them in.
//!
//! Tests that need a different behaviour (for example an echoing
//! `SubmitDecision` stub for latency measurements) can define their own
//! `StraitHost` impl; this struct is just the default production handler.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_core::Stream;
use strait_proto::v1::strait_host_server::StraitHost;
use strait_proto::v1::{
    FetchCredentialRequest, FetchCredentialResponse, HeartbeatRequest, HeartbeatResponse,
    ObservationEvent, RegisterContainerRequest, RegisterContainerResponse, RuleEvent,
    StreamObservationsAck, StreamRulesRequest, SubmitDecisionRequest, SubmitDecisionResponse,
};
use tonic::{Request, Response, Status, Streaming};

/// Production implementation of the `StraitHost` gRPC service.
///
/// The service is Clone + Send + Sync so it can be cheaply handed to both
/// the Unix-socket and TCP `tonic::transport::Server` instances. Internal
/// state is held behind atomics/arcs so neither listener sees the other's
/// concurrent mutations.
#[derive(Debug, Clone, Default)]
pub struct StraitHostService {
    sessions: Arc<AtomicU64>,
}

impl StraitHostService {
    /// Fresh service with no registered sessions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `RegisterContainer` calls served since the process started.
    /// Exposed for operator health endpoints and tests.
    pub fn sessions_registered(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }
}

/// Stream type returned by server-streaming RPCs. Boxed so the production
/// stub (which returns an immediate error) and any future real implementation
/// share a single type.
pub type RuleEventStream = Pin<Box<dyn Stream<Item = Result<RuleEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl StraitHost for StraitHostService {
    async fn register_container(
        &self,
        request: Request<RegisterContainerRequest>,
    ) -> Result<Response<RegisterContainerResponse>, Status> {
        let req = request.into_inner();
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id must be set"));
        }

        let seq = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        let session_id = format!("sess-{seq:08x}");
        Ok(Response::new(RegisterContainerResponse {
            session_id,
            default_scope: "default".to_string(),
            registered_at_unix_ms: now_unix_ms(),
            rules_resume_token: String::new(),
        }))
    }

    async fn submit_decision(
        &self,
        _request: Request<SubmitDecisionRequest>,
    ) -> Result<Response<SubmitDecisionResponse>, Status> {
        // Hold-and-resume lands in H-HCP-6 (retargeted H-CSM-3/4).
        Err(Status::unimplemented(
            "SubmitDecision is implemented in H-HCP-6",
        ))
    }

    async fn fetch_credential(
        &self,
        _request: Request<FetchCredentialRequest>,
    ) -> Result<Response<FetchCredentialResponse>, Status> {
        // Credential store moves off the agent in H-HCP-4.
        Err(Status::unimplemented(
            "FetchCredential is implemented in H-HCP-4",
        ))
    }

    type StreamRulesStream = RuleEventStream;

    async fn stream_rules(
        &self,
        _request: Request<StreamRulesRequest>,
    ) -> Result<Response<Self::StreamRulesStream>, Status> {
        // Rule store (and its stream source) lands in H-HCP-3.
        Err(Status::unimplemented(
            "StreamRules is implemented in H-HCP-3",
        ))
    }

    async fn stream_observations(
        &self,
        _request: Request<Streaming<ObservationEvent>>,
    ) -> Result<Response<StreamObservationsAck>, Status> {
        // Observation forwarding lands in M-HCP-5.
        Err(Status::unimplemented(
            "StreamObservations is implemented in M-HCP-5",
        ))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let now = now_unix_ms();
        // `sent_at_unix_ms` is echoed through `received_at_unix_ms` so
        // clients can measure round-trip latency without a second RPC.
        let received_at_unix_ms = request.into_inner().sent_at_unix_ms;
        Ok(Response::new(HeartbeatResponse {
            received_at_unix_ms,
            server_time_unix_ms: now,
        }))
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use strait_proto::v1::Verdict;

    #[tokio::test]
    async fn register_container_assigns_unique_session_ids() {
        let svc = StraitHostService::new();
        let a = svc
            .register_container(Request::new(RegisterContainerRequest {
                container_id: "a".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let b = svc
            .register_container(Request::new(RegisterContainerRequest {
                container_id: "b".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_ne!(a.session_id, b.session_id, "session ids should differ");
        assert_eq!(svc.sessions_registered(), 2);
    }

    #[tokio::test]
    async fn register_container_rejects_empty_id() {
        let svc = StraitHostService::new();
        let err = svc
            .register_container(Request::new(RegisterContainerRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn unimplemented_rpcs_return_unimplemented() {
        let svc = StraitHostService::new();
        let err = svc
            .submit_decision(Request::new(SubmitDecisionRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        let err = svc
            .fetch_credential(Request::new(FetchCredentialRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        // `stream_rules` returns a stream whose Ok type does not implement
        // Debug, so we match rather than `.unwrap_err()`.
        let result = svc
            .stream_rules(Request::new(StreamRulesRequest::default()))
            .await;
        match result {
            Err(err) => assert_eq!(err.code(), tonic::Code::Unimplemented),
            Ok(_) => panic!("expected Unimplemented from stream_rules stub"),
        }
    }

    #[tokio::test]
    async fn heartbeat_round_trips_sent_at() {
        let svc = StraitHostService::new();
        let resp = svc
            .heartbeat(Request::new(HeartbeatRequest {
                sent_at_unix_ms: 12345,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 12345);
        assert!(
            resp.server_time_unix_ms >= 0,
            "server_time_unix_ms should be populated"
        );
    }

    #[test]
    fn verdict_default_is_unspecified() {
        // Defense-in-depth: if someone adds a new Verdict variant above
        // `Unspecified`, proto3 semantics change. Lock the default value.
        assert_eq!(Verdict::default(), Verdict::Unspecified);
    }
}
